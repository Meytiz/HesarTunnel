package pkg

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Server runs on FOREIGN server.
// Accepts reverse tunnel from Iran client.
// Forwards traffic to local services (Xray on 127.0.0.1).
// Does NOT listen on config ports.
type Server struct {
	cfg    *Config
	crypto *CryptoEngine
	obfs   *Obfuscator
	pool   *BufferPool
	ports  []int

	tunnelPool *TunnelPool
	localConns *ConnMap

	listener net.Listener
	wg       sync.WaitGroup
}

func NewServer(cfg *Config) (*Server, error) {
	cr, err := NewCryptoEngine(cfg.Crypto.Method, cfg.Tunnel.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	ports, err := ParsePorts(cfg.Tunnel.ConfigPorts)
	if err != nil {
		return nil, fmt.Errorf("ports: %w", err)
	}
	return &Server{
		cfg:        cfg,
		crypto:     cr,
		obfs:       NewObfuscator(cfg.Crypto.ObfsMode, cfg.Crypto.Obfuscation),
		pool:       NewBufferPool(cfg.Performance.BufferSize),
		ports:      ports,
		tunnelPool: NewTunnelPool(),
		localConns: NewConnMap(),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Tunnel.TunnelPort)
	log.Printf("[SERVER] Tunnel listener on %s (%s)", addr, s.cfg.Tunnel.Protocol)
	log.Printf("[SERVER] Will forward to %s:<config_ports>", s.cfg.Tunnel.ServerBind)
	log.Printf("[SERVER] Config ports: %v", s.ports)

	var err error
	s.listener, err = s.listen(addr)
	if err != nil {
		return err
	}

	s.wg.Add(1)
	go s.acceptLoop(ctx)

	<-ctx.Done()
	return nil
}

func (s *Server) Shutdown(ctx context.Context) {
	log.Println("[SERVER] Shutting down...")
	if s.listener != nil {
		s.listener.Close()
	}
	s.tunnelPool.CloseAll()
	s.localConns.Range(func(_ uint32, v interface{}) bool {
		if c, ok := v.(net.Conn); ok {
			c.Close()
		}
		return true
	})
	s.localConns.Clear()

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	log.Println("[SERVER] Stopped")
}

func (s *Server) listen(addr string) (net.Listener, error) {
	switch s.cfg.Tunnel.Protocol {
	case "tcp":
		return NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay).Listen(addr)
	case "kcp":
		return NewKCPTransport(s.cfg.KCP).Listen(addr)
	}
	return nil, fmt.Errorf("bad protocol: %s", s.cfg.Tunnel.Protocol)
}

func (s *Server) optimize(conn net.Conn) {
	switch s.cfg.Tunnel.Protocol {
	case "tcp":
		NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay).Optimize(conn)
	case "kcp":
		NewKCPTransport(s.cfg.KCP).Optimize(conn)
	}
}

func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if errClosed(err) {
					return
				}
				log.Printf("[SERVER] Accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		s.optimize(conn)
		s.wg.Add(1)
		go s.handleTunnel(ctx, conn)
	}
}

func (s *Server) handleTunnel(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()

	mux := NewMux(conn)
	if err := s.auth(mux); err != nil {
		log.Printf("[SERVER] Auth failed %s: %v", conn.RemoteAddr(), err)
		mux.Close()
		return
	}
	log.Printf("[SERVER] Authenticated: %s", conn.RemoteAddr())

	s.tunnelPool.Add(mux)
	defer func() {
		s.tunnelPool.Remove(mux)
		mux.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		f, err := mux.ReadFrame()
		if err != nil {
			if err != io.EOF && !errClosed(err) {
				log.Printf("[SERVER] Tunnel read: %v", err)
			}
			return
		}

		switch f.Type {
		case MsgNewConn:
			// Client accepted user → connect to local service
			s.wg.Add(1)
			go s.connectLocal(ctx, mux, f.Port, f.ConnID)

		case MsgData:
			// User data from client → forward to local service
			s.forwardToLocal(f)

		case MsgCloseConn:
			if v, ok := s.localConns.Load(f.ConnID); ok {
				v.(net.Conn).Close()
				s.localConns.Delete(f.ConnID)
			}

		case MsgKeepAlive:
			mux.WriteFrame(NewControlFrame(MsgKeepAlive, 0, 0))
		}
	}
}

func (s *Server) auth(mux *Mux) error {
	mux.conn.SetDeadline(time.Now().Add(time.Duration(s.cfg.Performance.Timeout) * time.Second))
	defer mux.conn.SetDeadline(time.Time{})

	f, err := mux.ReadFrame()
	if err != nil {
		return err
	}
	if f.Type != MsgAuth {
		return fmt.Errorf("expected auth, got 0x%02x", f.Type)
	}

	token, err := s.crypto.Decrypt(f.Payload)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if !VerifyAuthToken(token, s.cfg.Tunnel.SecretKey) {
		mux.WriteFrame(NewControlFrame(MsgAuthFail, 0, 0))
		return fmt.Errorf("bad token")
	}

	if err := mux.WriteFrame(NewControlFrame(MsgAuthOK, 0, 0)); err != nil {
		return err
	}

	enc, err := s.crypto.Encrypt(EncodePortMap(s.ports))
	if err != nil {
		return err
	}
	return mux.WriteFrame(&Frame{Type: MsgPortMap, Payload: enc})
}

// connectLocal: connect to local service (Xray) when client reports new user
func (s *Server) connectLocal(ctx context.Context, mux *Mux, port uint16, connID uint32) {
	defer s.wg.Done()

	addr := fmt.Sprintf("%s:%d", s.cfg.Tunnel.ServerBind, port)
	lc, err := net.DialTimeout("tcp", addr, time.Duration(s.cfg.Performance.Timeout)*time.Second)
	if err != nil {
		log.Printf("[SERVER] Local connect %s failed (conn=%d): %v", addr, connID, err)
		mux.WriteFrame(NewControlFrame(MsgCloseConn, connID, port))
		return
	}

	NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay).Optimize(lc)
	s.localConns.Store(connID, lc)

	defer func() {
		lc.Close()
		s.localConns.Delete(connID)
		mux.WriteFrame(NewControlFrame(MsgCloseConn, connID, port))
	}()

	// Read from local service → encrypt → tunnel → client → user
	buf := s.pool.Get()
	defer s.pool.Put(buf)

	idle := time.Duration(s.cfg.Performance.MaxIdle) * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		lc.SetReadDeadline(time.Now().Add(idle))
		n, err := lc.Read(buf)
		if err != nil {
			if err != io.EOF && !errTimeout(err) && !errClosed(err) {
				log.Printf("[SERVER] Local read (conn=%d): %v", connID, err)
			}
			return
		}
		if n == 0 {
			continue
		}

		obf, err := s.obfs.Obfuscate(buf[:n])
		if err != nil {
			return
		}
		enc, err := s.crypto.Encrypt(obf)
		if err != nil {
			return
		}
		if err := mux.WriteFrame(NewDataFrame(connID, port, enc)); err != nil {
			return
		}
	}
}

// forwardToLocal: decrypt data from client and write to local service
func (s *Server) forwardToLocal(f *Frame) {
	dec, err := s.crypto.Decrypt(f.Payload)
	if err != nil {
		return
	}
	data, err := s.obfs.Deobfuscate(dec)
	if err != nil {
		return
	}
	v, ok := s.localConns.Load(f.ConnID)
	if !ok {
		return
	}
	lc := v.(net.Conn)
	lc.SetWriteDeadline(time.Now().Add(time.Duration(s.cfg.Performance.Timeout) * time.Second))
	if _, err := lc.Write(data); err != nil {
		lc.Close()
		s.localConns.Delete(f.ConnID)
	}
	lc.SetWriteDeadline(time.Time{})
}

func errTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

func errClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return err == io.EOF || err == io.ErrClosedPipe || err == net.ErrClosed ||
		strContains(s, "use of closed") || strContains(s, "broken pipe") || strContains(s, "connection reset")
}

func strContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
