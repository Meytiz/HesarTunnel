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

type Server struct {
	cfg        *Config
	crypto     *CryptoEngine
	obfs       *Obfuscator
	pool       *BufferPool
	ports      []int
	tunnelPool *TunnelPool
	localConns *ConnMap
	listener   net.Listener
	wg         sync.WaitGroup
}

func NewServer(cfg *Config) (*Server, error) {
	cr, err := NewCryptoEngine(cfg.Crypto.Method, cfg.Tunnel.SecretKey)
	if err != nil {
		return nil, err
	}
	ports, err := ParsePorts(cfg.Tunnel.ConfigPorts)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg, crypto: cr,
		obfs:       NewObfuscator(cfg.Crypto.ObfsMode, cfg.Crypto.Obfuscation),
		pool:       NewBufferPool(cfg.Performance.BufferSize),
		ports:      ports,
		tunnelPool: NewTunnelPool(),
		localConns: NewConnMap(),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Tunnel.TunnelPort)
	log.Printf("[SERVER] Tunnel on %s (%s)", addr, s.cfg.Tunnel.Protocol)
	log.Printf("[SERVER] Forward to %s, ports %v", s.cfg.Tunnel.ServerBind, s.ports)
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
	if s.listener != nil {
		s.listener.Close()
	}
	s.tunnelPool.CloseAll()
	s.localConns.Range(func(_ uint32, v interface{}) bool {
		v.(net.Conn).Close()
		return true
	})
	s.localConns.Clear()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (s *Server) listen(addr string) (net.Listener, error) {
	if s.cfg.Tunnel.Protocol == "kcp" {
		return NewKCPTransport(s.cfg.KCP).Listen(addr)
	}
	return NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay).Listen(addr)
}

func (s *Server) optimize(c net.Conn) {
	if s.cfg.Tunnel.Protocol == "kcp" {
		NewKCPTransport(s.cfg.KCP).Optimize(c)
	} else {
		NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay).Optimize(c)
	}
}

func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()
	for {
		c, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if isClosed(err) {
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		s.optimize(c)
		s.wg.Add(1)
		go s.handleTunnel(ctx, c)
	}
}

func (s *Server) handleTunnel(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	mux := NewMux(conn)
	if err := s.auth(mux); err != nil {
		log.Printf("[SERVER] Auth fail %s: %v", conn.RemoteAddr(), err)
		mux.Close()
		return
	}
	log.Printf("[SERVER] Auth OK: %s", conn.RemoteAddr())
	s.tunnelPool.Add(mux)
	defer func() { s.tunnelPool.Remove(mux); mux.Close() }()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		f, err := mux.ReadFrame()
		if err != nil {
			if err != io.EOF && !isClosed(err) {
				log.Printf("[SERVER] Read: %v", err)
			}
			return
		}
		switch f.Type {
		case MsgNewConn:
			s.wg.Add(1)
			go s.connectLocal(ctx, mux, f.Port, f.ConnID)
		case MsgData:
			s.fwdToLocal(f)
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
		return fmt.Errorf("expected auth")
	}
	tok, err := s.crypto.Decrypt(f.Payload)
	if err != nil {
		return err
	}
	if !VerifyAuthToken(tok, s.cfg.Tunnel.SecretKey) {
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

func (s *Server) connectLocal(ctx context.Context, mux *Mux, port uint16, cid uint32) {
	defer s.wg.Done()
	addr := fmt.Sprintf("%s:%d", s.cfg.Tunnel.ServerBind, port)
	lc, err := net.DialTimeout("tcp", addr, time.Duration(s.cfg.Performance.Timeout)*time.Second)
	if err != nil {
		log.Printf("[SERVER] Local %s fail (c=%d): %v", addr, cid, err)
		mux.WriteFrame(NewControlFrame(MsgCloseConn, cid, port))
		return
	}
	NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay).Optimize(lc)
	s.localConns.Store(cid, lc)
	defer func() {
		lc.Close()
		s.localConns.Delete(cid)
		mux.WriteFrame(NewControlFrame(MsgCloseConn, cid, port))
	}()

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
			if err != io.EOF && !isTimeout(err) && !isClosed(err) {
				log.Printf("[SERVER] Local read c=%d: %v", cid, err)
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
		if mux.WriteFrame(NewDataFrame(cid, port, enc)) != nil {
			return
		}
	}
}

func (s *Server) fwdToLocal(f *Frame) {
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

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func isClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return err == io.EOF || err == io.ErrClosedPipe || err == net.ErrClosed ||
		shas(s, "use of closed") || shas(s, "broken pipe") || shas(s, "connection reset")
}

func shas(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
