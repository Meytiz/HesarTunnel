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

// Server runs on FOREIGN server
// - Listens for reverse tunnel connections from Iran client
// - When data arrives through tunnel, forwards to LOCAL services (e.g., Xray on 127.0.0.1)
// - Does NOT listen on config ports (client does that)
type Server struct {
	cfg    *Config
	crypto *CryptoEngine
	obfs   *Obfuscator
	pool   *BufferPool
	ports  []int

	tunnelPool *TunnelPool
	localConns *ConnMap // connID -> net.Conn (connections to local services like Xray)

	tunnelListener net.Listener
	listMu         sync.Mutex

	wg sync.WaitGroup
}

func NewServer(cfg *Config) (*Server, error) {
	crypto, err := NewCryptoEngine(cfg.Crypto.Method, cfg.Tunnel.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("encryption engine init: %w", err)
	}

	ports, err := ParsePorts(cfg.Tunnel.ConfigPorts)
	if err != nil {
		return nil, fmt.Errorf("port parsing: %w", err)
	}

	return &Server{
		cfg:        cfg,
		crypto:     crypto,
		obfs:       NewObfuscator(cfg.Crypto.ObfsMode, cfg.Crypto.Obfuscation),
		pool:       NewBufferPool(cfg.Performance.BufferSize),
		ports:      ports,
		tunnelPool: NewTunnelPool(),
		localConns: NewConnMap(),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	// Only ONE listener: the tunnel port
	// Config ports are NOT listened here — client (Iran) does that
	tunnelAddr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Tunnel.TunnelPort)
	log.Printf("[SERVER] Starting tunnel listener on %s (protocol: %s)", tunnelAddr, s.cfg.Tunnel.Protocol)
	log.Printf("[SERVER] Forward target: %s (config ports: %v)", s.cfg.Tunnel.ServerBind, s.ports)
	log.Printf("[SERVER] Waiting for client connections from Iran...")

	var err error
	s.tunnelListener, err = s.createListener(tunnelAddr)
	if err != nil {
		return fmt.Errorf("tunnel listener: %w", err)
	}

	// Accept tunnel connections from Iran
	s.wg.Add(1)
	go s.acceptTunnels(ctx)

	<-ctx.Done()
	return nil
}

func (s *Server) Shutdown(ctx context.Context) {
	log.Println("[SERVER] Shutting down...")

	if s.tunnelListener != nil {
		s.tunnelListener.Close()
	}

	s.tunnelPool.CloseAll()

	s.localConns.Range(func(id uint32, v interface{}) bool {
		if conn, ok := v.(net.Conn); ok {
			conn.Close()
		}
		return true
	})
	s.localConns.Clear()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[SERVER] All goroutines stopped")
	case <-ctx.Done():
		log.Println("[SERVER] Shutdown timeout")
	}
}

func (s *Server) createListener(address string) (net.Listener, error) {
	switch s.cfg.Tunnel.Protocol {
	case "tcp":
		return NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay).Listen(address)
	case "kcp":
		return NewKCPTransport(s.cfg.KCP).Listen(address)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", s.cfg.Tunnel.Protocol)
	}
}

func (s *Server) optimizeConn(conn net.Conn) {
	switch s.cfg.Tunnel.Protocol {
	case "tcp":
		NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay).Optimize(conn)
	case "kcp":
		NewKCPTransport(s.cfg.KCP).Optimize(conn)
	}
}

// ─── Accept Tunnel Connections from Iran ─────────────────

func (s *Server) acceptTunnels(ctx context.Context) {
	defer s.wg.Done()

	for {
		conn, err := s.tunnelListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if isClosedError(err) {
					return
				}
				log.Printf("[SERVER] Tunnel accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		s.optimizeConn(conn)

		s.wg.Add(1)
		go s.handleTunnelConn(ctx, conn)
	}
}

func (s *Server) handleTunnelConn(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()

	mux := NewMux(conn)

	// Authenticate client
	if err := s.authenticateClient(mux); err != nil {
		log.Printf("[SERVER] Auth failed from %s: %v", conn.RemoteAddr(), err)
		mux.Close()
		return
	}

	log.Printf("[SERVER] Tunnel authenticated from %s", conn.RemoteAddr())

	s.tunnelPool.Add(mux)
	defer func() {
		s.tunnelPool.Remove(mux)
		mux.Close()
		log.Printf("[SERVER] Tunnel disconnected: %s", conn.RemoteAddr())
	}()

	// Read frames from tunnel
	// In REVERSE tunnel:
	// - MsgNewConn: client accepted a user, we need to connect to LOCAL service
	// - MsgData: data from user (via client), forward to local service
	// - MsgCloseConn: user disconnected
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		frame, err := mux.ReadFrame()
		if err != nil {
			if err != io.EOF && !isClosedError(err) {
				log.Printf("[SERVER] Tunnel read error: %v", err)
			}
			return
		}

		switch frame.Type {
		case MsgNewConn:
			// Client (Iran) accepted a new user connection
			// We need to connect to local service (e.g., Xray)
			s.wg.Add(1)
			go s.handleNewLocalConn(ctx, mux, frame.Port, frame.ConnID)

		case MsgData:
			// Data from user (through client), forward to local service
			s.handleDataFromClient(frame)

		case MsgCloseConn:
			// User disconnected, close local connection
			if v, ok := s.localConns.Load(frame.ConnID); ok {
				if lc, ok := v.(net.Conn); ok {
					lc.Close()
				}
				s.localConns.Delete(frame.ConnID)
			}

		case MsgKeepAlive:
			mux.WriteFrame(NewControlFrame(MsgKeepAlive, 0, 0))
		}
	}
}

// ─── Authentication ──────────────────────────────────────

func (s *Server) authenticateClient(mux *Mux) error {
	mux.conn.SetDeadline(time.Now().Add(time.Duration(s.cfg.Performance.Timeout) * time.Second))
	defer mux.conn.SetDeadline(time.Time{})

	frame, err := mux.ReadFrame()
	if err != nil {
		return fmt.Errorf("read auth: %w", err)
	}
	if frame.Type != MsgAuth {
		return fmt.Errorf("expected MsgAuth, got 0x%02x", frame.Type)
	}

	token, err := s.crypto.Decrypt(frame.Payload)
	if err != nil {
		return fmt.Errorf("decrypt token: %w", err)
	}
	if !VerifyAuthToken(token, s.cfg.Tunnel.SecretKey) {
		mux.WriteFrame(NewControlFrame(MsgAuthFail, 0, 0))
		return fmt.Errorf("invalid auth token")
	}

	if err := mux.WriteFrame(NewControlFrame(MsgAuthOK, 0, 0)); err != nil {
		return fmt.Errorf("send auth OK: %w", err)
	}

	portData := EncodePortMap(s.ports)
	encPorts, err := s.crypto.Encrypt(portData)
	if err != nil {
		return fmt.Errorf("encrypt port map: %w", err)
	}
	return mux.WriteFrame(&Frame{Type: MsgPortMap, Payload: encPorts})
}

// ─── Handle New Local Connection (connect to Xray etc.) ──

func (s *Server) handleNewLocalConn(ctx context.Context, mux *Mux, port uint16, connID uint32) {
	defer s.wg.Done()

	// Connect to LOCAL service (e.g., Xray on 127.0.0.1:8880)
	localAddr := fmt.Sprintf("%s:%d", s.cfg.Tunnel.ServerBind, port)
	localConn, err := net.DialTimeout("tcp", localAddr, time.Duration(s.cfg.Performance.Timeout)*time.Second)
	if err != nil {
		log.Printf("[SERVER] Cannot connect to local %s (conn=%d): %v", localAddr, connID, err)
		mux.WriteFrame(NewControlFrame(MsgCloseConn, connID, port))
		return
	}

	NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay).Optimize(localConn)
	s.localConns.Store(connID, localConn)

	log.Printf("[SERVER] Connected to local %s (conn=%d)", localAddr, connID)

	defer func() {
		localConn.Close()
		s.localConns.Delete(connID)
		mux.WriteFrame(NewControlFrame(MsgCloseConn, connID, port))
	}()

	// Read from local service → encrypt → send through tunnel → client → user
	buf := s.pool.Get()
	defer s.pool.Put(buf)

	idleTimeout := time.Duration(s.cfg.Performance.MaxIdle) * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		localConn.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := localConn.Read(buf)
		if err != nil {
			if err != io.EOF && !isTimeoutError(err) && !isClosedError(err) {
				log.Printf("[SERVER] Local read error (conn=%d): %v", connID, err)
			}
			return
		}

		if n == 0 {
			continue
		}

		// Obfuscate + Encrypt
		obfuscated, err := s.obfs.Obfuscate(buf[:n])
		if err != nil {
			log.Printf("[SERVER] Obfuscate error: %v", err)
			return
		}

		encrypted, err := s.crypto.Encrypt(obfuscated)
		if err != nil {
			log.Printf("[SERVER] Encrypt error: %v", err)
			return
		}

		// Send back through tunnel to client
		if err := mux.WriteFrame(NewDataFrame(connID, port, encrypted)); err != nil {
			log.Printf("[SERVER] Tunnel write error (conn=%d): %v", connID, err)
			return
		}
	}
}

// ─── Handle Data from Client (user data) ─────────────────

func (s *Server) handleDataFromClient(frame *Frame) {
	// Decrypt data that came from user through tunnel
	decrypted, err := s.crypto.Decrypt(frame.Payload)
	if err != nil {
		log.Printf("[SERVER] Decrypt error (conn=%d): %v", frame.ConnID, err)
		return
	}

	data, err := s.obfs.Deobfuscate(decrypted)
	if err != nil {
		log.Printf("[SERVER] Deobfuscate error (conn=%d): %v", frame.ConnID, err)
		return
	}

	// Forward to local service (Xray)
	v, ok := s.localConns.Load(frame.ConnID)
	if !ok {
		return
	}
	lc, ok := v.(net.Conn)
	if !ok {
		return
	}

	lc.SetWriteDeadline(time.Now().Add(time.Duration(s.cfg.Performance.Timeout) * time.Second))
	if _, err := lc.Write(data); err != nil {
		lc.Close()
		s.localConns.Delete(frame.ConnID)
	}
	lc.SetWriteDeadline(time.Time{})
}

// ─── Helpers ─────────────────────────────────────────────

func isTimeoutError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return err == io.EOF ||
		err == io.ErrClosedPipe ||
		err == net.ErrClosed ||
		containsStr(errStr, "use of closed") ||
		containsStr(errStr, "broken pipe") ||
		containsStr(errStr, "connection reset")
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && findStr(s, substr)
}

func findStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
