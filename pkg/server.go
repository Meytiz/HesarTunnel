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

// Server runs on the foreign/remote server
// Accepts reverse tunnel connections from Iran client
// Listens on config ports and forwards traffic through tunnel
type Server struct {
	cfg    *Config
	crypto *CryptoEngine
	obfs   *Obfuscator
	pool   *BufferPool
	idGen  *ConnIDGenerator
	ports  []int

	tunnelPool *TunnelPool
	localConns *ConnMap // connID -> net.Conn

	listeners []net.Listener
	listMu    sync.Mutex

	wg sync.WaitGroup
}

// NewServer creates a new server instance
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
		idGen:      NewConnIDGenerator(),
		ports:      ports,
		tunnelPool: NewTunnelPool(),
		localConns: NewConnMap(),
	}, nil
}

// Run starts the server and blocks until context is cancelled
func (s *Server) Run(ctx context.Context) error {
	// Start tunnel listener
	tunnelAddr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Tunnel.TunnelPort)
	log.Printf("[SERVER] Starting tunnel listener on %s (protocol: %s)", tunnelAddr, s.cfg.Tunnel.Protocol)

	tunnelListener, err := s.createListener(tunnelAddr)
	if err != nil {
		return fmt.Errorf("tunnel listener: %w", err)
	}
	s.addListener(tunnelListener)

	// Accept tunnel connections
	s.wg.Add(1)
	go s.acceptTunnels(ctx, tunnelListener)

	// Start config port listeners
	for _, port := range s.ports {
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[SERVER] WARNING: Cannot listen on port %d: %v", port, err)
			continue
		}
		s.addListener(listener)
		log.Printf("[SERVER] Listening on config port %d", port)

		s.wg.Add(1)
		go s.acceptConfigConns(ctx, listener, port)
	}

	// Wait for context cancellation
	<-ctx.Done()
	return nil
}

// Shutdown performs graceful shutdown
func (s *Server) Shutdown(ctx context.Context) {
	log.Println("[SERVER] Shutting down...")

	// Close all listeners first (stop accepting new connections)
	s.listMu.Lock()
	for _, l := range s.listeners {
		l.Close()
	}
	s.listeners = nil
	s.listMu.Unlock()

	// Close all tunnel connections
	s.tunnelPool.CloseAll()

	// Close all local connections
	s.localConns.Range(func(id uint32, v interface{}) bool {
		if conn, ok := v.(net.Conn); ok {
			conn.Close()
		}
		return true
	})
	s.localConns.Clear()

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[SERVER] All goroutines stopped")
	case <-ctx.Done():
		log.Println("[SERVER] Shutdown timeout, forcing exit")
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

func (s *Server) addListener(l net.Listener) {
	s.listMu.Lock()
	s.listeners = append(s.listeners, l)
	s.listMu.Unlock()
}

func (s *Server) optimizeConn(conn net.Conn) {
	switch s.cfg.Tunnel.Protocol {
	case "tcp":
		NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay).Optimize(conn)
	case "kcp":
		NewKCPTransport(s.cfg.KCP).Optimize(conn)
	}
}

// ─── Tunnel Connection Handling ──────────────────────────

func (s *Server) acceptTunnels(ctx context.Context, listener net.Listener) {
	defer s.wg.Done()

	for {
		conn, err := listener.Accept()
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

	// Authenticate
	mux := NewMux(conn)
	if err := s.authenticateClient(mux); err != nil {
		log.Printf("[SERVER] Auth failed from %s: %v", conn.RemoteAddr(), err)
		mux.Close()
		return
	}

	log.Printf("[SERVER] Tunnel authenticated from %s", conn.RemoteAddr())

	// Add to pool
	s.tunnelPool.Add(mux)
	defer func() {
		s.tunnelPool.Remove(mux)
		mux.Close()
		log.Printf("[SERVER] Tunnel disconnected: %s", conn.RemoteAddr())
	}()

	// Read frames from tunnel (responses from client)
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
		case MsgData:
			s.handleDataFromClient(frame)

		case MsgCloseConn:
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

func (s *Server) authenticateClient(mux *Mux) error {
	// Set deadline for auth
	mux.conn.SetDeadline(time.Now().Add(time.Duration(s.cfg.Performance.Timeout) * time.Second))
	defer mux.conn.SetDeadline(time.Time{})

	// Read auth frame
	frame, err := mux.ReadFrame()
	if err != nil {
		return fmt.Errorf("read auth: %w", err)
	}
	if frame.Type != MsgAuth {
		return fmt.Errorf("expected MsgAuth, got type 0x%02x", frame.Type)
	}

	// Decrypt and verify token
	token, err := s.crypto.Decrypt(frame.Payload)
	if err != nil {
		return fmt.Errorf("decrypt auth token: %w", err)
	}
	if !VerifyAuthToken(token, s.cfg.Tunnel.SecretKey) {
		mux.WriteFrame(NewControlFrame(MsgAuthFail, 0, 0))
		return fmt.Errorf("invalid auth token")
	}

	// Send auth success
	if err := mux.WriteFrame(NewControlFrame(MsgAuthOK, 0, 0)); err != nil {
		return fmt.Errorf("send auth OK: %w", err)
	}

	// Send port mapping
	portData := EncodePortMap(s.ports)
	encPorts, err := s.crypto.Encrypt(portData)
	if err != nil {
		return fmt.Errorf("encrypt port map: %w", err)
	}
	if err := mux.WriteFrame(&Frame{Type: MsgPortMap, Payload: encPorts}); err != nil {
		return fmt.Errorf("send port map: %w", err)
	}

	return nil
}

func (s *Server) handleDataFromClient(frame *Frame) {
	// Decrypt
	decrypted, err := s.crypto.Decrypt(frame.Payload)
	if err != nil {
		log.Printf("[SERVER] Decrypt error (conn=%d): %v", frame.ConnID, err)
		return
	}

	// Deobfuscate
	data, err := s.obfs.Deobfuscate(decrypted)
	if err != nil {
		log.Printf("[SERVER] Deobfuscate error (conn=%d): %v", frame.ConnID, err)
		return
	}

	// Forward to local connection
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

// ─── Config Port Connection Handling ─────────────────────

func (s *Server) acceptConfigConns(ctx context.Context, listener net.Listener, port int) {
	defer s.wg.Done()

	tcpTransport := NewTCPTransport(s.cfg.Performance.Timeout, s.cfg.Performance.NoDelay)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if isClosedError(err) {
					return
				}
				log.Printf("[SERVER] Port %d accept error: %v", port, err)
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}

		tcpTransport.Optimize(conn)

		// Get a tunnel
		tunnel := s.tunnelPool.Get()
		if tunnel == nil {
			log.Printf("[SERVER] No tunnel available for port %d, rejecting connection", port)
			conn.Close()
			continue
		}
		s.tunnelPool.AdvanceIndex()

		// Assign connection ID
		connID := s.idGen.Next()
		s.localConns.Store(connID, conn)

		// Notify client about new connection
		if err := tunnel.WriteFrame(NewControlFrame(MsgNewConn, connID, uint16(port))); err != nil {
			log.Printf("[SERVER] Failed to notify client for conn %d: %v", connID, err)
			conn.Close()
			s.localConns.Delete(connID)
			continue
		}

		// Forward local -> tunnel
		s.wg.Add(1)
		go s.forwardLocalToTunnel(ctx, conn, tunnel, uint16(port), connID)
	}
}

func (s *Server) forwardLocalToTunnel(ctx context.Context, localConn net.Conn, tunnel *Mux, port uint16, connID uint32) {
	defer s.wg.Done()
	defer func() {
		tunnel.WriteFrame(NewControlFrame(MsgCloseConn, connID, port))
		localConn.Close()
		s.localConns.Delete(connID)
	}()

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

		// Obfuscate
		obfuscated, err := s.obfs.Obfuscate(buf[:n])
		if err != nil {
			log.Printf("[SERVER] Obfuscate error: %v", err)
			return
		}

		// Encrypt
		encrypted, err := s.crypto.Encrypt(obfuscated)
		if err != nil {
			log.Printf("[SERVER] Encrypt error: %v", err)
			return
		}

		// Send through tunnel
		if err := tunnel.WriteFrame(NewDataFrame(connID, port, encrypted)); err != nil {
			log.Printf("[SERVER] Tunnel write error (conn=%d): %v", connID, err)
			return
		}
	}
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
	return err == io.EOF ||
		err == io.ErrClosedPipe ||
		err == net.ErrClosed ||
		isErrorContains(err, "use of closed") ||
		isErrorContains(err, "broken pipe") ||
		isErrorContains(err, "connection reset")
}

func isErrorContains(err error, substr string) bool {
	if err == nil {
		return false
	}
	return len(err.Error()) > 0 && contains(err.Error(), substr)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
