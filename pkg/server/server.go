package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"hesartunnel/pkg/config"
	"hesartunnel/pkg/crypto"
	"hesartunnel/pkg/mux"
	"hesartunnel/pkg/obfuscation"
	"hesartunnel/pkg/pool"
)

// Server runs on the FOREIGN server.
// It accepts reverse tunnel connections from Iranian clients
// and forwards external user traffic through the tunnel.
type Server struct {
	cfg     *config.Config
	clients map[string]*ClientSession
	mu      sync.RWMutex
	pool    *pool.BufferPool
}

type ClientSession struct {
	mux        *mux.Mux
	remotePort int
	listener   net.Listener
	cancel     context.CancelFunc
}

func New(cfg *config.Config) *Server {
	return &Server{
		cfg:     cfg,
		clients: make(map[string]*ClientSession),
		pool:    pool.NewBufferPool(cfg.BufferSize),
	}
}

func (s *Server) Run(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.cfg.ServerPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer listener.Close()

	log.Printf("[INFO] Control plane listening on %s", addr)
	log.Printf("[INFO] Waiting for tunnel clients...")

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("[WARN] Accept error: %v", err)
				continue
			}
		}
		go s.handleTunnelClient(ctx, conn)
	}
}

func (s *Server) handleTunnelClient(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	remoteAddr := raw.RemoteAddr().String()
	log.Printf("[INFO] New tunnel client: %s", remoteAddr)

	// ─── PHASE 1: Raw TCP handshake (pre-obfuscation) ───
	//
	// Protocol auto-detection:
	//   - First byte 0x16 → Client sent FakeClientHello, consume it, then read salt
	//   - Any other byte  → First byte is part of the 32-byte salt
	//
	// This ensures the server works regardless of client obfuscation setting.

	salt := make([]byte, 32)

	firstByte := make([]byte, 1)
	if _, err := io.ReadFull(raw, firstByte); err != nil {
		log.Printf("[WARN] Handshake failed (read first byte): %v", err)
		return
	}

	if firstByte[0] == 0x16 {
		// TLS ClientHello detected — consume the entire record
		restHeader := make([]byte, 4)
		if _, err := io.ReadFull(raw, restHeader); err != nil {
			log.Printf("[WARN] Handshake failed (ClientHello header): %v", err)
			return
		}
		recordLen := binary.BigEndian.Uint16(restHeader[2:4])
		if recordLen > 16384 {
			log.Printf("[WARN] Invalid ClientHello length: %d", recordLen)
			return
		}
		helloPayload := make([]byte, recordLen)
		if _, err := io.ReadFull(raw, helloPayload); err != nil {
			log.Printf("[WARN] Handshake failed (ClientHello body): %v", err)
			return
		}
		log.Printf("[DEBUG] Consumed FakeClientHello (%d bytes) from %s", recordLen, remoteAddr)

		// Now read the 32-byte salt
		if _, err := io.ReadFull(raw, salt); err != nil {
			log.Printf("[WARN] Handshake failed (salt after hello): %v", err)
			return
		}
	} else {
		// No ClientHello — first byte is start of salt
		salt[0] = firstByte[0]
		if _, err := io.ReadFull(raw, salt[1:]); err != nil {
			log.Printf("[WARN] Handshake failed (salt): %v", err)
			return
		}
	}

	// Derive session key from PSK + salt
	key, err := crypto.DeriveKey(s.cfg.KeyHash[:], salt)
	if err != nil {
		log.Printf("[WARN] Key derivation failed: %v", err)
		return
	}

	cipher, err := crypto.NewCipherSuite(key)
	if err != nil {
		log.Printf("[WARN] Cipher init failed: %v", err)
		return
	}

	// ─── PHASE 2: Obfuscated connection (TLS record framing) ───

	obfConn := obfuscation.WrapConn(raw, obfuscation.Config{
		PaddingRange:  s.cfg.PaddingRange,
		FragmentRange: s.cfg.FragmentRange,
		SNI:           s.cfg.TLSSNI,
	})

	// Read encrypted auth token through obfuscated connection
	authBuf := make([]byte, 512)
	n, err := obfConn.Read(authBuf)
	if err != nil {
		log.Printf("[WARN] Auth read failed: %v", err)
		return
	}

	authData, err := cipher.Decrypt(authBuf[:n], salt)
	if err != nil {
		log.Printf("[WARN] Auth verification FAILED from %s (wrong key?)", remoteAddr)
		return
	}

	// Parse tunnel config from auth data (with bounds check)
	tunnelCfg, err := parseTunnelConfig(authData)
	if err != nil {
		log.Printf("[WARN] Invalid tunnel config from %s: %v", remoteAddr, err)
		return
	}
	log.Printf("[INFO] Client authenticated: %s -> expose port %d",
		remoteAddr, tunnelCfg.RemotePort)

	// ─── PHASE 3: Multiplexed tunnel session ───

	clientCtx, clientCancel := context.WithCancel(ctx)
	defer clientCancel()

	muxSession := mux.NewMux(obfConn, cipher, true)
	defer muxSession.Close()

	// Register client session
	session := &ClientSession{
		mux:        muxSession,
		remotePort: tunnelCfg.RemotePort,
		cancel:     clientCancel,
	}

	s.mu.Lock()
	s.clients[remoteAddr] = session
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, remoteAddr)
		s.mu.Unlock()
	}()

	// Start public listener for this tunnel
	pubAddr := fmt.Sprintf(":%d", tunnelCfg.RemotePort)
	pubListener, err := net.Listen("tcp", pubAddr)
	if err != nil {
		log.Printf("[ERROR] Cannot listen on %s: %v", pubAddr, err)
		return
	}
	session.listener = pubListener
	defer pubListener.Close()

	log.Printf("[INFO] ✓ Tunnel active: public :%d -> client %s",
		tunnelCfg.RemotePort, remoteAddr)

	// Heartbeat goroutine
	go func() {
		ticker := time.NewTicker(time.Duration(s.cfg.HeartbeatSec) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := muxSession.SendPing(); err != nil {
					clientCancel()
					return
				}
			case <-clientCtx.Done():
				return
			}
		}
	}()

	// Close public listener when context is cancelled
	go func() {
		<-clientCtx.Done()
		pubListener.Close()
	}()

	// Accept public connections and forward through tunnel
	for {
		pubConn, err := pubListener.Accept()
		if err != nil {
			select {
			case <-clientCtx.Done():
				return
			default:
				continue
			}
		}
		go s.proxyConnection(pubConn, muxSession)
	}
}

func (s *Server) proxyConnection(pubConn net.Conn, m *mux.Mux) {
	defer pubConn.Close()

	// Open a new mux stream to the client
	stream, err := m.OpenStream()
	if err != nil {
		log.Printf("[WARN] Stream open failed: %v", err)
		return
	}
	defer stream.Close()

	// Bidirectional copy with buffer pool
	s.biCopy(pubConn, stream)
}

func (s *Server) biCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyFn := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		buf := s.pool.Get()
		defer s.pool.Put(buf)
		io.CopyBuffer(dst, src, buf)
	}

	go copyFn(a, b)
	go copyFn(b, a)
	wg.Wait()
}

type tunnelConfig struct {
	RemotePort int
}

func parseTunnelConfig(data []byte) (tunnelConfig, error) {
	if len(data) < 2 {
		return tunnelConfig{}, fmt.Errorf("auth data too short: %d bytes", len(data))
	}
	port := int(binary.BigEndian.Uint16(data[:2]))
	if port == 0 || port > 65535 {
		return tunnelConfig{}, fmt.Errorf("invalid port: %d", port)
	}
	return tunnelConfig{RemotePort: port}, nil
}
