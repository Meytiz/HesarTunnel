package server

import (
	"context"
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
	cfg      *config.Config
	clients  map[string]*ClientSession
	mu       sync.RWMutex
	pool     *pool.BufferPool
}

type ClientSession struct {
	mux       *mux.Mux
	remotePort int
	listener  net.Listener
	cancel    context.CancelFunc
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

	// Wrap connection with obfuscation layer
	obfConn := obfuscation.WrapConn(raw, obfuscation.Config{
		PaddingRange:  s.cfg.PaddingRange,
		FragmentRange: s.cfg.FragmentRange,
		SNI:           s.cfg.TLSSNI,
	})

	// Perform handshake: receive salt + verify PSK
	salt := make([]byte, 32)
	if _, err := io.ReadFull(obfConn, salt); err != nil {
		log.Printf("[WARN] Handshake failed (salt): %v", err)
		return
	}

	// Derive session key
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

	// Read encrypted auth token
	authBuf := make([]byte, 256)
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

	// Parse tunnel config from auth data
	tunnelCfg := parseTunnelConfig(authData)
	log.Printf("[INFO] Client authenticated: %s -> expose port %d",
		remoteAddr, tunnelCfg.RemotePort)

	// Create multiplexed session
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

	// Heartbeat
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

	// Accept public connections and forward through tunnel
	go func() {
		<-clientCtx.Done()
		pubListener.Close()
	}()

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
		go s.proxyConnection(clientCtx, pubConn, muxSession)
	}
}

func (s *Server) proxyConnection(ctx context.Context, pubConn net.Conn, m *mux.Mux) {
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

	copy := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		buf := s.pool.Get()
		defer s.pool.Put(buf)
		io.CopyBuffer(dst, src, buf)
	}

	go copy(a, b)
	go copy(b, a)
	wg.Wait()
}

type tunnelConfig struct {
	RemotePort int
}

func parseTunnelConfig(data []byte) tunnelConfig {
	// Simple format: first 2 bytes = remote port
	port := int(data[0])<<8 | int(data[1])
	return tunnelConfig{RemotePort: port}
}
