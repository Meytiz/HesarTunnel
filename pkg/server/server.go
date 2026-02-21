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

type Server struct {
	cfg  *config.Config
	pool *pool.BufferPool
}

func New(cfg *config.Config) *Server {
	return &Server{
		cfg:  cfg,
		pool: pool.NewBufferPool(cfg.BufferSize),
	}
}

func (s *Server) Run(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.cfg.ServerPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer listener.Close()

	log.Printf("[INFO] Control plane listening on %s (Control Port)", addr)
	log.Printf("[INFO] Waiting for Iran Client...")

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
	log.Printf("[INFO] New tunnel connection from: %s", remoteAddr)

	salt := make([]byte, 32)
	firstByte := make([]byte, 1)
	if _, err := io.ReadFull(raw, firstByte); err != nil {
		return
	}

	if firstByte[0] == 0x16 {
		restHeader := make([]byte, 4)
		if _, err := io.ReadFull(raw, restHeader); err != nil {
			return
		}
		recordLen := binary.BigEndian.Uint16(restHeader[2:4])
		helloPayload := make([]byte, recordLen)
		if _, err := io.ReadFull(raw, helloPayload); err != nil {
			return
		}
		if _, err := io.ReadFull(raw, salt); err != nil {
			return
		}
	} else {
		salt[0] = firstByte[0]
		if _, err := io.ReadFull(raw, salt[1:]); err != nil {
			return
		}
	}

	key, err := crypto.DeriveKey(s.cfg.KeyHash[:], salt)
	if err != nil {
		return
	}

	cipher, err := crypto.NewCipherSuite(key)
	if err != nil {
		return
	}

	obfConn := obfuscation.WrapConn(raw, obfuscation.Config{
		PaddingRange:  s.cfg.PaddingRange,
		FragmentRange: s.cfg.FragmentRange,
		SNI:           s.cfg.TLSSNI,
	})

	authBuf := make([]byte, 512)
	n, err := obfConn.Read(authBuf)
	if err != nil {
		return
	}

	authData, err := cipher.Decrypt(authBuf[:n], salt)
	if err != nil {
		log.Printf("[WARN] Auth FAILED from %s", remoteAddr)
		return
	}

	tunnelCfg, err := parseTunnelConfig(authData)
	if err != nil {
		return
	}
	
	log.Printf("[INFO] ✓ Iran Server Authenticated")
	log.Printf("[INFO] ✓ Forwarding incoming data to local X-UI on port :%d", tunnelCfg.RemotePort)

	clientCtx, clientCancel := context.WithCancel(ctx)
	defer clientCancel()

	muxSession := mux.NewMux(obfConn, cipher, true)
	defer muxSession.Close()

	go func() {
		<-clientCtx.Done()
		muxSession.Close()
	}()

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

	// گوش دادن به ورودی‌های تونل از سمت ایران
	for {
		select {
		case <-clientCtx.Done():
			return
		default:
		}

		stream, err := muxSession.AcceptStream()
		if err != nil {
			return // Tunnel connection lost
		}

		go func(st *mux.Stream) {
			defer st.Close()
			
			// متصل شدن داخلی به نرم افزار Xray/X-UI
			xrayAddr := fmt.Sprintf("127.0.0.1:%d", tunnelCfg.RemotePort)
			xrayConn, err := net.DialTimeout("tcp", xrayAddr, 5*time.Second)
			if err != nil {
				log.Printf("[WARN] X-UI is not running on port %d... Connection rejected.", tunnelCfg.RemotePort)
				return
			}
			defer xrayConn.Close()

			s.biCopy(xrayConn, st)
		}(stream)
	}
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
		return tunnelConfig{}, fmt.Errorf("auth data too short")
	}
	port := int(binary.BigEndian.Uint16(data[:2]))
	if port == 0 || port > 65535 {
		return tunnelConfig{}, fmt.Errorf("invalid port")
	}
	return tunnelConfig{RemotePort: port}, nil
}
