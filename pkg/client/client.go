package client

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

// Client runs on the IRAN server.
// It connects OUT to the foreign server (reverse tunnel)
// and forwards incoming mux streams to local services.
type Client struct {
	cfg  *config.Config
	pool *pool.BufferPool
}

func New(cfg *config.Config) *Client {
	return &Client{
		cfg:  cfg,
		pool: pool.NewBufferPool(cfg.BufferSize),
	}
}

func (c *Client) Run(ctx context.Context) error {
	retryCount := 0

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		err := c.connect(ctx)
		if err != nil && ctx.Err() == nil {
			retryCount++
			delay := c.backoff(retryCount)
			log.Printf("[WARN] Connection lost: %v (retry #%d in %v)",
				err, retryCount, delay)

			if c.cfg.MaxReconnect > 0 && retryCount >= c.cfg.MaxReconnect {
				return fmt.Errorf("max reconnect attempts reached")
			}

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil
			}
		} else {
			retryCount = 0
		}
	}
}

func (c *Client) connect(ctx context.Context) error {
	serverAddr := fmt.Sprintf("%s:%d", c.cfg.ServerAddr, c.cfg.ServerPort)
	log.Printf("[INFO] Connecting to %s...", serverAddr)

	// Dial with timeout
	dialer := net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()

	// Wrap with obfuscation (anti-DPI)
	obfConn := obfuscation.WrapConn(raw, obfuscation.Config{
		PaddingRange:  c.cfg.PaddingRange,
		FragmentRange: c.cfg.FragmentRange,
		SNI:           c.cfg.TLSSNI,
	})

	// Send fake TLS ClientHello (defeats SNI-based DPI)
	if c.cfg.Obfuscation == "tls" {
		if err := obfConn.FakeClientHello(); err != nil {
			return fmt.Errorf("fake hello: %w", err)
		}
	}

	// Generate session salt and send it
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("salt: %w", err)
	}
	if _, err := obfConn.Conn.Write(salt); err != nil {
		return fmt.Errorf("send salt: %w", err)
	}

	// Derive session key from PSK + salt
	key, err := crypto.DeriveKey(c.cfg.KeyHash[:], salt)
	if err != nil {
		return fmt.Errorf("key derive: %w", err)
	}

	cipher, err := crypto.NewCipherSuite(key)
	if err != nil {
		return fmt.Errorf("cipher: %w", err)
	}

	// Send encrypted auth + tunnel config
	authData := make([]byte, 2)
	binary.BigEndian.PutUint16(authData, uint16(c.cfg.RemotePort))

	encAuth, err := cipher.Encrypt(authData, salt)
	if err != nil {
		return fmt.Errorf("auth encrypt: %w", err)
	}
	if _, err := obfConn.Write(encAuth); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	log.Printf("[INFO] ✓ Authenticated with server")
	log.Printf("[INFO] ✓ Tunnel: remote :%d -> local :%d",
		c.cfg.RemotePort, c.cfg.LocalPort)

	// Create multiplexed session
	muxSession := mux.NewMux(obfConn, cipher, false)
	defer muxSession.Close()

	// Heartbeat
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	go func() {
		ticker := time.NewTicker(time.Duration(c.cfg.HeartbeatSec) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := muxSession.SendPing(); err != nil {
					connCancel()
					return
				}
			case <-connCtx.Done():
				return
			}
		}
	}()

	// Accept streams and forward to local service
	for {
		stream, err := muxSession.AcceptStream()
		if err != nil {
			return fmt.Errorf("accept stream: %w", err)
		}
		go c.handleStream(connCtx, stream)
	}
}

func (c *Client) handleStream(ctx context.Context, stream *mux.Stream) {
	defer stream.Close()

	// Connect to local service
	localAddr := fmt.Sprintf("127.0.0.1:%d", c.cfg.LocalPort)
	localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
	if err != nil {
		log.Printf("[WARN] Local connect %s failed: %v", localAddr, err)
		return
	}
	defer localConn.Close()

	// Bidirectional copy
	c.biCopy(localConn, stream)
}

func (c *Client) biCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		buf := c.pool.Get()
		defer c.pool.Put(buf)
		io.CopyBuffer(dst, src, buf)
	}

	go copy(a, b)
	go copy(b, a)
	wg.Wait()
}

func (c *Client) backoff(retry int) time.Duration {
	base := time.Duration(c.cfg.ReconnectSec) * time.Second
	delay := base * time.Duration(1<<min(retry, 6)) // exponential, max 64x
	if delay > 2*time.Minute {
		delay = 2 * time.Minute
	}
	return delay
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
