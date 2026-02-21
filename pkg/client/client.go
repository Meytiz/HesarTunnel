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

type Client struct {
	cfg        *config.Config
	pool       *pool.BufferPool
	muxSession *mux.Mux
	muxMu      sync.RWMutex
}

func New(cfg *config.Config) *Client {
	return &Client{
		cfg:  cfg,
		pool: pool.NewBufferPool(cfg.BufferSize),
	}
}

func (c *Client) Run(ctx context.Context) error {
	// اجرا کردن Listener لوکال (پورت ایران) فقط برای یک بار
	localAddr := fmt.Sprintf(":%d", c.cfg.LocalPort)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on local port %d: %w", c.cfg.LocalPort, err)
	}
	defer listener.Close()

	log.Printf("[INFO] Client reading on Local Port %s (Give this to users)", localAddr)

	// اجرای حلقه پذیرش کاربران روی سرور ایران
	go c.acceptUsers(listener)

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
			log.Printf("[WARN] Tunnel lost: %v (retry #%d in %v)", err, retryCount, delay)

			if c.cfg.MaxReconnect > 0 && retryCount >= c.cfg.MaxReconnect {
				return fmt.Errorf("max reconnect attempts reached")
			}
			time.Sleep(delay)
		} else if err == nil {
			retryCount = 0
		}
	}
}

func (c *Client) acceptUsers(listener net.Listener) {
	for {
		userConn, err := listener.Accept()
		if err != nil {
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()

			c.muxMu.RLock()
			m := c.muxSession
			c.muxMu.RUnlock()

			if m == nil {
				log.Printf("[WARN] Tunnel is not ready, dropping user connection")
				return
			}

			// باز کردن یک مسیر امن جدید برای کاربر در داخل تونل
			stream, err := m.OpenStream()
			if err != nil {
				log.Printf("[WARN] Failed to open stream in tunnel: %v", err)
				return
			}
			defer stream.Close()

			c.biCopy(conn, stream)
		}(userConn)
	}
}

func (c *Client) connect(ctx context.Context) error {
	serverAddr := fmt.Sprintf("%s:%d", c.cfg.ServerAddr, c.cfg.ServerPort)
	log.Printf("[INFO] Connecting tunnel to Foreign Server %s...", serverAddr)

	dialer := net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()

	if c.cfg.Obfuscation == "tls" {
		tmpObf := obfuscation.WrapConn(raw, obfuscation.Config{
			PaddingRange:  c.cfg.PaddingRange,
			FragmentRange: c.cfg.FragmentRange,
			SNI:           c.cfg.TLSSNI,
		})
		if err := tmpObf.FakeClientHello(); err != nil {
			return fmt.Errorf("fake hello: %w", err)
		}
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("salt: %w", err)
	}
	if _, err := raw.Write(salt); err != nil {
		return fmt.Errorf("send salt: %w", err)
	}

	key, err := crypto.DeriveKey(c.cfg.KeyHash[:], salt)
	if err != nil {
		return fmt.Errorf("key derive: %w", err)
	}

	cipher, err := crypto.NewCipherSuite(key)
	if err != nil {
		return fmt.Errorf("cipher: %w", err)
	}

	obfConn := obfuscation.WrapConn(raw, obfuscation.Config{
		PaddingRange:  c.cfg.PaddingRange,
		FragmentRange: c.cfg.FragmentRange,
		SNI:           c.cfg.TLSSNI,
	})

	authData := make([]byte, 2)
	binary.BigEndian.PutUint16(authData, uint16(c.cfg.RemotePort))

	encAuth, err := cipher.Encrypt(authData, salt)
	if err != nil {
		return fmt.Errorf("auth encrypt: %w", err)
	}
	if _, err := obfConn.Write(encAuth); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	log.Printf("[INFO] ✓ Tunnel Authenticated")
	log.Printf("[INFO] ✓ Traffic Route: Users [:%d] ---> X-UI [:%d]", c.cfg.LocalPort, c.cfg.RemotePort)

	muxSession := mux.NewMux(obfConn, cipher, false)
	
	c.muxMu.Lock()
	c.muxSession = muxSession
	c.muxMu.Unlock()

	defer func() {
		c.muxMu.Lock()
		c.muxSession = nil
		c.muxMu.Unlock()
		muxSession.Close()
	}()

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

	// بلاک ماندن کلاینت تا زمانی که ارتباط تونل قطع شود
	for {
		_, err := muxSession.AcceptStream()
		if err != nil {
			return fmt.Errorf("tunnel closed: %w", err)
		}
	}
}

func (c *Client) biCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyFn := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		buf := c.pool.Get()
		defer c.pool.Put(buf)
		io.CopyBuffer(dst, src, buf)
	}

	go copyFn(a, b)
	go copyFn(b, a)
	wg.Wait()
}

func (c *Client) backoff(retry int) time.Duration {
	base := time.Duration(c.cfg.ReconnectSec) * time.Second
	shift := retry
	if shift > 6 {
		shift = 6
	}
	delay := base * time.Duration(1<<shift)
	if delay > 2*time.Minute {
		delay = 2 * time.Minute
	}
	return delay
}
