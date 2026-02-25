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

// Client runs on the Iran server
// Connects to foreign server, creates reverse tunnels
// Forwards received traffic to local services
type Client struct {
	cfg    *Config
	crypto *CryptoEngine
	obfs   *Obfuscator
	pool   *BufferPool
	ports  []int

	tunnelPool *TunnelPool
	localConns *ConnMap // connID -> net.Conn

	wg sync.WaitGroup
}

// NewClient creates a new client instance
func NewClient(cfg *Config) (*Client, error) {
	crypto, err := NewCryptoEngine(cfg.Crypto.Method, cfg.Tunnel.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("encryption engine init: %w", err)
	}

	ports, err := ParsePorts(cfg.Tunnel.ConfigPorts)
	if err != nil {
		return nil, fmt.Errorf("port parsing: %w", err)
	}

	return &Client{
		cfg:        cfg,
		crypto:     crypto,
		obfs:       NewObfuscator(cfg.Crypto.ObfsMode, cfg.Crypto.Obfuscation),
		pool:       NewBufferPool(cfg.Performance.BufferSize),
		ports:      ports,
		tunnelPool: NewTunnelPool(),
		localConns: NewConnMap(),
	}, nil
}

// Run starts the client and blocks until context is cancelled
func (c *Client) Run(ctx context.Context) error {
	remoteAddr := fmt.Sprintf("%s:%d", c.cfg.Tunnel.RemoteIP, c.cfg.Tunnel.TunnelPort)
	log.Printf("[CLIENT] Connecting to server %s (protocol: %s, tunnels: %d)",
		remoteAddr, c.cfg.Tunnel.Protocol, c.cfg.Performance.TunnelCount)

	// Maintain multiple tunnel connections
	for i := 0; i < c.cfg.Performance.TunnelCount; i++ {
		c.wg.Add(1)
		go c.maintainTunnel(ctx, remoteAddr, i)
	}

	<-ctx.Done()
	return nil
}

// Shutdown performs graceful shutdown
func (c *Client) Shutdown(ctx context.Context) {
	log.Println("[CLIENT] Shutting down...")

	// Close all tunnels
	c.tunnelPool.CloseAll()

	// Close all local connections
	c.localConns.Range(func(id uint32, v interface{}) bool {
		if conn, ok := v.(net.Conn); ok {
			conn.Close()
		}
		return true
	})
	c.localConns.Clear()

	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[CLIENT] All goroutines stopped")
	case <-ctx.Done():
		log.Println("[CLIENT] Shutdown timeout")
	}
}

// ─── Tunnel Maintenance ──────────────────────────────────

func (c *Client) maintainTunnel(ctx context.Context, remoteAddr string, tunnelID int) {
	defer c.wg.Done()

	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := c.dialTunnel(remoteAddr)
		if err != nil {
			log.Printf("[CLIENT] Tunnel#%d connect failed: %v (retry in %v)", tunnelID, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			// Exponential backoff
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Reset backoff on successful connect
		backoff = time.Second
		log.Printf("[CLIENT] Tunnel#%d connected to %s", tunnelID, remoteAddr)

		mux := NewMux(conn)

		// Authenticate
		if err := c.authenticate(mux); err != nil {
			log.Printf("[CLIENT] Tunnel#%d auth failed: %v", tunnelID, err)
			mux.Close()
			continue
		}

		log.Printf("[CLIENT] Tunnel#%d authenticated", tunnelID)

		// Add to pool
		c.tunnelPool.Add(mux)

		// Handle tunnel (blocks until disconnected)
		c.handleTunnel(ctx, mux, tunnelID)

		// Cleanup
		c.tunnelPool.Remove(mux)
		mux.Close()

		log.Printf("[CLIENT] Tunnel#%d lost, reconnecting...", tunnelID)
	}
}

func (c *Client) dialTunnel(address string) (net.Conn, error) {
	switch c.cfg.Tunnel.Protocol {
	case "tcp":
		return NewTCPTransport(c.cfg.Performance.Timeout, c.cfg.Performance.NoDelay).Dial(address)
	case "kcp":
		return NewKCPTransport(c.cfg.KCP).Dial(address)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", c.cfg.Tunnel.Protocol)
	}
}

// ─── Authentication ──────────────────────────────────────

func (c *Client) authenticate(mux *Mux) error {
	mux.conn.SetDeadline(time.Now().Add(time.Duration(c.cfg.Performance.Timeout) * time.Second))
	defer mux.conn.SetDeadline(time.Time{})

	// Generate and encrypt auth token
	token := GenerateAuthToken(c.cfg.Tunnel.SecretKey)
	encToken, err := c.crypto.Encrypt(token)
	if err != nil {
		return fmt.Errorf("encrypt auth token: %w", err)
	}

	// Send auth
	if err := mux.WriteFrame(&Frame{Type: MsgAuth, Payload: encToken}); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	// Read response
	frame, err := mux.ReadFrame()
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	switch frame.Type {
	case MsgAuthFail:
		return fmt.Errorf("server rejected authentication")
	case MsgAuthOK:
		// Continue
	default:
		return fmt.Errorf("unexpected auth response type: 0x%02x", frame.Type)
	}

	// Read port mapping
	portFrame, err := mux.ReadFrame()
	if err != nil {
		return fmt.Errorf("read port map: %w", err)
	}

	if portFrame.Type == MsgPortMap && len(portFrame.Payload) > 0 {
		decPorts, err := c.crypto.Decrypt(portFrame.Payload)
		if err != nil {
			log.Printf("[CLIENT] Warning: could not decrypt port map: %v", err)
		} else {
			ports, err := DecodePortMap(decPorts)
			if err != nil {
				log.Printf("[CLIENT] Warning: could not parse port map: %v", err)
			} else {
				log.Printf("[CLIENT] Server ports: %v", ports)
			}
		}
	}

	return nil
}

// ─── Tunnel Frame Handler ────────────────────────────────

func (c *Client) handleTunnel(ctx context.Context, mux *Mux, tunnelID int) {
	// Start keepalive sender
	keepaliveCtx, keepaliveCancel := context.WithCancel(ctx)
	defer keepaliveCancel()

	c.wg.Add(1)
	go c.sendKeepalive(keepaliveCtx, mux, tunnelID)

	// Main read loop
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		frame, err := mux.ReadFrame()
		if err != nil {
			if err != io.EOF && !isClosedError(err) {
				log.Printf("[CLIENT] Tunnel#%d read error: %v", tunnelID, err)
			}
			return
		}

		switch frame.Type {
		case MsgNewConn:
			c.wg.Add(1)
			go c.handleNewConnection(ctx, mux, frame.Port, frame.ConnID)

		case MsgData:
			c.handleDataFromServer(frame)

		case MsgCloseConn:
			if v, ok := c.localConns.Load(frame.ConnID); ok {
				if lc, ok := v.(net.Conn); ok {
					lc.Close()
				}
				c.localConns.Delete(frame.ConnID)
			}

		case MsgKeepAlive:
			// Keepalive response received, connection is alive
		}
	}
}

func (c *Client) sendKeepalive(ctx context.Context, mux *Mux, tunnelID int) {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Duration(c.cfg.Performance.Keepalive) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := mux.WriteFrame(NewControlFrame(MsgKeepAlive, 0, 0)); err != nil {
				log.Printf("[CLIENT] Tunnel#%d keepalive send error: %v", tunnelID, err)
				return
			}
		}
	}
}

func (c *Client) handleDataFromServer(frame *Frame) {
	// Decrypt
	decrypted, err := c.crypto.Decrypt(frame.Payload)
	if err != nil {
		log.Printf("[CLIENT] Decrypt error (conn=%d): %v", frame.ConnID, err)
		return
	}

	// Deobfuscate
	data, err := c.obfs.Deobfuscate(decrypted)
	if err != nil {
		log.Printf("[CLIENT] Deobfuscate error (conn=%d): %v", frame.ConnID, err)
		return
	}

	// Forward to local connection
	v, ok := c.localConns.Load(frame.ConnID)
	if !ok {
		return
	}
	lc, ok := v.(net.Conn)
	if !ok {
		return
	}

	lc.SetWriteDeadline(time.Now().Add(time.Duration(c.cfg.Performance.Timeout) * time.Second))
	if _, err := lc.Write(data); err != nil {
		lc.Close()
		c.localConns.Delete(frame.ConnID)
	}
	lc.SetWriteDeadline(time.Time{})
}

// ─── Local Connection Handler ────────────────────────────

func (c *Client) handleNewConnection(ctx context.Context, mux *Mux, port uint16, connID uint32) {
	defer c.wg.Done()

	// Connect to local service
	localAddr := fmt.Sprintf("127.0.0.1:%d", port)
	localConn, err := net.DialTimeout("tcp", localAddr, time.Duration(c.cfg.Performance.Timeout)*time.Second)
	if err != nil {
		log.Printf("[CLIENT] Cannot connect to local %s (conn=%d): %v", localAddr, connID, err)
		mux.WriteFrame(NewControlFrame(MsgCloseConn, connID, port))
		return
	}

	NewTCPTransport(c.cfg.Performance.Timeout, c.cfg.Performance.NoDelay).Optimize(localConn)
	c.localConns.Store(connID, localConn)

	defer func() {
		localConn.Close()
		c.localConns.Delete(connID)
		mux.WriteFrame(NewControlFrame(MsgCloseConn, connID, port))
	}()

	buf := c.pool.Get()
	defer c.pool.Put(buf)

	idleTimeout := time.Duration(c.cfg.Performance.MaxIdle) * time.Second

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
				log.Printf("[CLIENT] Local read error (conn=%d): %v", connID, err)
			}
			return
		}

		if n == 0 {
			continue
		}

		// Obfuscate
		obfuscated, err := c.obfs.Obfuscate(buf[:n])
		if err != nil {
			log.Printf("[CLIENT] Obfuscate error: %v", err)
			return
		}

		// Encrypt
		encrypted, err := c.crypto.Encrypt(obfuscated)
		if err != nil {
			log.Printf("[CLIENT] Encrypt error: %v", err)
			return
		}

		// Send through tunnel
		if err := mux.WriteFrame(NewDataFrame(connID, port, encrypted)); err != nil {
			log.Printf("[CLIENT] Tunnel write error (conn=%d): %v", connID, err)
			return
		}
	}
}
