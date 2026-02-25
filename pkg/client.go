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

// Client runs on IRAN server
// - Connects to foreign server (reverse tunnel)
// - LISTENS on config ports (users connect here)
// - Forwards user traffic through encrypted tunnel to foreign server
// - Foreign server then forwards to local service (Xray)
type Client struct {
	cfg    *Config
	crypto *CryptoEngine
	obfs   *Obfuscator
	pool   *BufferPool
	idGen  *ConnIDGenerator
	ports  []int

	tunnelPool *TunnelPool
	localConns *ConnMap // connID -> net.Conn (user connections)

	listeners []net.Listener
	listMu    sync.Mutex

	wg sync.WaitGroup
}

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
		idGen:      NewConnIDGenerator(),
		ports:      ports,
		tunnelPool: NewTunnelPool(),
		localConns: NewConnMap(),
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	remoteAddr := fmt.Sprintf("%s:%d", c.cfg.Tunnel.RemoteIP, c.cfg.Tunnel.TunnelPort)
	log.Printf("[CLIENT] Target server: %s (protocol: %s, tunnels: %d)",
		remoteAddr, c.cfg.Tunnel.Protocol, c.cfg.Performance.TunnelCount)

	// Step 1: Start listening on config ports (users connect here)
	for _, port := range c.ports {
		addr := fmt.Sprintf("%s:%d", c.cfg.Tunnel.ClientForward, port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[CLIENT] WARNING: Cannot listen on %s: %v", addr, err)
			continue
		}
		c.addListener(listener)
		log.Printf("[CLIENT] Listening for users on %s", addr)

		c.wg.Add(1)
		go c.acceptUserConns(ctx, listener, port)
	}

	// Step 2: Connect reverse tunnels to foreign server
	for i := 0; i < c.cfg.Performance.TunnelCount; i++ {
		c.wg.Add(1)
		go c.maintainTunnel(ctx, remoteAddr, i)
	}

	<-ctx.Done()
	return nil
}

func (c *Client) Shutdown(ctx context.Context) {
	log.Println("[CLIENT] Shutting down...")

	// Close all user listeners
	c.listMu.Lock()
	for _, l := range c.listeners {
		l.Close()
	}
	c.listeners = nil
	c.listMu.Unlock()

	c.tunnelPool.CloseAll()

	c.localConns.Range(func(id uint32, v interface{}) bool {
		if conn, ok := v.(net.Conn); ok {
			conn.Close()
		}
		return true
	})
	c.localConns.Clear()

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

func (c *Client) addListener(l net.Listener) {
	c.listMu.Lock()
	c.listeners = append(c.listeners, l)
	c.listMu.Unlock()
}

// ─── Accept User Connections (on config ports) ───────────

func (c *Client) acceptUserConns(ctx context.Context, listener net.Listener, port int) {
	defer c.wg.Done()

	tcpOpt := NewTCPTransport(c.cfg.Performance.Timeout, c.cfg.Performance.NoDelay)

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
				log.Printf("[CLIENT] Port %d accept error: %v", port, err)
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}

		tcpOpt.Optimize(conn)

		// Get a tunnel to send traffic through
		tunnel := c.tunnelPool.Get()
		if tunnel == nil {
			log.Printf("[CLIENT] No tunnel available for port %d, rejecting user", port)
			conn.Close()
			continue
		}
		c.tunnelPool.AdvanceIndex()

		// Assign unique connection ID
		connID := c.idGen.Next()
		c.localConns.Store(connID, conn)

		log.Printf("[CLIENT] User connected on port %d (conn=%d) from %s", port, connID, conn.RemoteAddr())

		// Notify server about new connection
		if err := tunnel.WriteFrame(NewControlFrame(MsgNewConn, connID, uint16(port))); err != nil {
			log.Printf("[CLIENT] Failed to notify server (conn=%d): %v", connID, err)
			conn.Close()
			c.localConns.Delete(connID)
			continue
		}

		// Forward user data → tunnel
		c.wg.Add(1)
		go c.forwardUserToTunnel(ctx, conn, tunnel, uint16(port), connID)
	}
}

// Forward: user connection → encrypt → tunnel → server → Xray
func (c *Client) forwardUserToTunnel(ctx context.Context, userConn net.Conn, tunnel *Mux, port uint16, connID uint32) {
	defer c.wg.Done()
	defer func() {
		tunnel.WriteFrame(NewControlFrame(MsgCloseConn, connID, port))
		userConn.Close()
		c.localConns.Delete(connID)
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

		userConn.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := userConn.Read(buf)
		if err != nil {
			if err != io.EOF && !isTimeoutError(err) && !isClosedError(err) {
				log.Printf("[CLIENT] User read error (conn=%d): %v", connID, err)
			}
			return
		}

		if n == 0 {
			continue
		}

		// Obfuscate + Encrypt
		obfuscated, err := c.obfs.Obfuscate(buf[:n])
		if err != nil {
			log.Printf("[CLIENT] Obfuscate error: %v", err)
			return
		}

		encrypted, err := c.crypto.Encrypt(obfuscated)
		if err != nil {
			log.Printf("[CLIENT] Encrypt error: %v", err)
			return
		}

		// Send through tunnel to foreign server
		if err := tunnel.WriteFrame(NewDataFrame(connID, port, encrypted)); err != nil {
			log.Printf("[CLIENT] Tunnel write error (conn=%d): %v", connID, err)
			return
		}
	}
}

// ─── Maintain Reverse Tunnel to Foreign Server ───────────

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
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		backoff = time.Second
		log.Printf("[CLIENT] Tunnel#%d connected to %s", tunnelID, remoteAddr)

		mux := NewMux(conn)

		if err := c.authenticate(mux); err != nil {
			log.Printf("[CLIENT] Tunnel#%d auth failed: %v", tunnelID, err)
			mux.Close()
			continue
		}

		log.Printf("[CLIENT] Tunnel#%d authenticated", tunnelID)

		c.tunnelPool.Add(mux)
		c.handleTunnel(ctx, mux, tunnelID)
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

	token := GenerateAuthToken(c.cfg.Tunnel.SecretKey)
	encToken, err := c.crypto.Encrypt(token)
	if err != nil {
		return fmt.Errorf("encrypt auth token: %w", err)
	}

	if err := mux.WriteFrame(&Frame{Type: MsgAuth, Payload: encToken}); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	frame, err := mux.ReadFrame()
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	switch frame.Type {
	case MsgAuthFail:
		return fmt.Errorf("server rejected authentication")
	case MsgAuthOK:
	default:
		return fmt.Errorf("unexpected response: 0x%02x", frame.Type)
	}

	portFrame, err := mux.ReadFrame()
	if err != nil {
		return fmt.Errorf("read port map: %w", err)
	}

	if portFrame.Type == MsgPortMap && len(portFrame.Payload) > 0 {
		if decPorts, err := c.crypto.Decrypt(portFrame.Payload); err == nil {
			if ports, err := DecodePortMap(decPorts); err == nil {
				log.Printf("[CLIENT] Server ports: %v", ports)
			}
		}
	}

	return nil
}

// ─── Handle Tunnel Frames (responses from server) ────────

func (c *Client) handleTunnel(ctx context.Context, mux *Mux, tunnelID int) {
	// Keepalive
	keepCtx, keepCancel := context.WithCancel(ctx)
	defer keepCancel()

	c.wg.Add(1)
	go c.sendKeepalive(keepCtx, mux, tunnelID)

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
		case MsgData:
			// Response data from server (Xray response), forward to user
			c.handleDataFromServer(frame)

		case MsgCloseConn:
			// Server closed connection to local service
			if v, ok := c.localConns.Load(frame.ConnID); ok {
				if lc, ok := v.(net.Conn); ok {
					lc.Close()
				}
				c.localConns.Delete(frame.ConnID)
			}

		case MsgKeepAlive:
			// alive
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
				log.Printf("[CLIENT] Tunnel#%d keepalive error: %v", tunnelID, err)
				return
			}
		}
	}
}

// Handle: server response → decrypt → forward to user
func (c *Client) handleDataFromServer(frame *Frame) {
	decrypted, err := c.crypto.Decrypt(frame.Payload)
	if err != nil {
		log.Printf("[CLIENT] Decrypt error (conn=%d): %v", frame.ConnID, err)
		return
	}

	data, err := c.obfs.Deobfuscate(decrypted)
	if err != nil {
		log.Printf("[CLIENT] Deobfuscate error (conn=%d): %v", frame.ConnID, err)
		return
	}

	// Forward to user connection
	v, ok := c.localConns.Load(frame.ConnID)
	if !ok {
		return
	}
	userConn, ok := v.(net.Conn)
	if !ok {
		return
	}

	userConn.SetWriteDeadline(time.Now().Add(time.Duration(c.cfg.Performance.Timeout) * time.Second))
	if _, err := userConn.Write(data); err != nil {
		userConn.Close()
		c.localConns.Delete(frame.ConnID)
	}
	userConn.SetWriteDeadline(time.Time{})
}
