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

// Client runs on IRAN server.
// Listens on config ports (users connect here).
// Connects reverse tunnel to foreign server.
// Forwards user traffic through tunnel.
type Client struct {
	cfg    *Config
	crypto *CryptoEngine
	obfs   *Obfuscator
	pool   *BufferPool
	idGen  *ConnIDGenerator
	ports  []int

	tunnelPool *TunnelPool
	localConns *ConnMap // connID -> user net.Conn

	listeners []net.Listener
	listMu    sync.Mutex
	wg        sync.WaitGroup
}

func NewClient(cfg *Config) (*Client, error) {
	cr, err := NewCryptoEngine(cfg.Crypto.Method, cfg.Tunnel.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	ports, err := ParsePorts(cfg.Tunnel.ConfigPorts)
	if err != nil {
		return nil, fmt.Errorf("ports: %w", err)
	}
	return &Client{
		cfg:        cfg,
		crypto:     cr,
		obfs:       NewObfuscator(cfg.Crypto.ObfsMode, cfg.Crypto.Obfuscation),
		pool:       NewBufferPool(cfg.Performance.BufferSize),
		idGen:      NewConnIDGenerator(),
		ports:      ports,
		tunnelPool: NewTunnelPool(),
		localConns: NewConnMap(),
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	remote := fmt.Sprintf("%s:%d", c.cfg.Tunnel.RemoteIP, c.cfg.Tunnel.TunnelPort)
	log.Printf("[CLIENT] Server: %s (%s, %d tunnels)", remote, c.cfg.Tunnel.Protocol, c.cfg.Performance.TunnelCount)
	log.Printf("[CLIENT] Listen: %s, ports: %v", c.cfg.Tunnel.ClientForward, c.ports)

	// Listen on config ports for users
	for _, port := range c.ports {
		addr := fmt.Sprintf("%s:%d", c.cfg.Tunnel.ClientForward, port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[CLIENT] WARNING: Cannot listen %s: %v", addr, err)
			continue
		}
		c.listMu.Lock()
		c.listeners = append(c.listeners, ln)
		c.listMu.Unlock()
		log.Printf("[CLIENT] Listening for users on %s", addr)

		c.wg.Add(1)
		go c.acceptUsers(ctx, ln, port)
	}

	// Connect tunnels to foreign server
	for i := 0; i < c.cfg.Performance.TunnelCount; i++ {
		c.wg.Add(1)
		go c.maintainTunnel(ctx, remote, i)
	}

	<-ctx.Done()
	return nil
}

func (c *Client) Shutdown(ctx context.Context) {
	log.Println("[CLIENT] Shutting down...")

	c.listMu.Lock()
	for _, ln := range c.listeners {
		ln.Close()
	}
	c.listeners = nil
	c.listMu.Unlock()

	c.tunnelPool.CloseAll()
	c.localConns.Range(func(_ uint32, v interface{}) bool {
		v.(net.Conn).Close()
		return true
	})
	c.localConns.Clear()

	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	log.Println("[CLIENT] Stopped")
}

// ─── Accept Users ────────────────────────────────────────

func (c *Client) acceptUsers(ctx context.Context, ln net.Listener, port int) {
	defer c.wg.Done()
	opt := NewTCPTransport(c.cfg.Performance.Timeout, c.cfg.Performance.NoDelay)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if errClosed(err) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}

		opt.Optimize(conn)

		tun := c.tunnelPool.Get()
		if tun == nil {
			log.Printf("[CLIENT] No tunnel for port %d, reject", port)
			conn.Close()
			continue
		}
		c.tunnelPool.AdvanceIndex()

		id := c.idGen.Next()
		c.localConns.Store(id, conn)

		// Notify server: new user connected
		if err := tun.WriteFrame(NewControlFrame(MsgNewConn, id, uint16(port))); err != nil {
			conn.Close()
			c.localConns.Delete(id)
			continue
		}

		c.wg.Add(1)
		go c.forwardUserToTunnel(ctx, conn, tun, uint16(port), id)
	}
}

// Forward: user → encrypt → tunnel → server → Xray
func (c *Client) forwardUserToTunnel(ctx context.Context, user net.Conn, tun *Mux, port uint16, id uint32) {
	defer c.wg.Done()
	defer func() {
		tun.WriteFrame(NewControlFrame(MsgCloseConn, id, port))
		user.Close()
		c.localConns.Delete(id)
	}()

	buf := c.pool.Get()
	defer c.pool.Put(buf)

	idle := time.Duration(c.cfg.Performance.MaxIdle) * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		user.SetReadDeadline(time.Now().Add(idle))
		n, err := user.Read(buf)
		if err != nil {
			if err != io.EOF && !errTimeout(err) && !errClosed(err) {
				log.Printf("[CLIENT] User read (conn=%d): %v", id, err)
			}
			return
		}
		if n == 0 {
			continue
		}

		obf, err := c.obfs.Obfuscate(buf[:n])
		if err != nil {
			return
		}
		enc, err := c.crypto.Encrypt(obf)
		if err != nil {
			return
		}
		if err := tun.WriteFrame(NewDataFrame(id, port, enc)); err != nil {
			return
		}
	}
}

// ─── Tunnel ──────────────────────────────────────────────

func (c *Client) maintainTunnel(ctx context.Context, remote string, tid int) {
	defer c.wg.Done()

	backoff := time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := c.dial(remote)
		if err != nil {
			log.Printf("[CLIENT] T#%d connect: %v (retry %v)", tid, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}

		backoff = time.Second
		log.Printf("[CLIENT] T#%d connected to %s", tid, remote)

		mux := NewMux(conn)
		if err := c.doAuth(mux); err != nil {
			log.Printf("[CLIENT] T#%d auth: %v", tid, err)
			mux.Close()
			continue
		}
		log.Printf("[CLIENT] T#%d authenticated", tid)

		c.tunnelPool.Add(mux)
		c.readTunnel(ctx, mux, tid)
		c.tunnelPool.Remove(mux)
		mux.Close()

		log.Printf("[CLIENT] T#%d lost, reconnecting...", tid)
	}
}

func (c *Client) dial(addr string) (net.Conn, error) {
	switch c.cfg.Tunnel.Protocol {
	case "tcp":
		return NewTCPTransport(c.cfg.Performance.Timeout, c.cfg.Performance.NoDelay).Dial(addr)
	case "kcp":
		return NewKCPTransport(c.cfg.KCP).Dial(addr)
	}
	return nil, fmt.Errorf("bad protocol: %s", c.cfg.Tunnel.Protocol)
}

func (c *Client) doAuth(mux *Mux) error {
	mux.conn.SetDeadline(time.Now().Add(time.Duration(c.cfg.Performance.Timeout) * time.Second))
	defer mux.conn.SetDeadline(time.Time{})

	enc, err := c.crypto.Encrypt(GenerateAuthToken(c.cfg.Tunnel.SecretKey))
	if err != nil {
		return err
	}
	if err := mux.WriteFrame(&Frame{Type: MsgAuth, Payload: enc}); err != nil {
		return err
	}

	f, err := mux.ReadFrame()
	if err != nil {
		return err
	}
	if f.Type == MsgAuthFail {
		return fmt.Errorf("rejected")
	}
	if f.Type != MsgAuthOK {
		return fmt.Errorf("unexpected: 0x%02x", f.Type)
	}

	// Read port map
	pf, err := mux.ReadFrame()
	if err != nil {
		return err
	}
	if pf.Type == MsgPortMap && len(pf.Payload) > 0 {
		if dec, err := c.crypto.Decrypt(pf.Payload); err == nil {
			if ports, err := DecodePortMap(dec); err == nil {
				log.Printf("[CLIENT] Server ports: %v", ports)
			}
		}
	}
	return nil
}

// readTunnel: read responses from server
func (c *Client) readTunnel(ctx context.Context, mux *Mux, tid int) {
	keepCtx, keepCancel := context.WithCancel(ctx)
	defer keepCancel()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		tk := time.NewTicker(time.Duration(c.cfg.Performance.Keepalive) * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-keepCtx.Done():
				return
			case <-tk.C:
				if mux.WriteFrame(NewControlFrame(MsgKeepAlive, 0, 0)) != nil {
					return
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		f, err := mux.ReadFrame()
		if err != nil {
			if err != io.EOF && !errClosed(err) {
				log.Printf("[CLIENT] T#%d read: %v", tid, err)
			}
			return
		}

		switch f.Type {
		case MsgData:
			// Response from Xray → forward to user
			c.forwardToUser(f)

		case MsgCloseConn:
			if v, ok := c.localConns.Load(f.ConnID); ok {
				v.(net.Conn).Close()
				c.localConns.Delete(f.ConnID)
			}

		case MsgKeepAlive:
			// alive
		}
	}
}

// forwardToUser: decrypt server response and send to user
func (c *Client) forwardToUser(f *Frame) {
	dec, err := c.crypto.Decrypt(f.Payload)
	if err != nil {
		return
	}
	data, err := c.obfs.Deobfuscate(dec)
	if err != nil {
		return
	}
	v, ok := c.localConns.Load(f.ConnID)
	if !ok {
		return
	}
	user := v.(net.Conn)
	user.SetWriteDeadline(time.Now().Add(time.Duration(c.cfg.Performance.Timeout) * time.Second))
	if _, err := user.Write(data); err != nil {
		user.Close()
		c.localConns.Delete(f.ConnID)
	}
	user.SetWriteDeadline(time.Time{})
}
