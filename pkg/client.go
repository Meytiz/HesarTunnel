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

type Client struct {
	cfg        *Config
	crypto     *CryptoEngine
	obfs       *Obfuscator
	pool       *BufferPool
	idGen      *ConnIDGenerator
	ports      []int
	tunnelPool *TunnelPool
	localConns *ConnMap
	listeners  []net.Listener
	lmu        sync.Mutex
	wg         sync.WaitGroup
}

func NewClient(cfg *Config) (*Client, error) {
	cr, err := NewCryptoEngine(cfg.Crypto.Method, cfg.Tunnel.SecretKey)
	if err != nil {
		return nil, err
	}
	ports, err := ParsePorts(cfg.Tunnel.ConfigPorts)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg: cfg, crypto: cr,
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
	log.Printf("[CLIENT] Server: %s (%s)", remote, c.cfg.Tunnel.Protocol)
	log.Printf("[CLIENT] Listen: %s, ports: %v", c.cfg.Tunnel.ClientForward, c.ports)

	for _, port := range c.ports {
		addr := fmt.Sprintf("%s:%d", c.cfg.Tunnel.ClientForward, port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[CLIENT] WARN: listen %s: %v", addr, err)
			continue
		}
		c.lmu.Lock()
		c.listeners = append(c.listeners, ln)
		c.lmu.Unlock()
		log.Printf("[CLIENT] Listening %s", addr)
		c.wg.Add(1)
		go c.acceptUsers(ctx, ln, port)
	}

	for i := 0; i < c.cfg.Performance.TunnelCount; i++ {
		c.wg.Add(1)
		go c.maintain(ctx, remote, i)
	}
	<-ctx.Done()
	return nil
}

func (c *Client) Shutdown(ctx context.Context) {
	c.lmu.Lock()
	for _, ln := range c.listeners {
		ln.Close()
	}
	c.listeners = nil
	c.lmu.Unlock()
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
}

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
				if isClosed(err) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		opt.Optimize(conn)
		tun := c.tunnelPool.Get()
		if tun == nil {
			conn.Close()
			continue
		}
		c.tunnelPool.AdvanceIndex()
		id := c.idGen.Next()
		c.localConns.Store(id, conn)
		if tun.WriteFrame(NewControlFrame(MsgNewConn, id, uint16(port))) != nil {
			conn.Close()
			c.localConns.Delete(id)
			continue
		}
		c.wg.Add(1)
		go c.fwdUserToTunnel(ctx, conn, tun, uint16(port), id)
	}
}

func (c *Client) fwdUserToTunnel(ctx context.Context, user net.Conn, tun *Mux, port uint16, id uint32) {
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
			if err != io.EOF && !isTimeout(err) && !isClosed(err) {
				log.Printf("[CLIENT] User read c=%d: %v", id, err)
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
		if tun.WriteFrame(NewDataFrame(id, port, enc)) != nil {
			return
		}
	}
}

func (c *Client) maintain(ctx context.Context, remote string, tid int) {
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
			log.Printf("[CLIENT] T#%d: %v (retry %v)", tid, err, backoff)
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
		log.Printf("[CLIENT] T#%d connected", tid)
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
		log.Printf("[CLIENT] T#%d lost", tid)
	}
}

func (c *Client) dial(addr string) (net.Conn, error) {
	if c.cfg.Tunnel.Protocol == "kcp" {
		return NewKCPTransport(c.cfg.KCP).Dial(addr)
	}
	return NewTCPTransport(c.cfg.Performance.Timeout, c.cfg.Performance.NoDelay).Dial(addr)
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

func (c *Client) readTunnel(ctx context.Context, mux *Mux, tid int) {
	kctx, kcancel := context.WithCancel(ctx)
	defer kcancel()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		tk := time.NewTicker(time.Duration(c.cfg.Performance.Keepalive) * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-kctx.Done():
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
			if err != io.EOF && !isClosed(err) {
				log.Printf("[CLIENT] T#%d read: %v", tid, err)
			}
			return
		}
		switch f.Type {
		case MsgData:
			c.fwdToUser(f)
		case MsgCloseConn:
			if v, ok := c.localConns.Load(f.ConnID); ok {
				v.(net.Conn).Close()
				c.localConns.Delete(f.ConnID)
			}
		case MsgKeepAlive:
		}
	}
}

func (c *Client) fwdToUser(f *Frame) {
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
	u := v.(net.Conn)
	u.SetWriteDeadline(time.Now().Add(time.Duration(c.cfg.Performance.Timeout) * time.Second))
	if _, err := u.Write(data); err != nil {
		u.Close()
		c.localConns.Delete(f.ConnID)
	}
	u.SetWriteDeadline(time.Time{})
}
