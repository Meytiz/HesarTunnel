package pkg

import (
	"fmt"
	"net"

	kcp "github.com/xtaci/kcp-go/v5"
)

// KCPTransport handles KCP (UDP-based reliable) connections
type KCPTransport struct {
	cfg KCPConfig
}

// NewKCPTransport creates a new KCP transport
func NewKCPTransport(cfg KCPConfig) *KCPTransport {
	return &KCPTransport{cfg: cfg}
}

// Listen creates a KCP listener on the given address
func (k *KCPTransport) Listen(address string) (net.Listener, error) {
	listener, err := kcp.ListenWithOptions(address, nil, k.cfg.DataShard, k.cfg.ParityShard)
	if err != nil {
		return nil, fmt.Errorf("KCP listen on %s: %w", address, err)
	}
	if k.cfg.DSCP > 0 {
		listener.SetDSCP(k.cfg.DSCP)
	}
	return listener, nil
}

// Dial connects to a KCP address
func (k *KCPTransport) Dial(address string) (net.Conn, error) {
	conn, err := kcp.DialWithOptions(address, nil, k.cfg.DataShard, k.cfg.ParityShard)
	if err != nil {
		return nil, fmt.Errorf("KCP dial %s: %w", address, err)
	}
	k.Optimize(conn)
	return conn, nil
}

// Optimize applies KCP optimizations
func (k *KCPTransport) Optimize(conn net.Conn) {
	kcpConn, ok := conn.(*kcp.UDPSession)
	if !ok {
		return
	}

	switch k.cfg.Preset {
	case "fast3":
		kcpConn.SetNoDelay(1, 10, 2, 1)
	case "fast2":
		kcpConn.SetNoDelay(1, 20, 2, 1)
	case "fast":
		kcpConn.SetNoDelay(1, 30, 2, 1)
	case "normal":
		kcpConn.SetNoDelay(0, 40, 0, 0)
	default:
		kcpConn.SetNoDelay(1, 20, 2, 1)
	}

	kcpConn.SetWindowSize(k.cfg.SndWnd, k.cfg.RcvWnd)
	kcpConn.SetMtu(k.cfg.MTU)
	kcpConn.SetACKNoDelay(true)
	kcpConn.SetStreamMode(true)
}
