package pkg

import (
	"fmt"
	"net"

	kcp "github.com/xtaci/kcp-go/v5"
)

type KCPTransport struct {
	cfg KCPConfig
}

func NewKCPTransport(cfg KCPConfig) *KCPTransport {
	return &KCPTransport{cfg: cfg}
}

func (k *KCPTransport) Listen(addr string) (net.Listener, error) {
	ln, err := kcp.ListenWithOptions(addr, nil, k.cfg.DataShard, k.cfg.ParityShard)
	if err != nil {
		return nil, fmt.Errorf("KCP listen %s: %w", addr, err)
	}
	if k.cfg.DSCP > 0 {
		ln.SetDSCP(k.cfg.DSCP)
	}
	return ln, nil
}

func (k *KCPTransport) Dial(addr string) (net.Conn, error) {
	conn, err := kcp.DialWithOptions(addr, nil, k.cfg.DataShard, k.cfg.ParityShard)
	if err != nil {
		return nil, fmt.Errorf("KCP dial %s: %w", addr, err)
	}
	k.Optimize(conn)
	return conn, nil
}

func (k *KCPTransport) Optimize(conn net.Conn) {
	kc, ok := conn.(*kcp.UDPSession)
	if !ok {
		return
	}
	switch k.cfg.Preset {
	case "fast3":
		kc.SetNoDelay(1, 10, 2, 1)
	case "fast2":
		kc.SetNoDelay(1, 20, 2, 1)
	case "fast":
		kc.SetNoDelay(1, 30, 2, 1)
	default:
		kc.SetNoDelay(0, 40, 0, 0)
	}
	kc.SetWindowSize(k.cfg.SndWnd, k.cfg.RcvWnd)
	kc.SetMtu(k.cfg.MTU)
	kc.SetACKNoDelay(true)
	kc.SetStreamMode(true)
}
