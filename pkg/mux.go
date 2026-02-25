package pkg

import (
	"io"
	"log"
	"net"
	"sync"
)

type Mux struct {
	conn    net.Conn
	writeMu sync.Mutex
	closed  chan struct{}
	once    sync.Once
}

func NewMux(conn net.Conn) *Mux {
	return &Mux{conn: conn, closed: make(chan struct{})}
}

func (m *Mux) WriteFrame(f *Frame) error {
	select {
	case <-m.closed:
		return io.ErrClosedPipe
	default:
	}
	m.writeMu.Lock()
	err := MarshalFrame(m.conn, f)
	m.writeMu.Unlock()
	return err
}

func (m *Mux) ReadFrame() (*Frame, error) {
	select {
	case <-m.closed:
		return nil, io.ErrClosedPipe
	default:
	}
	return UnmarshalFrame(m.conn)
}

func (m *Mux) Close() error {
	var err error
	m.once.Do(func() {
		close(m.closed)
		err = m.conn.Close()
	})
	return err
}

func (m *Mux) IsClosed() bool {
	select {
	case <-m.closed:
		return true
	default:
		return false
	}
}

func (m *Mux) RemoteAddr() net.Addr { return m.conn.RemoteAddr() }

type TunnelPool struct {
	mu      sync.Mutex
	tunnels []*Mux
	idx     int
}

func NewTunnelPool() *TunnelPool {
	return &TunnelPool{tunnels: make([]*Mux, 0, 8)}
}

func (tp *TunnelPool) Add(m *Mux) {
	tp.mu.Lock()
	tp.tunnels = append(tp.tunnels, m)
	total := len(tp.tunnels)
	tp.mu.Unlock()
	log.Printf("[POOL] Tunnel added from %s (total: %d)", m.RemoteAddr(), total)
}

func (tp *TunnelPool) Remove(m *Mux) {
	tp.mu.Lock()
	for i, t := range tp.tunnels {
		if t == m {
			tp.tunnels = append(tp.tunnels[:i], tp.tunnels[i+1:]...)
			break
		}
	}
	if tp.idx >= len(tp.tunnels) && len(tp.tunnels) > 0 {
		tp.idx = 0
	}
	remaining := len(tp.tunnels)
	tp.mu.Unlock()
	log.Printf("[POOL] Tunnel removed (remaining: %d)", remaining)
}

func (tp *TunnelPool) Get() *Mux {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	n := len(tp.tunnels)
	if n == 0 {
		return nil
	}

	// Try from current index, find first alive
	for i := 0; i < n; i++ {
		candidate := tp.tunnels[(tp.idx+i)%n]
		if !candidate.IsClosed() {
			return candidate
		}
	}
	return nil
}

func (tp *TunnelPool) AdvanceIndex() {
	tp.mu.Lock()
	if len(tp.tunnels) > 0 {
		tp.idx = (tp.idx + 1) % len(tp.tunnels)
	}
	tp.mu.Unlock()
}

func (tp *TunnelPool) Count() int {
	tp.mu.Lock()
	n := len(tp.tunnels)
	tp.mu.Unlock()
	return n
}

func (tp *TunnelPool) CloseAll() {
	tp.mu.Lock()
	for _, t := range tp.tunnels {
		t.Close()
	}
	tp.tunnels = tp.tunnels[:0]
	tp.idx = 0
	tp.mu.Unlock()
}
