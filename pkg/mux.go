package pkg

import (
	"io"
	"log"
	"net"
	"sync"
)

// Mux provides thread-safe multiplexed read/write over a single connection
// This prevents race conditions when multiple goroutines write to the same tunnel
type Mux struct {
	conn    net.Conn
	writeMu sync.Mutex // serializes writes
	readMu  sync.Mutex // serializes reads (usually only one reader)
	closed  chan struct{}
	once    sync.Once
}

// NewMux creates a new multiplexer over a connection
func NewMux(conn net.Conn) *Mux {
	return &Mux{
		conn:   conn,
		closed: make(chan struct{}),
	}
}

// WriteFrame writes a frame in a thread-safe manner
func (m *Mux) WriteFrame(f *Frame) error {
	select {
	case <-m.closed:
		return io.ErrClosedPipe
	default:
	}

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	return MarshalFrame(m.conn, f)
}

// ReadFrame reads a frame in a thread-safe manner
func (m *Mux) ReadFrame() (*Frame, error) {
	select {
	case <-m.closed:
		return nil, io.ErrClosedPipe
	default:
	}

	m.readMu.Lock()
	defer m.readMu.Unlock()

	return UnmarshalFrame(m.conn)
}

// Close closes the multiplexer and underlying connection
func (m *Mux) Close() error {
	var err error
	m.once.Do(func() {
		close(m.closed)
		err = m.conn.Close()
	})
	return err
}

// IsClosed returns true if the mux is closed
func (m *Mux) IsClosed() bool {
	select {
	case <-m.closed:
		return true
	default:
		return false
	}
}

// RemoteAddr returns the remote address
func (m *Mux) RemoteAddr() net.Addr {
	return m.conn.RemoteAddr()
}

// LocalAddr returns the local address
func (m *Mux) LocalAddr() net.Addr {
	return m.conn.LocalAddr()
}

// TunnelPool manages a pool of tunnel multiplexers with round-robin selection
type TunnelPool struct {
	mu      sync.RWMutex
	tunnels []*Mux
	index   int
}

// NewTunnelPool creates a new tunnel pool
func NewTunnelPool() *TunnelPool {
	return &TunnelPool{
		tunnels: make([]*Mux, 0, 8),
	}
}

// Add adds a tunnel to the pool
func (tp *TunnelPool) Add(m *Mux) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.tunnels = append(tp.tunnels, m)
	log.Printf("[POOL] Tunnel added from %s (total: %d)", m.RemoteAddr(), len(tp.tunnels))
}

// Remove removes a tunnel from the pool
func (tp *TunnelPool) Remove(m *Mux) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	for i, t := range tp.tunnels {
		if t == m {
			tp.tunnels = append(tp.tunnels[:i], tp.tunnels[i+1:]...)
			if tp.index >= len(tp.tunnels) && len(tp.tunnels) > 0 {
				tp.index = 0
			}
			log.Printf("[POOL] Tunnel removed (remaining: %d)", len(tp.tunnels))
			return
		}
	}
}

// Get returns the next tunnel using round-robin
// Returns nil if no tunnels available
func (tp *TunnelPool) Get() *Mux {
	tp.mu.RLock()
	defer tp.mu.RUnlock()

	n := len(tp.tunnels)
	if n == 0 {
		return nil
	}

	// Round-robin selection
	m := tp.tunnels[tp.index%n]

	// Check if alive
	if m.IsClosed() {
		// Try next ones
		for i := 1; i < n; i++ {
			candidate := tp.tunnels[(tp.index+i)%n]
			if !candidate.IsClosed() {
				tp.mu.RUnlock()
				tp.mu.Lock()
				tp.index = (tp.index + i + 1) % n
				tp.mu.Unlock()
				tp.mu.RLock()
				return candidate
			}
		}
		return nil // all closed
	}

	// Advance index (need write lock, but avoid deadlock)
	// We'll just accept slight inaccuracy in round-robin for read performance
	return m
}

// AdvanceIndex advances the round-robin index (call after Get)
func (tp *TunnelPool) AdvanceIndex() {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if len(tp.tunnels) > 0 {
		tp.index = (tp.index + 1) % len(tp.tunnels)
	}
}

// Count returns number of active tunnels
func (tp *TunnelPool) Count() int {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return len(tp.tunnels)
}

// CloseAll closes all tunnels in the pool
func (tp *TunnelPool) CloseAll() {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	for _, t := range tp.tunnels {
		t.Close()
	}
	tp.tunnels = tp.tunnels[:0]
	tp.index = 0
	log.Printf("[POOL] All tunnels closed")
}
