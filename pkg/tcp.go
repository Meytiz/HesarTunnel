package pkg

import (
	"fmt"
	"net"
	"time"
)

// TCPTransport handles TCP connections with optimizations
type TCPTransport struct {
	noDelay bool
	timeout time.Duration
}

// NewTCPTransport creates a new TCP transport
func NewTCPTransport(timeout int, noDelay bool) *TCPTransport {
	return &TCPTransport{
		noDelay: noDelay,
		timeout: time.Duration(timeout) * time.Second,
	}
}

// Listen creates a TCP listener on the given address
func (t *TCPTransport) Listen(address string) (net.Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("TCP listen on %s: %w", address, err)
	}
	return listener, nil
}

// Dial connects to a TCP address with timeout
func (t *TCPTransport) Dial(address string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", address, t.timeout)
	if err != nil {
		return nil, fmt.Errorf("TCP dial %s: %w", address, err)
	}
	t.Optimize(conn)
	return conn, nil
}

// Optimize applies TCP optimizations to a connection
func (t *TCPTransport) Optimize(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tcpConn.SetNoDelay(t.noDelay)
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)

	// Increase socket buffers for high throughput
	tcpConn.SetReadBuffer(4 * 1024 * 1024)  // 4MB
	tcpConn.SetWriteBuffer(4 * 1024 * 1024) // 4MB
}
