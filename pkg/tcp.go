package pkg

import (
	"fmt"
	"net"
	"time"
)

type TCPTransport struct {
	noDelay bool
	timeout time.Duration
}

func NewTCPTransport(timeout int, noDelay bool) *TCPTransport {
	return &TCPTransport{
		noDelay: noDelay,
		timeout: time.Duration(timeout) * time.Second,
	}
}

func (t *TCPTransport) Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP listen %s: %w", addr, err)
	}
	return ln, nil
}

func (t *TCPTransport) Dial(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, t.timeout)
	if err != nil {
		return nil, fmt.Errorf("TCP dial %s: %w", addr, err)
	}
	t.Optimize(conn)
	return conn, nil
}

func (t *TCPTransport) Optimize(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tc.SetNoDelay(t.noDelay)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(30 * time.Second)
	tc.SetReadBuffer(4 * 1024 * 1024)
	tc.SetWriteBuffer(4 * 1024 * 1024)
}
