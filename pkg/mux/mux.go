package mux

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"hesartunnel/pkg/crypto"
	"hesartunnel/pkg/pool"
)

// Multiplexer runs multiple logical streams over a single encrypted connection.
// This is critical for efficiency: one TCP connection, many tunneled ports.
//
// Frame format (after encryption):
//   [StreamID:4][Flags:1][Length:2][Payload:N]
//
// Flags:
//   0x01 = SYN  (new stream)
//   0x02 = FIN  (close stream)
//   0x04 = DATA (payload)
//   0x08 = PING (keepalive)
//   0x10 = PONG (keepalive response)

const (
	FlagSYN  byte = 0x01
	FlagFIN  byte = 0x02
	FlagDATA byte = 0x04
	FlagPING byte = 0x08
	FlagPONG byte = 0x10

	FrameHeaderSize = 7
	MaxPayloadSize  = 16384
	StreamBufferSize = 65536
)

type Mux struct {
	conn      net.Conn
	cipher    *crypto.CipherSuite
	streams   map[uint32]*Stream
	streamsMu sync.RWMutex
	nextID    atomic.Uint32
	acceptCh  chan *Stream
	closeCh   chan struct{}
	closeOnce sync.Once
	bufPool   *pool.BufferPool
	isServer  bool
}

type Stream struct {
	id       uint32
	mux      *Mux
	readBuf  chan []byte
	closed   atomic.Bool
}

func NewMux(conn net.Conn, cipher *crypto.CipherSuite, isServer bool) *Mux {
	m := &Mux{
		conn:     conn,
		cipher:   cipher,
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream, 256),
		closeCh:  make(chan struct{}),
		bufPool:  pool.NewBufferPool(32768),
		isServer: isServer,
	}

	// Server uses even IDs, client uses odd IDs
	if isServer {
		m.nextID.Store(0)
	} else {
		m.nextID.Store(1)
	}

	go m.readLoop()
	return m
}

// OpenStream creates a new multiplexed stream.
func (m *Mux) OpenStream() (*Stream, error) {
	select {
	case <-m.closeCh:
		return nil, fmt.Errorf("mux closed")
	default:
	}

	id := m.nextID.Add(2) - 2
	s := &Stream{
		id:      id,
		mux:     m,
		readBuf: make(chan []byte, 64),
	}

	m.streamsMu.Lock()
	m.streams[id] = s
	m.streamsMu.Unlock()

	// Send SYN frame
	if err := m.writeFrame(id, FlagSYN, nil); err != nil {
		return nil, err
	}

	return s, nil
}

// AcceptStream waits for incoming streams (server side).
func (m *Mux) AcceptStream() (*Stream, error) {
	select {
	case s := <-m.acceptCh:
		return s, nil
	case <-m.closeCh:
		return nil, fmt.Errorf("mux closed")
	}
}

func (m *Mux) readLoop() {
	defer m.Close()

	for {
		// Read encrypted frame
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(m.conn, lenBuf); err != nil {
			return
		}
		encLen := binary.BigEndian.Uint32(lenBuf)
		if encLen > MaxPayloadSize+1024 {
			return // invalid frame
		}

		encData := make([]byte, encLen)
		if _, err := io.ReadFull(m.conn, encData); err != nil {
			return
		}

		// Decrypt
		frame, err := m.cipher.Decrypt(encData, nil)
		if err != nil {
			return // tampered data
		}

		if len(frame) < FrameHeaderSize {
			continue
		}

		// Parse frame header
		streamID := binary.BigEndian.Uint32(frame[:4])
		flags := frame[4]
		payloadLen := binary.BigEndian.Uint16(frame[5:7])
		payload := frame[7 : 7+payloadLen]

		m.handleFrame(streamID, flags, payload)
	}
}

func (m *Mux) handleFrame(streamID uint32, flags byte, payload []byte) {
	switch {
	case flags&FlagPING != 0:
		_ = m.writeFrame(streamID, FlagPONG, nil)
		return
	case flags&FlagPONG != 0:
		return // keepalive response
	}

	m.streamsMu.RLock()
	s, exists := m.streams[streamID]
	m.streamsMu.RUnlock()

	if flags&FlagSYN != 0 && !exists {
		s = &Stream{
			id:      streamID,
			mux:     m,
			readBuf: make(chan []byte, 64),
		}
		m.streamsMu.Lock()
		m.streams[streamID] = s
		m.streamsMu.Unlock()

		select {
		case m.acceptCh <- s:
		default:
			// Accept queue full, drop
		}
		return
	}

	if s == nil {
		return
	}

	if flags&FlagDATA != 0 && len(payload) > 0 {
		data := make([]byte, len(payload))
		copy(data, payload)
		select {
		case s.readBuf <- data:
		default:
			// Buffer full, apply backpressure
		}
	}

	if flags&FlagFIN != 0 {
		s.closed.Store(true)
		close(s.readBuf)
		m.streamsMu.Lock()
		delete(m.streams, streamID)
		m.streamsMu.Unlock()
	}
}

func (m *Mux) writeFrame(streamID uint32, flags byte, payload []byte) error {
	frame := make([]byte, FrameHeaderSize+len(payload))
	binary.BigEndian.PutUint32(frame[:4], streamID)
	frame[4] = flags
	binary.BigEndian.PutUint16(frame[5:7], uint16(len(payload)))
	if len(payload) > 0 {
		copy(frame[7:], payload)
	}

	// Encrypt the frame
	encrypted, err := m.cipher.Encrypt(frame, nil)
	if err != nil {
		return err
	}

	// Write length-prefixed encrypted frame
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))

	_, err = m.conn.Write(append(lenBuf, encrypted...))
	return err
}

// SendPing sends keepalive ping.
func (m *Mux) SendPing() error {
	return m.writeFrame(0, FlagPING, nil)
}

func (m *Mux) Close() error {
	m.closeOnce.Do(func() {
		close(m.closeCh)
		m.conn.Close()
	})
	return nil
}

// Stream implements net.Conn-like interface.
func (s *Stream) Read(buf []byte) (int, error) {
	data, ok := <-s.readBuf
	if !ok {
		return 0, io.EOF
	}
	n := copy(buf, data)
	return n, nil
}

func (s *Stream) Write(data []byte) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("stream closed")
	}
	totalWritten := 0
	for len(data) > 0 {
		chunkSize := MaxPayloadSize
		if chunkSize > len(data) {
			chunkSize = len(data)
		}
		if err := s.mux.writeFrame(s.id, FlagDATA, data[:chunkSize]); err != nil {
			return totalWritten, err
		}
		data = data[chunkSize:]
		totalWritten += chunkSize
	}
	return totalWritten, nil
}

func (s *Stream) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.mux.writeFrame(s.id, FlagFIN, nil)
}

func (s *Stream) LocalAddr() net.Addr  { return s.mux.conn.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.mux.conn.RemoteAddr() }
func (s *Stream) SetDeadline(t time.Time) error      { return nil }
func (s *Stream) SetReadDeadline(t time.Time) error   { return nil }
func (s *Stream) SetWriteDeadline(t time.Time) error  { return nil }
