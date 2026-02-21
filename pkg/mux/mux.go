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
// Wire format (before encryption):
//   [StreamID:4][Flags:1][Length:2][Payload:N]
//
// On the wire (after encryption):
//   [EncLen:4][Nonce:24][Encrypted(frame)+Tag:16]
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

	FrameHeaderSize  = 7     // 4 (streamID) + 1 (flags) + 2 (length)
	MaxPayloadSize   = 16384
)

type Mux struct {
	conn      net.Conn
	cipher    *crypto.CipherSuite
	streams   map[uint32]*Stream
	streamsMu sync.RWMutex
	writeMu   sync.Mutex        // protects concurrent conn.Write calls
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
	residual []byte         // leftover from partial reads
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
		m.streamsMu.Lock()
		delete(m.streams, id)
		m.streamsMu.Unlock()
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
		// Read 4-byte encrypted frame length prefix
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(m.conn, lenBuf); err != nil {
			return
		}
		encLen := binary.BigEndian.Uint32(lenBuf)
		if encLen == 0 || encLen > MaxPayloadSize+1024 {
			return // invalid frame size
		}

		// Read encrypted frame data
		encData := make([]byte, encLen)
		if _, err := io.ReadFull(m.conn, encData); err != nil {
			return
		}

		// Decrypt
		frame, err := m.cipher.Decrypt(encData, nil)
		if err != nil {
			return // tampered or wrong key
		}

		if len(frame) < FrameHeaderSize {
			continue // malformed frame, skip
		}

		// Parse frame header
		streamID := binary.BigEndian.Uint32(frame[:4])
		flags := frame[4]
		payloadLen := int(binary.BigEndian.Uint16(frame[5:7]))

		// BOUNDS CHECK: ensure payloadLen doesn't exceed frame
		if payloadLen > len(frame)-FrameHeaderSize {
			continue // corrupted payloadLen, skip
		}

		payload := frame[FrameHeaderSize : FrameHeaderSize+payloadLen]
		m.handleFrame(streamID, flags, payload)
	}
}

func (m *Mux) handleFrame(streamID uint32, flags byte, payload []byte) {
	// Handle keepalive first (no stream needed)
	switch {
	case flags&FlagPING != 0:
		_ = m.writeFrame(streamID, FlagPONG, nil)
		return
	case flags&FlagPONG != 0:
		return // keepalive response, nothing to do
	}

	m.streamsMu.RLock()
	s, exists := m.streams[streamID]
	m.streamsMu.RUnlock()

	// Handle SYN: create new stream
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
			// Accept queue full, reject stream
			_ = m.writeFrame(streamID, FlagFIN, nil)
			m.streamsMu.Lock()
			delete(m.streams, streamID)
			m.streamsMu.Unlock()
		}
		return
	}

	if s == nil {
		return // unknown stream
	}

	// Handle DATA
	if flags&FlagDATA != 0 && len(payload) > 0 {
		data := make([]byte, len(payload))
		copy(data, payload)
		select {
		case s.readBuf <- data:
		default:
			// Buffer full — this applies backpressure
		}
	}

	// Handle FIN
	if flags&FlagFIN != 0 {
		s.closed.Store(true)
		close(s.readBuf)
		m.streamsMu.Lock()
		delete(m.streams, streamID)
		m.streamsMu.Unlock()
	}
}

// writeFrame builds, encrypts, and sends a mux frame.
// Thread-safe: uses writeMu to prevent interleaved writes.
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

	// Build wire message: [4-byte length][encrypted data]
	wireMsg := make([]byte, 4+len(encrypted))
	binary.BigEndian.PutUint32(wireMsg[:4], uint32(len(encrypted)))
	copy(wireMsg[4:], encrypted)

	// Write atomically under mutex to prevent interleaving
	m.writeMu.Lock()
	_, err = m.conn.Write(wireMsg)
	m.writeMu.Unlock()
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

// ──────────────────────────────────────────────
// Stream implements io.ReadWriteCloser + net.Conn
// ──────────────────────────────────────────────

// Read reads data from the stream.
// Uses a residual buffer to handle cases where the incoming data chunk
// is larger than the caller's buffer, preventing data loss.
func (s *Stream) Read(buf []byte) (int, error) {
	// Serve from residual first
	if len(s.residual) > 0 {
		n := copy(buf, s.residual)
		if n < len(s.residual) {
			s.residual = s.residual[n:]
		} else {
			s.residual = nil
		}
		return n, nil
	}

	// Wait for next data chunk from channel
	data, ok := <-s.readBuf
	if !ok {
		return 0, io.EOF
	}

	n := copy(buf, data)
	if n < len(data) {
		// Store remainder for next Read call
		s.residual = make([]byte, len(data)-n)
		copy(s.residual, data[n:])
	}
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
		return nil // already closed
	}
	return s.mux.writeFrame(s.id, FlagFIN, nil)
}

// net.Conn interface compliance
func (s *Stream) LocalAddr() net.Addr                { return s.mux.conn.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr               { return s.mux.conn.RemoteAddr() }
func (s *Stream) SetDeadline(t time.Time) error      { return nil }
func (s *Stream) SetReadDeadline(t time.Time) error  { return nil }
func (s *Stream) SetWriteDeadline(t time.Time) error { return nil }
