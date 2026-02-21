package obfuscation

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

// Anti-DPI Strategy:
// 1. TLS 1.3 Record Layer mimicry (content type 0x17 = Application Data)
// 2. Random padding to defeat length-based fingerprinting
// 3. ClientHello fragmentation to bypass SNI-based blocking
// 4. Timing jitter to prevent timing analysis
// 5. Fake HTTP/2 ALPN negotiation
// 6. Variable record sizes mimicking real HTTPS traffic

const (
	TLSApplicationData = 0x17
	TLSVersion12       = 0x0303 // TLS 1.2 record version (used by TLS 1.3)
	MaxTLSRecordSize   = 16384
	MinPadding         = 0
	MaxPadding         = 255
)

// ObfuscatedConn wraps a net.Conn with anti-DPI obfuscation.
type ObfuscatedConn struct {
	net.Conn
	paddingMin   int
	paddingMax   int
	fragmentMin  int
	fragmentMax  int
	sni          string
	handshakeDone bool
}

type Config struct {
	PaddingRange  [2]int
	FragmentRange [2]int
	SNI           string
}

func WrapConn(conn net.Conn, cfg Config) *ObfuscatedConn {
	return &ObfuscatedConn{
		Conn:        conn,
		paddingMin:  cfg.PaddingRange[0],
		paddingMax:  cfg.PaddingRange[1],
		fragmentMin: cfg.FragmentRange[0],
		fragmentMax: cfg.FragmentRange[1],
		sni:         cfg.SNI,
	}
}

// Write wraps data in TLS 1.3 Application Data records with padding.
// Each write produces a record that looks like legitimate HTTPS traffic.
// Format: [0x17][0x03 0x03][length:2][payload][random_padding]
func (oc *ObfuscatedConn) Write(data []byte) (int, error) {
	totalWritten := 0
	remaining := data

	for len(remaining) > 0 {
		// Determine fragment size (randomized to defeat analysis)
		fragSize := oc.randomInt(1024, 8192)
		if fragSize > len(remaining) {
			fragSize = len(remaining)
		}

		fragment := remaining[:fragSize]
		remaining = remaining[fragSize:]

		// Generate random padding
		padLen := oc.randomInt(oc.paddingMin, oc.paddingMax)
		padding := make([]byte, padLen)
		rand.Read(padding)

		// Build TLS record
		recordLen := len(fragment) + padLen + 1 // +1 for padding length byte
		if recordLen > MaxTLSRecordSize {
			recordLen = MaxTLSRecordSize
		}

		var buf bytes.Buffer
		buf.WriteByte(TLSApplicationData)         // Content type
		binary.Write(&buf, binary.BigEndian, uint16(TLSVersion12)) // Version
		binary.Write(&buf, binary.BigEndian, uint16(recordLen))     // Length
		buf.Write(fragment)
		buf.Write(padding)
		buf.WriteByte(byte(padLen)) // Padding length indicator

		// Apply random fragmentation at TCP level
		if err := oc.fragmentedWrite(buf.Bytes()); err != nil {
			return totalWritten, err
		}
		totalWritten += fragSize
	}

	return totalWritten, nil
}

// Read unwraps TLS records and strips padding.
func (oc *ObfuscatedConn) Read(buf []byte) (int, error) {
	// Read TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(oc.Conn, header); err != nil {
		return 0, err
	}

	// Validate record type
	if header[0] != TLSApplicationData {
		return 0, fmt.Errorf("invalid record type: 0x%02x", header[0])
	}

	// Read record payload
	recordLen := binary.BigEndian.Uint16(header[3:5])
	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(oc.Conn, payload); err != nil {
		return 0, err
	}

	// Strip padding (last byte indicates padding length)
	padLen := int(payload[len(payload)-1])
	dataEnd := len(payload) - padLen - 1
	if dataEnd < 0 || dataEnd > len(buf) {
		return 0, fmt.Errorf("invalid padding length")
	}

	copy(buf, payload[:dataEnd])
	return dataEnd, nil
}

// fragmentedWrite splits TCP writes to defeat DPI reassembly.
func (oc *ObfuscatedConn) fragmentedWrite(data []byte) error {
	numFragments := oc.randomInt(oc.fragmentMin, oc.fragmentMax)
	if numFragments <= 1 || len(data) < 10 {
		_, err := oc.Conn.Write(data)
		return err
	}

	remaining := data
	for i := 0; i < numFragments && len(remaining) > 0; i++ {
		var fragSize int
		if i == numFragments-1 {
			fragSize = len(remaining)
		} else {
			fragSize = oc.randomInt(1, len(remaining)/2+1)
		}

		if _, err := oc.Conn.Write(remaining[:fragSize]); err != nil {
			return err
		}
		remaining = remaining[fragSize:]

		// Timing jitter between fragments (0-2ms)
		jitter := oc.randomInt(0, 2000)
		time.Sleep(time.Duration(jitter) * time.Microsecond)
	}
	return nil
}

// FakeClientHello sends a TLS ClientHello with specified SNI.
// This makes the initial connection look like legitimate HTTPS.
func (oc *ObfuscatedConn) FakeClientHello() error {
	hello := buildClientHello(oc.sni)
	// Fragment the ClientHello to bypass SNI detection
	return oc.fragmentedWrite(hello)
}

func buildClientHello(sni string) []byte {
	// Minimal TLS 1.3 ClientHello with:
	// - Random session ID
	// - Modern cipher suites (TLS_AES_128_GCM_SHA256, etc.)
	// - SNI extension with provided domain
	// - Supported versions extension (TLS 1.3)
	// - Key share extension (X25519)
	var buf bytes.Buffer

	// Record header
	buf.WriteByte(0x16) // Handshake
	binary.Write(&buf, binary.BigEndian, uint16(0x0301)) // TLS 1.0 for compat

	// We'll fill length later
	lenPos := buf.Len()
	buf.Write([]byte{0x00, 0x00}) // placeholder

	// Handshake header
	buf.WriteByte(0x01) // ClientHello
	hsLenPos := buf.Len()
	buf.Write([]byte{0x00, 0x00, 0x00}) // placeholder

	// Client version (TLS 1.2)
	binary.Write(&buf, binary.BigEndian, uint16(0x0303))

	// Random (32 bytes)
	random := make([]byte, 32)
	rand.Read(random)
	buf.Write(random)

	// Session ID (32 bytes)
	buf.WriteByte(32)
	sessID := make([]byte, 32)
	rand.Read(sessID)
	buf.Write(sessID)

	// Cipher suites
	cipherSuites := []uint16{
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	}
	binary.Write(&buf, binary.BigEndian, uint16(len(cipherSuites)*2))
	for _, cs := range cipherSuites {
		binary.Write(&buf, binary.BigEndian, cs)
	}

	// Compression methods
	buf.WriteByte(1)
	buf.WriteByte(0)

	// Extensions
	var extBuf bytes.Buffer

	// SNI extension
	sniBytes := []byte(sni)
	extBuf.Write([]byte{0x00, 0x00}) // SNI type
	sniListLen := len(sniBytes) + 5
	binary.Write(&extBuf, binary.BigEndian, uint16(sniListLen))
	binary.Write(&extBuf, binary.BigEndian, uint16(sniListLen-2))
	extBuf.WriteByte(0x00) // Host name type
	binary.Write(&extBuf, binary.BigEndian, uint16(len(sniBytes)))
	extBuf.Write(sniBytes)

	// Supported Versions extension (TLS 1.3)
	extBuf.Write([]byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04})

	// Key Share extension (X25519)
	keyShare := make([]byte, 32)
	rand.Read(keyShare)
	extBuf.Write([]byte{0x00, 0x33})
	binary.Write(&extBuf, binary.BigEndian, uint16(len(keyShare)+6))
	binary.Write(&extBuf, binary.BigEndian, uint16(len(keyShare)+4))
	binary.Write(&extBuf, binary.BigEndian, uint16(0x001d)) // X25519
	binary.Write(&extBuf, binary.BigEndian, uint16(len(keyShare)))
	extBuf.Write(keyShare)

	// Write extensions length + data
	binary.Write(&buf, binary.BigEndian, uint16(extBuf.Len()))
	buf.Write(extBuf.Bytes())

	// Fix lengths
	result := buf.Bytes()
	hsLen := len(result) - hsLenPos - 3
	result[hsLenPos] = byte(hsLen >> 16)
	result[hsLenPos+1] = byte(hsLen >> 8)
	result[hsLenPos+2] = byte(hsLen)

	recordLen := len(result) - lenPos - 2
	binary.BigEndian.PutUint16(result[lenPos:], uint16(recordLen))

	return result
}

func (oc *ObfuscatedConn) randomInt(min, max int) int {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return int(n.Int64()) + min
}
