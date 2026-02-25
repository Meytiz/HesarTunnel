package pkg

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

// Obfuscator applies traffic obfuscation to resist DPI
type Obfuscator struct {
	mode    string
	enabled bool
}

// NewObfuscator creates a new obfuscator
func NewObfuscator(mode string, enabled bool) *Obfuscator {
	return &Obfuscator{
		mode:    mode,
		enabled: enabled,
	}
}

// Obfuscate wraps data to disguise traffic pattern
func (o *Obfuscator) Obfuscate(data []byte) ([]byte, error) {
	if !o.enabled || len(data) == 0 {
		return data, nil
	}

	switch o.mode {
	case "tls-hello":
		return o.wrapTLS(data)
	case "http":
		return o.wrapHTTP(data)
	case "random-padding":
		return o.wrapPadding(data)
	default:
		return data, nil
	}
}

// Deobfuscate unwraps obfuscated data
func (o *Obfuscator) Deobfuscate(data []byte) ([]byte, error) {
	if !o.enabled || len(data) == 0 {
		return data, nil
	}

	switch o.mode {
	case "tls-hello":
		return o.unwrapTLS(data)
	case "http":
		return o.unwrapHTTP(data)
	case "random-padding":
		return o.unwrapPadding(data)
	default:
		return data, nil
	}
}

// ─── TLS 1.3 Record Obfuscation ─────────────────────────
// Wraps data as TLS Application Data records
// This is simpler and more reliable than faking ClientHello
// DPI sees standard TLS 1.2/1.3 record layer

func (o *Obfuscator) wrapTLS(data []byte) ([]byte, error) {
	// TLS Application Data Record:
	// [ContentType:1][Version:2][Length:2][Fragment:N]
	//
	// Content Type 0x17 = Application Data
	// Version 0x0303 = TLS 1.2 (used even in TLS 1.3 record layer)
	// Length = len(data)

	dataLen := len(data)
	if dataLen > 16384 { // TLS max record size
		// Split into multiple records
		var buf bytes.Buffer
		for offset := 0; offset < dataLen; {
			chunkSize := dataLen - offset
			if chunkSize > 16384 {
				chunkSize = 16384
			}

			buf.WriteByte(0x17) // Application Data
			buf.Write([]byte{0x03, 0x03})
			lenBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBytes, uint16(chunkSize))
			buf.Write(lenBytes)
			buf.Write(data[offset : offset+chunkSize])

			offset += chunkSize
		}
		return buf.Bytes(), nil
	}

	buf := make([]byte, 5+dataLen)
	buf[0] = 0x17 // Application Data
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], uint16(dataLen))
	copy(buf[5:], data)

	return buf, nil
}

func (o *Obfuscator) unwrapTLS(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("TLS record too short: %d bytes", len(data))
	}

	// Can have multiple records concatenated
	var result bytes.Buffer
	offset := 0

	for offset < len(data) {
		if len(data)-offset < 5 {
			return nil, fmt.Errorf("incomplete TLS record header at offset %d", offset)
		}

		contentType := data[offset]
		if contentType != 0x17 {
			return nil, fmt.Errorf("unexpected TLS content type: 0x%02x at offset %d", contentType, offset)
		}

		// Skip version check (we accept any 0x03,0x0X)
		recordLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))

		if offset+5+recordLen > len(data) {
			return nil, fmt.Errorf("TLS record length exceeds data: need %d, have %d", offset+5+recordLen, len(data))
		}

		result.Write(data[offset+5 : offset+5+recordLen])
		offset += 5 + recordLen
	}

	return result.Bytes(), nil
}

// ─── HTTP Obfuscation ────────────────────────────────────
// Wraps data in HTTP response format (simpler parsing)

func (o *Obfuscator) wrapHTTP(data []byte) ([]byte, error) {
	// Use fixed-length header for reliable parsing
	// Format: "HTTP/1.1 200 OK\r\nContent-Length: XXXXX\r\n\r\n" + data
	header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %05d\r\nConnection: keep-alive\r\n\r\n", len(data))

	buf := make([]byte, len(header)+len(data))
	copy(buf, header)
	copy(buf[len(header):], data)

	return buf, nil
}

func (o *Obfuscator) unwrapHTTP(data []byte) ([]byte, error) {
	// Find the double CRLF that ends HTTP headers
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx == -1 {
		return nil, fmt.Errorf("HTTP header terminator not found")
	}
	return data[idx+4:], nil
}

// ─── Random Padding Obfuscation ──────────────────────────
// Format: [PaddingLen:2][Padding:N][DataLen:4][Data:M]

func (o *Obfuscator) wrapPadding(data []byte) ([]byte, error) {
	// Random padding between 16 and 128 bytes
	paddingBig, err := rand.Int(rand.Reader, big.NewInt(113))
	if err != nil {
		return nil, fmt.Errorf("random generation failed: %w", err)
	}
	paddingLen := int(paddingBig.Int64()) + 16

	totalLen := 2 + paddingLen + 4 + len(data)
	buf := make([]byte, totalLen)

	// Padding length
	binary.BigEndian.PutUint16(buf[0:2], uint16(paddingLen))

	// Random padding
	rand.Read(buf[2 : 2+paddingLen])

	// Data length
	binary.BigEndian.PutUint32(buf[2+paddingLen:6+paddingLen], uint32(len(data)))

	// Data
	copy(buf[6+paddingLen:], data)

	return buf, nil
}

func (o *Obfuscator) unwrapPadding(data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("padded data too short: %d bytes", len(data))
	}

	paddingLen := int(binary.BigEndian.Uint16(data[0:2]))
	if paddingLen > len(data)-6 {
		return nil, fmt.Errorf("padding length %d exceeds data size %d", paddingLen, len(data))
	}

	dataLen := int(binary.BigEndian.Uint32(data[2+paddingLen : 6+paddingLen]))
	if 6+paddingLen+dataLen > len(data) {
		return nil, fmt.Errorf("data length %d exceeds available data", dataLen)
	}

	return data[6+paddingLen : 6+paddingLen+dataLen], nil
}

// Overhead returns maximum obfuscation overhead in bytes
func (o *Obfuscator) Overhead() int {
	if !o.enabled {
		return 0
	}
	switch o.mode {
	case "tls-hello":
		return 5 // TLS record header
	case "http":
		return 80 // HTTP header
	case "random-padding":
		return 134 // 2 + 128(max padding) + 4
	default:
		return 0
	}
}
