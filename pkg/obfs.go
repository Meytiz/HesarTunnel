package pkg

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

type Obfuscator struct {
	mode    string
	enabled bool
}

func NewObfuscator(mode string, enabled bool) *Obfuscator {
	return &Obfuscator{mode: mode, enabled: enabled}
}

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
		return o.wrapPad(data)
	default:
		return data, nil
	}
}

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
		return o.unwrapPad(data)
	default:
		return data, nil
	}
}

func (o *Obfuscator) wrapTLS(data []byte) ([]byte, error) {
	dLen := len(data)
	if dLen <= 16384 {
		buf := make([]byte, 5+dLen)
		buf[0] = 0x17
		buf[1] = 0x03
		buf[2] = 0x03
		binary.BigEndian.PutUint16(buf[3:5], uint16(dLen))
		copy(buf[5:], data)
		return buf, nil
	}
	var buf bytes.Buffer
	for off := 0; off < dLen; {
		chunk := dLen - off
		if chunk > 16384 {
			chunk = 16384
		}
		hdr := [5]byte{0x17, 0x03, 0x03}
		binary.BigEndian.PutUint16(hdr[3:5], uint16(chunk))
		buf.Write(hdr[:])
		buf.Write(data[off : off+chunk])
		off += chunk
	}
	return buf.Bytes(), nil
}

func (o *Obfuscator) unwrapTLS(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("TLS too short")
	}
	var result bytes.Buffer
	off := 0
	for off < len(data) {
		if len(data)-off < 5 {
			return nil, fmt.Errorf("incomplete TLS header")
		}
		if data[off] != 0x17 {
			return nil, fmt.Errorf("bad content type: 0x%02x", data[off])
		}
		rLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
		if off+5+rLen > len(data) {
			return nil, fmt.Errorf("TLS record exceeds data")
		}
		result.Write(data[off+5 : off+5+rLen])
		off += 5 + rLen
	}
	return result.Bytes(), nil
}

func (o *Obfuscator) wrapHTTP(data []byte) ([]byte, error) {
	hdr := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", len(data))
	buf := make([]byte, len(hdr)+len(data))
	copy(buf, hdr)
	copy(buf[len(hdr):], data)
	return buf, nil
}

func (o *Obfuscator) unwrapHTTP(data []byte) ([]byte, error) {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx == -1 {
		return nil, fmt.Errorf("HTTP end not found")
	}
	return data[idx+4:], nil
}

func (o *Obfuscator) wrapPad(data []byte) ([]byte, error) {
	pBig, err := rand.Int(rand.Reader, big.NewInt(113))
	if err != nil {
		return nil, err
	}
	pLen := int(pBig.Int64()) + 16
	buf := make([]byte, 2+pLen+4+len(data))
	binary.BigEndian.PutUint16(buf[0:2], uint16(pLen))
	rand.Read(buf[2 : 2+pLen])
	binary.BigEndian.PutUint32(buf[2+pLen:6+pLen], uint32(len(data)))
	copy(buf[6+pLen:], data)
	return buf, nil
}

func (o *Obfuscator) unwrapPad(data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("pad data too short")
	}
	pLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 6+pLen > len(data) {
		return nil, fmt.Errorf("padding exceeds data")
	}
	dLen := int(binary.BigEndian.Uint32(data[2+pLen : 6+pLen]))
	if 6+pLen+dLen > len(data) {
		return nil, fmt.Errorf("data exceeds buffer")
	}
	return data[6+pLen : 6+pLen+dLen], nil
}
