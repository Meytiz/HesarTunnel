package pkg

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

/*
Wire Protocol v2:

Each frame on the wire:
  [MagicByte:1][Version:1][Type:1][Flags:1][ConnID:4][Port:2][Length:2][Payload:N]

Total header: 12 bytes
MaxPayload: 65000 bytes (leaving room for encryption overhead)

MagicByte prevents accidental parsing of garbage data.
*/

const (
	ProtoMagic   byte = 0xAE
	ProtoVersion byte = 0x02

	// Message types
	MsgData      byte = 0x01
	MsgKeepAlive byte = 0x02
	MsgNewConn   byte = 0x03
	MsgCloseConn byte = 0x04
	MsgAuth      byte = 0x05
	MsgAuthOK    byte = 0x06
	MsgAuthFail  byte = 0x07
	MsgPortMap   byte = 0x08

	// Flags
	FlagNone       byte = 0x00
	FlagCompressed byte = 0x01
	FlagUrgent     byte = 0x02

	HeaderSize = 12
	MaxPayload = 65000
)

// Frame represents a protocol message
type Frame struct {
	Type    byte
	Flags   byte
	ConnID  uint32
	Port    uint16
	Payload []byte
}

// headerPool avoids allocating header buffers for every frame
var headerPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, HeaderSize)
		return &b
	},
}

// MarshalFrame writes a frame directly to writer (thread-safe when writer is locked externally)
func MarshalFrame(w io.Writer, f *Frame) error {
	payloadLen := len(f.Payload)
	if payloadLen > MaxPayload {
		return fmt.Errorf("payload too large: %d > %d", payloadLen, MaxPayload)
	}

	hdrPtr := headerPool.Get().(*[]byte)
	hdr := *hdrPtr
	defer headerPool.Put(hdrPtr)

	hdr[0] = ProtoMagic
	hdr[1] = ProtoVersion
	hdr[2] = f.Type
	hdr[3] = f.Flags
	binary.BigEndian.PutUint32(hdr[4:8], f.ConnID)
	binary.BigEndian.PutUint16(hdr[8:10], f.Port)
	binary.BigEndian.PutUint16(hdr[10:12], uint16(payloadLen))

	// Write header
	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Write payload
	if payloadLen > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	return nil
}

// UnmarshalFrame reads a frame from reader
func UnmarshalFrame(r io.Reader) (*Frame, error) {
	hdrPtr := headerPool.Get().(*[]byte)
	hdr := *hdrPtr
	defer headerPool.Put(hdrPtr)

	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Validate magic byte
	if hdr[0] != ProtoMagic {
		return nil, fmt.Errorf("invalid magic byte: 0x%02x (expected 0x%02x)", hdr[0], ProtoMagic)
	}

	// Validate version
	if hdr[1] != ProtoVersion {
		return nil, fmt.Errorf("unsupported protocol version: %d (expected %d)", hdr[1], ProtoVersion)
	}

	msgType := hdr[2]
	flags := hdr[3]
	connID := binary.BigEndian.Uint32(hdr[4:8])
	port := 
