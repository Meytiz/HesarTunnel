package pkg

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	ProtoMagic   byte = 0xAE
	ProtoVersion byte = 0x02

	MsgData      byte = 0x01
	MsgKeepAlive byte = 0x02
	MsgNewConn   byte = 0x03
	MsgCloseConn byte = 0x04
	MsgAuth      byte = 0x05
	MsgAuthOK    byte = 0x06
	MsgAuthFail  byte = 0x07
	MsgPortMap   byte = 0x08

	FlagNone byte = 0x00

	HeaderSize = 12
	MaxPayload = 65000
)

type Frame struct {
	Type    byte
	Flags   byte
	ConnID  uint32
	Port    uint16
	Payload []byte
}

func MarshalFrame(w io.Writer, f *Frame) error {
	pLen := len(f.Payload)
	if pLen > MaxPayload {
		return fmt.Errorf("payload too large: %d", pLen)
	}

	hdr := make([]byte, HeaderSize)
	hdr[0] = ProtoMagic
	hdr[1] = ProtoVersion
	hdr[2] = f.Type
	hdr[3] = f.Flags
	binary.BigEndian.PutUint32(hdr[4:8], f.ConnID)
	binary.BigEndian.PutUint16(hdr[8:10], f.Port)
	binary.BigEndian.PutUint16(hdr[10:12], uint16(pLen))

	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if pLen > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}
	return nil
}

func UnmarshalFrame(r io.Reader) (*Frame, error) {
	hdr := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	if hdr[0] != ProtoMagic {
		return nil, fmt.Errorf("bad magic: 0x%02x", hdr[0])
	}
	if hdr[1] != ProtoVersion {
		return nil, fmt.Errorf("bad version: %d", hdr[1])
	}

	pLen := binary.BigEndian.Uint16(hdr[10:12])
	if pLen > MaxPayload {
		return nil, fmt.Errorf("payload too large: %d", pLen)
	}

	var payload []byte
	if pLen > 0 {
		payload = make([]byte, pLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return &Frame{
		Type:    hdr[2],
		Flags:   hdr[3],
		ConnID:  binary.BigEndian.Uint32(hdr[4:8]),
		Port:    binary.BigEndian.Uint16(hdr[8:10]),
		Payload: payload,
	}, nil
}

func NewDataFrame(connID uint32, port uint16, data []byte) *Frame {
	return &Frame{Type: MsgData, ConnID: connID, Port: port, Payload: data}
}

func NewControlFrame(msgType byte, connID uint32, port uint16) *Frame {
	return &Frame{Type: msgType, ConnID: connID, Port: port}
}

func EncodePortMap(ports []int) []byte {
	buf := make([]byte, 2+len(ports)*2)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(ports)))
	for i, p := range ports {
		binary.BigEndian.PutUint16(buf[2+i*2:4+i*2], uint16(p))
	}
	return buf
}

func DecodePortMap(data []byte) ([]int, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("port map too short")
	}
	n := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+n*2 {
		return nil, fmt.Errorf("port map incomplete")
	}
	ports := make([]int, n)
	for i := 0; i < n; i++ {
		ports[i] = int(binary.BigEndian.Uint16(data[2+i*2 : 4+i*2]))
	}
	return ports, nil
}
