package securetcp

import (
	"encoding/binary"
	"fmt"
)

const (
	protocolVersion byte = 1
	headerLen            = 8
)

// FrameType is the logical protocol frame kind.
type FrameType byte

const (
	FrameHandshake1 FrameType = 0x01
	FrameHandshake2 FrameType = 0x02
	FrameResume1    FrameType = 0x03
	FrameResume2    FrameType = 0x04

	FrameData  FrameType = 0x10
	FramePing  FrameType = 0x11
	FramePong  FrameType = 0x12
	FrameClose FrameType = 0x13
	FrameError FrameType = 0x14

	FrameRekey1 FrameType = 0x20
	FrameRekey2 FrameType = 0x21
)

func (t FrameType) String() string {
	switch t {
	case FrameHandshake1:
		return "HANDSHAKE1"
	case FrameHandshake2:
		return "HANDSHAKE2"
	case FrameResume1:
		return "RESUME1"
	case FrameResume2:
		return "RESUME2"
	case FrameData:
		return "DATA"
	case FramePing:
		return "PING"
	case FramePong:
		return "PONG"
	case FrameClose:
		return "CLOSE"
	case FrameError:
		return "ERROR"
	case FrameRekey1:
		return "REKEY1"
	case FrameRekey2:
		return "REKEY2"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(t))
	}
}

func encodeHeader(magic uint16, typ FrameType, length uint32) [headerLen]byte {
	var h [headerLen]byte
	binary.BigEndian.PutUint16(h[0:2], magic)
	h[2] = protocolVersion
	h[3] = byte(typ)
	binary.BigEndian.PutUint32(h[4:8], length)
	return h
}

func decodeHeader(h []byte, magic uint16, maxLen uint32) (FrameType, uint32, error) {
	if len(h) != headerLen {
		return 0, 0, ErrBadFrame
	}
	if binary.BigEndian.Uint16(h[0:2]) != magic {
		return 0, 0, ErrBadMagic
	}
	if h[2] != protocolVersion {
		return 0, 0, ErrBadVersion
	}
	length := binary.BigEndian.Uint32(h[4:8])
	if length > maxLen {
		return 0, 0, ErrFrameTooLarge
	}
	return FrameType(h[3]), length, nil
}
