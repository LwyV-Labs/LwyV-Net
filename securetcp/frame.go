package securetcp

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const HeaderLen = 10

type FrameType byte

const (
	FrameHandshakeInit FrameType = 0x01
	FrameHandshakeResp FrameType = 0x02

	FrameData     FrameType = 0x10
	FramePing     FrameType = 0x11
	FramePong     FrameType = 0x12
	FrameRekeyReq FrameType = 0x13
	FrameRekeyRes FrameType = 0x14
	FrameClose    FrameType = 0x15
)

type frameHeader struct {
	Magic   uint32
	Version byte
	Type    FrameType
	Length  uint32
}

func encodeHeader(h frameHeader) [HeaderLen]byte {
	var b [HeaderLen]byte
	binary.BigEndian.PutUint32(b[0:4], h.Magic)
	b[4] = h.Version
	b[5] = byte(h.Type)
	binary.BigEndian.PutUint32(b[6:10], h.Length)
	return b
}

func decodeHeader(b []byte) frameHeader {
	return frameHeader{
		Magic:   binary.BigEndian.Uint32(b[0:4]),
		Version: b[4],
		Type:    FrameType(b[5]),
		Length:  binary.BigEndian.Uint32(b[6:10]),
	}
}

func readFullWithDeadline(c net.Conn, b []byte, timeout time.Duration) error {
	if timeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(timeout))
	}
	_, err := io.ReadFull(c, b)
	return err
}

func writeFullWithDeadline(c net.Conn, b []byte, timeout time.Duration) error {
	if timeout > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(timeout))
	}
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func readFrame(c net.Conn, cfg CommonConfig) (FrameType, []byte, error) {
	var hb [HeaderLen]byte
	if err := readFullWithDeadline(c, hb[:], cfg.ReadTimeout); err != nil {
		return 0, nil, err
	}
	h := decodeHeader(hb[:])
	if h.Magic != cfg.Magic {
		return 0, nil, ErrBadMagic
	}
	if h.Version != cfg.Version {
		return 0, nil, ErrBadVersion
	}
	if h.Length > cfg.MaxFramePayload {
		return 0, nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, h.Length, cfg.MaxFramePayload)
	}
	payload := make([]byte, h.Length)
	if h.Length > 0 {
		if err := readFullWithDeadline(c, payload, cfg.ReadTimeout); err != nil {
			return 0, nil, err
		}
	}
	return h.Type, payload, nil
}

func writeFrame(c net.Conn, cfg CommonConfig, typ FrameType, payload []byte) error {
	if uint32(len(payload)) > cfg.MaxFramePayload {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(payload), cfg.MaxFramePayload)
	}
	h := encodeHeader(frameHeader{Magic: cfg.Magic, Version: cfg.Version, Type: typ, Length: uint32(len(payload))})
	buf := make([]byte, 0, HeaderLen+len(payload))
	buf = append(buf, h[:]...)
	buf = append(buf, payload...)
	return writeFullWithDeadline(c, buf, cfg.WriteTimeout)
}
