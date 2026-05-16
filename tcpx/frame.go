package tcpx

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const HeaderSize = 11

const (
	FrameHandshakeClient byte = 1
	FrameHandshakeServer byte = 2
	FrameEncrypted       byte = 3
	FrameClose           byte = 4
)

const (
	InnerData      byte = 1
	InnerPing      byte = 2
	InnerPong      byte = 3
	InnerKeyUpdate byte = 4
)

type Frame struct {
	Magic   uint32
	Version uint16
	Type    byte
	Payload []byte
}

func readFrame(conn net.Conn, cfg BaseConfig) (Frame, error) {
	if cfg.ReadTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
	}
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return Frame{}, err
	}
	magic := binary.BigEndian.Uint32(header[0:4])
	version := binary.BigEndian.Uint16(header[4:6])
	frameType := header[6]
	length := binary.BigEndian.Uint32(header[7:11])
	if magic != cfg.Magic {
		return Frame{}, ErrBadMagic
	}
	if version != cfg.Version {
		return Frame{}, ErrBadVersion
	}
	if length > cfg.MaxPayload {
		return Frame{}, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, length, cfg.MaxPayload)
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Magic: magic, Version: version, Type: frameType, Payload: payload}, nil
}

func writeFrame(conn net.Conn, cfg BaseConfig, frameType byte, payload []byte) error {
	if uint32(len(payload)) > cfg.MaxPayload {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(payload), cfg.MaxPayload)
	}
	if cfg.WriteTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	}
	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], cfg.Magic)
	binary.BigEndian.PutUint16(buf[4:6], cfg.Version)
	buf[6] = frameType
	binary.BigEndian.PutUint32(buf[7:11], uint32(len(payload)))
	copy(buf[HeaderSize:], payload)
	_, err := conn.Write(buf)
	return err
}
