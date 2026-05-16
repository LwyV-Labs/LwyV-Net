package securetcp

import (
	"io"
	"net"
	"time"
)

func readRawFrame(nc net.Conn, cfg Config) (FrameType, []byte, [headerLen]byte, error) {
	var h [headerLen]byte
	if cfg.ReadTimeout > 0 {
		_ = nc.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
	}
	if _, err := io.ReadFull(nc, h[:]); err != nil {
		return 0, nil, h, err
	}
	typ, length, err := decodeHeader(h[:], cfg.Magic, cfg.MaxFrameSize+1024)
	if err != nil {
		return 0, nil, h, err
	}
	payload := make([]byte, int(length))
	if length > 0 {
		if cfg.ReadTimeout > 0 {
			_ = nc.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
		}
		if _, err := io.ReadFull(nc, payload); err != nil {
			return 0, nil, h, err
		}
	}
	return typ, payload, h, nil
}

func writeRawFrame(nc net.Conn, cfg Config, typ FrameType, payload []byte) error {
	if uint32(len(payload)) > cfg.MaxFrameSize+1024 {
		return ErrFrameTooLarge
	}
	h := encodeHeader(cfg.Magic, typ, uint32(len(payload)))
	if cfg.WriteTimeout > 0 {
		_ = nc.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	}
	if _, err := nc.Write(h[:]); err != nil {
		return err
	}
	written := 0
	for written < len(payload) {
		if cfg.WriteTimeout > 0 {
			_ = nc.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
		}
		n, err := nc.Write(payload[written:])
		if err != nil {
			return err
		}
		written += n
	}
	return nil
}
