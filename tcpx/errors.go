package tcpx

import "errors"

var (
	ErrBadMagic      = errors.New("tcpx: bad magic")
	ErrBadVersion    = errors.New("tcpx: bad version")
	ErrFrameTooLarge = errors.New("tcpx: frame too large")
	ErrBadFrame      = errors.New("tcpx: bad frame")
	ErrReplay        = errors.New("tcpx: replay detected")
	ErrClosed        = errors.New("tcpx: closed")
	ErrHandshake     = errors.New("tcpx: handshake failed")
	ErrReconnectStop = errors.New("tcpx: reconnect stopped")
)
