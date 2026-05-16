package securetcp

import "errors"

var (
	ErrBadMagic       = errors.New("securetcp: bad frame magic")
	ErrBadVersion     = errors.New("securetcp: bad frame version")
	ErrFrameTooLarge  = errors.New("securetcp: frame too large")
	ErrClosed         = errors.New("securetcp: connection closed")
	ErrReplay         = errors.New("securetcp: replayed or too old packet")
	ErrNoSession      = errors.New("securetcp: no active crypto session")
	ErrHandshake      = errors.New("securetcp: handshake failed")
	ErrReconnectOff   = errors.New("securetcp: auto reconnect is disabled")
	ErrInvalidKeySize = errors.New("securetcp: invalid key size")
)
