package vlan

import "fmt"

type PayloadType byte

const (
	// TypeAuth is the first application frame after tcpx encrypted handshake.
	TypeAuth  PayloadType = 1
	TypeVDHCP PayloadType = 2
	TypeIP    PayloadType = 3
)

func Pack(t PayloadType, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = byte(t)
	copy(out[1:], payload)
	return out
}

func Unpack(b []byte) (PayloadType, []byte, error) {
	if len(b) < 1 {
		return 0, nil, fmt.Errorf("empty payload")
	}
	t := PayloadType(b[0])
	switch t {
	case TypeAuth, TypeVDHCP, TypeIP:
		return t, b[1:], nil
	default:
		return 0, nil, fmt.Errorf("unknown payload type: %d", b[0])
	}
}

func shortID(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
