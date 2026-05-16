package vlan2

import "fmt"

type PayloadType byte

const (
	TypeVDHCP PayloadType = 1
	TypeIP    PayloadType = 2
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
	switch PayloadType(b[0]) {
	case TypeVDHCP, TypeIP:
		return PayloadType(b[0]), b[1:], nil
	default:
		return 0, nil, fmt.Errorf("unknown payload type: %d", b[0])
	}
}
