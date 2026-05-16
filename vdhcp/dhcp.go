package vdhcp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	MessageTypeDiscover = "DISCOVER"
	MessageTypeOffer    = "OFFER"
	MessageTypeNak      = "NAK"
)

type Message struct {
	Type string `json:"type"`

	// RequestID is used to match one request/response pair and reject stale offers.
	RequestID string `json:"requestId,omitempty"`

	IP           string `json:"ip,omitempty"`
	SubnetMask   string `json:"subnetMask,omitempty"`
	Gateway      string `json:"gateway,omitempty"`
	LeaseSeconds int64  `json:"leaseSeconds,omitempty"`

	Reason string `json:"reason,omitempty"`
}

func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func EncodeDiscover() ([]byte, string, error) {
	reqID := NewRequestID()
	b, err := json.Marshal(Message{Type: MessageTypeDiscover, RequestID: reqID})
	return b, reqID, err
}

func EncodeOffer(reqID, ip, subnetMask, gateway string, lease time.Duration) ([]byte, error) {
	return json.Marshal(Message{
		Type:         MessageTypeOffer,
		RequestID:    reqID,
		IP:           ip,
		SubnetMask:   subnetMask,
		Gateway:      gateway,
		LeaseSeconds: int64(lease.Seconds()),
	})
}

func EncodeNak(reqID, reason string) ([]byte, error) {
	return json.Marshal(Message{Type: MessageTypeNak, RequestID: reqID, Reason: reason})
}

func DecodeMessage(pkt []byte) (Message, error) {
	var msg Message
	if err := json.Unmarshal(pkt, &msg); err != nil {
		return msg, err
	}
	switch msg.Type {
	case MessageTypeDiscover, MessageTypeOffer, MessageTypeNak:
		return msg, nil
	case "":
		return msg, fmt.Errorf("invalid vdhcp message: type is empty")
	default:
		return msg, fmt.Errorf("invalid vdhcp message type: %s", msg.Type)
	}
}

func ValidateOffer(msg Message, reqID string) error {
	if msg.Type != MessageTypeOffer {
		return fmt.Errorf("unexpected message type: %s", msg.Type)
	}
	if msg.RequestID != reqID {
		return fmt.Errorf("request id mismatch")
	}
	if msg.IP == "" || msg.SubnetMask == "" || msg.Gateway == "" {
		return fmt.Errorf("invalid offer: missing ip/subnet/gateway")
	}
	if msg.LeaseSeconds <= 0 {
		return fmt.Errorf("invalid offer: leaseSeconds must be positive")
	}
	return nil
}
