package vdhcp2

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

	// 用于匹配一次请求和响应，防止客户端收到旧响应后误处理。
	RequestID string `json:"requestId,omitempty"`

	IP         string `json:"ip,omitempty"`
	SubnetMask string `json:"subnetMask,omitempty"`
	Gateway    string `json:"gateway,omitempty"`

	LeaseSeconds int64 `json:"leaseSeconds,omitempty"`

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
	b, err := json.Marshal(Message{
		Type:      MessageTypeDiscover,
		RequestID: reqID,
	})
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
	return json.Marshal(Message{
		Type:      MessageTypeNak,
		RequestID: reqID,
		Reason:    reason,
	})
}

func DecodeMessage(pkt []byte) (Message, error) {
	var msg Message
	if err := json.Unmarshal(pkt, &msg); err != nil {
		return msg, err
	}
	if msg.Type == "" {
		return msg, fmt.Errorf("invalid vdhcp message: type is empty")
	}
	return msg, nil
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
	return nil
}
