package vdhcp

import (
	"encoding/json"
	"fmt"
)

const (
	MessageTypeDiscover = "DISCOVER"
	MessageTypeOffer    = "OFFER"
	MessageTypeNak      = "NAK"
)

type Message struct {
	// Type: DISCOVER / OFFER / NAK
	Type       string `json:"type"`
	IP         string `json:"ip,omitempty"`
	SubnetMask string `json:"subnetMask,omitempty"`
	Gateway    string `json:"gateway,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func EncodeDiscover() ([]byte, error) {
	return json.Marshal(Message{Type: MessageTypeDiscover})
}

func EncodeOffer(ip, subnetMask, gateway string) ([]byte, error) {
	return json.Marshal(Message{Type: MessageTypeOffer, IP: ip, SubnetMask: subnetMask, Gateway: gateway})
}

func EncodeNak(reason string) ([]byte, error) {
	return json.Marshal(Message{Type: MessageTypeNak, Reason: reason})
}

func DecodeMessage(pkt []byte) (Message, error) {
	// 注意：这里只做格式校验，不做字段语义（由调用方判断类型和必填字段）。
	var msg Message
	if err := json.Unmarshal(pkt, &msg); err != nil {
		return msg, err
	}
	if msg.Type == "" {
		return msg, fmt.Errorf("invalid DHCP message: type is empty")
	}
	return msg, nil
}
