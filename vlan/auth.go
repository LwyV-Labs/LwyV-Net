package vlan

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/LwyV-Labs/LwyV-Net/tcpx"
)

const (
	clientAuthVersion     byte = 1
	clientAuthNonceSize        = 16
	clientAuthMACSize          = sha256.Size
	clientAuthPayloadSize      = 1 + 32 + clientAuthNonceSize + clientAuthMACSize
)

// EncodeClientAuth proves that the client owns its long-term X25519 private key.
// The returned clientID is the client's static public key encoded as hex.
func EncodeClientAuth(clientPrivateKey, serverPublicKey string) ([]byte, string, error) {
	clientPriv, err := tcpx.ParsePrivateKeyAny(clientPrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse client private key: %w", err)
	}
	serverPub, err := tcpx.ParsePublicKeyAny(serverPublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse server public key: %w", err)
	}

	shared, err := clientPriv.ECDH(serverPub)
	if err != nil {
		return nil, "", fmt.Errorf("client auth ecdh: %w", err)
	}
	clientPubRaw := clientPriv.PublicKey().Bytes()
	serverPubRaw := serverPub.Bytes()

	nonce := make([]byte, clientAuthNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	mac := clientAuthMAC(shared, clientPubRaw, serverPubRaw, nonce)

	payload := make([]byte, 0, clientAuthPayloadSize)
	payload = append(payload, clientAuthVersion)
	payload = append(payload, clientPubRaw...)
	payload = append(payload, nonce...)
	payload = append(payload, mac...)
	return payload, hex.EncodeToString(clientPubRaw), nil
}

// VerifyClientAuth verifies a TypeAuth payload and returns the client static public key in hex.
func VerifyClientAuth(payload []byte, serverPrivateKey string) (string, error) {
	if len(payload) != clientAuthPayloadSize {
		return "", fmt.Errorf("bad auth payload size: %d", len(payload))
	}
	if payload[0] != clientAuthVersion {
		return "", fmt.Errorf("bad auth version: %d", payload[0])
	}

	serverPriv, err := tcpx.ParsePrivateKeyAny(serverPrivateKey)
	if err != nil {
		return "", fmt.Errorf("parse server private key: %w", err)
	}

	clientPubRaw := cloneBytes(payload[1 : 1+32])
	nonce := cloneBytes(payload[1+32 : 1+32+clientAuthNonceSize])
	gotMAC := payload[1+32+clientAuthNonceSize:]

	clientPub, err := tcpx.ParsePublicKeyAny(hex.EncodeToString(clientPubRaw))
	if err != nil {
		return "", fmt.Errorf("parse client public key: %w", err)
	}
	shared, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return "", fmt.Errorf("server auth ecdh: %w", err)
	}

	wantMAC := clientAuthMAC(shared, clientPubRaw, serverPriv.PublicKey().Bytes(), nonce)
	if !hmac.Equal(gotMAC, wantMAC) {
		return "", fmt.Errorf("client auth mac mismatch")
	}
	return hex.EncodeToString(clientPubRaw), nil
}

func clientAuthMAC(shared, clientPub, serverPub, nonce []byte) []byte {
	root := hmac.New(sha256.New, shared)
	_, _ = root.Write([]byte("vlan2 client auth root v2"))
	prk := root.Sum(nil)

	mac := hmac.New(sha256.New, prk)
	_, _ = mac.Write([]byte("vlan2 client auth payload v2"))
	_, _ = mac.Write(clientPub)
	_, _ = mac.Write(serverPub)
	_, _ = mac.Write(nonce)
	return mac.Sum(nil)
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
