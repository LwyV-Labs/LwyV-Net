package tcpx

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerateStaticKey returns an X25519 key pair encoded as hex.
// Keep this function for callers that already use the first tcpx-go version.
func GenerateStaticKey() (privateHex string, publicHex string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(priv.Bytes()), hex.EncodeToString(priv.PublicKey().Bytes()), nil
}

// GenerateStaticKeyBase64 returns an X25519 key pair encoded as standard base64.
// This matches your existing client.json/server.json format.
func GenerateStaticKeyBase64() (privateB64 string, publicB64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func ParsePrivateKeyHex(s string) (*ecdh.PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return priv, nil
}

func ParsePublicKeyHex(s string) (*ecdh.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return pub, nil
}

func ParsePrivateKeyAny(s string) (*ecdh.PrivateKey, error) {
	raw, err := DecodeX25519Key(s)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return priv, nil
}

func ParsePublicKeyAny(s string) (*ecdh.PublicKey, error) {
	raw, err := DecodeX25519Key(s)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return pub, nil
}

func NormalizePrivateKeyHex(s string) (string, error) {
	priv, err := ParsePrivateKeyAny(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(priv.Bytes()), nil
}

func NormalizePublicKeyHex(s string) (string, error) {
	pub, err := ParsePublicKeyAny(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub.Bytes()), nil
}

func PublicKeyHexFromPrivate(s string) (string, error) {
	priv, err := ParsePrivateKeyAny(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(priv.PublicKey().Bytes()), nil
}

func PublicKeyBase64FromPrivate(s string) (string, error) {
	priv, err := ParsePrivateKeyAny(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// DecodeX25519Key accepts 32 raw-byte X25519 keys encoded as hex, standard base64,
// raw standard base64, URL-safe base64, or raw URL-safe base64.
func DecodeX25519Key(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty key")
	}

	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return cloneBytes(b), nil
	}

	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range decoders {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return cloneBytes(b), nil
		}
	}
	return nil, fmt.Errorf("key must be 32 raw bytes encoded as hex/base64/base64url")
}
