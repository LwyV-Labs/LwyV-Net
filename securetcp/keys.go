package securetcp

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type KeyPair struct {
	PrivateKeyB64 string
	PublicKeyB64  string
}

func GenerateKeyPair() (KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		PrivateKeyB64: base64.StdEncoding.EncodeToString(priv.Bytes()),
		PublicKeyB64:  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

func parsePrivateKeyB64(s string) (*ecdh.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: private key is %d bytes", ErrInvalidKeySize, len(b))
	}
	return ecdh.X25519().NewPrivateKey(b)
}

func parsePublicKeyB64(s string) (*ecdh.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: public key is %d bytes", ErrInvalidKeySize, len(b))
	}
	return ecdh.X25519().NewPublicKey(b)
}

func publicKeyB64FromPrivate(privB64 string) (string, error) {
	priv, err := parsePrivateKeyB64(privB64)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}
