package securetcp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	x25519PrivateKeySize = 32
	x25519PublicKeySize  = 32
	aesGCMKeySize        = 32
	nonceSize            = 12
)

// KeyPair is a raw X25519 static or ephemeral key pair.
type KeyPair struct {
	Private []byte
	Public  []byte
}

// GenerateKeyPair creates an X25519 key pair. Persist server static keys in production.
func GenerateKeyPair() (KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Private: append([]byte(nil), priv.Bytes()...), Public: append([]byte(nil), priv.PublicKey().Bytes()...)}, nil
}

// PublicKeyFromPrivate derives the X25519 public key from a raw private key.
func PublicKeyFromPrivate(private []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), priv.PublicKey().Bytes()...), nil
}

func ecdhShared(private, peerPublic []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPublic)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk []byte, info []byte, n int) []byte {
	var out bytes.Buffer
	var t []byte
	counter := byte(1)
	for out.Len() < n {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out.Write(t)
		counter++
	}
	return out.Bytes()[:n]
}

func hkdf(salt, ikm []byte, info string, n int) []byte {
	return hkdfExpand(hkdfExtract(salt, ikm), []byte(info), n)
}

func sha256Sum(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

type cipherState struct {
	aead      cipher.AEAD
	nonceBase [nonceSize]byte
}

func newCipherState(master []byte, label string) (*cipherState, error) {
	material := hkdf(nil, master, label, aesGCMKeySize+nonceSize)
	block, err := aes.NewCipher(material[:aesGCMKeySize])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	cs := &cipherState{aead: aead}
	copy(cs.nonceBase[:], material[aesGCMKeySize:])
	return cs, nil
}

func (cs *cipherState) nonce(seq uint64) []byte {
	n := make([]byte, nonceSize)
	copy(n, cs.nonceBase[:])
	var tail [8]byte
	binary.BigEndian.PutUint64(tail[:], seq)
	for i := 0; i < 8; i++ {
		n[nonceSize-8+i] ^= tail[i]
	}
	return n
}

func (cs *cipherState) seal(seq uint64, aad []byte, plaintext []byte) []byte {
	return cs.aead.Seal(nil, cs.nonce(seq), plaintext, aad)
}

func (cs *cipherState) open(seq uint64, aad []byte, ciphertext []byte) ([]byte, error) {
	return cs.aead.Open(nil, cs.nonce(seq), ciphertext, aad)
}

func encryptOnce(key, aad, plaintext []byte) ([]byte, []byte, error) {
	if len(key) < aesGCMKeySize {
		return nil, nil, errors.New("securetcp: short aead key")
	}
	block, err := aes.NewCipher(key[:aesGCMKeySize])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func decryptOnce(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	if len(key) < aesGCMKeySize {
		return nil, errors.New("securetcp: short aead key")
	}
	block, err := aes.NewCipher(key[:aesGCMKeySize])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("securetcp: bad nonce")
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
