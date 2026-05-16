package securetcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func zeroNonce() []byte { return make([]byte, 12) }

func nonceFor(epoch, seq uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint32(n[0:4], uint32(epoch))
	binary.BigEndian.PutUint64(n[4:12], seq)
	return n[:]
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func appendAll(parts ...[]byte) []byte {
	var total int
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}

func prologue(cfg CommonConfig) []byte {
	var p [8]byte
	binary.BigEndian.PutUint32(p[0:4], cfg.Magic)
	p[4] = cfg.Version
	copy(p[5:], []byte{'I', 'K', '1'})
	return p[:]
}

func deriveSessionKeys(root []byte) (c2s, s2c []byte) {
	km := hkdfSHA256(root, []byte("securetcp directional keys"), []byte("c2s|s2c"), 64)
	return km[:32], km[32:]
}

func makeAEADsForRole(root []byte, role Role) (send, recv cipher.AEAD, err error) {
	c2s, s2c := deriveSessionKeys(root)
	if role == RoleClient {
		send, err = newGCM(c2s)
		if err != nil {
			return nil, nil, err
		}
		recv, err = newGCM(s2c)
		return send, recv, err
	}
	send, err = newGCM(s2c)
	if err != nil {
		return nil, nil, err
	}
	recv, err = newGCM(c2s)
	return send, recv, err
}

func encodeU64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func requireLen(name string, got, want int) error {
	if got != want {
		return fmt.Errorf("%s length = %d, want %d", name, got, want)
	}
	return nil
}
