package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	RekeyInterval           = 120 * time.Second
	replayWindowSize uint64 = 4096
)

var protocolName = []byte("lwyv-net-ik-v1")

type Identity struct {
	Private []byte
	Public  []byte
}

func ParsePrivateKey(s string) (Identity, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Identity{}, fmt.Errorf("private key base64 decode failed: %w", err)
	}
	if len(raw) != 32 {
		return Identity{}, fmt.Errorf("private key must be 32 bytes")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Private: raw, Public: pub}, nil
}

func ParsePublicKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("public key base64 decode failed: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("public key must be 32 bytes")
	}
	return raw, nil
}

func DeviceIDFromPublicKey(pub []byte) string {
	h := sha256.Sum256(pub)
	return fmt.Sprintf("%x", h[:8])
}

type CryptoSession struct {
	keyID       uint32
	sendCounter uint64

	recvMax  uint64
	recvSeen map[uint64]struct{}
	recvMu   sync.Mutex

	sendAEAD cipherAead
	recvAEAD cipherAead
}

type cipherAead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
}

func NewSession(keyID uint32, sendKey, recvKey []byte) (*CryptoSession, error) {
	send, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, err
	}
	recv, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, err
	}
	return &CryptoSession{
		keyID:    keyID,
		sendAEAD: send,
		recvAEAD: recv,
		recvSeen: make(map[uint64]struct{}, replayWindowSize),
	}, nil
}

func (s *CryptoSession) KeyID() uint32 { return s.keyID }

func (s *CryptoSession) Encrypt(innerType byte, payload []byte) ([]byte, error) {
	counter := atomic.AddUint64(&s.sendCounter, 1)
	head := make([]byte, 13)
	binary.BigEndian.PutUint32(head[:4], s.keyID)
	binary.BigEndian.PutUint64(head[4:12], counter)
	head[12] = innerType

	nonce := make([]byte, s.sendAEAD.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], counter)
	ciphertext := s.sendAEAD.Seal(nil, nonce, payload, head)
	out := append(head, ciphertext...)
	return out, nil
}

func (s *CryptoSession) Decrypt(pkt []byte) (byte, []byte, error) {
	if len(pkt) < 13 {
		return 0, nil, fmt.Errorf("secure payload too short")
	}

	head := pkt[:13]
	counter := binary.BigEndian.Uint64(head[4:12])
	if counter == 0 {
		return 0, nil, fmt.Errorf("invalid packet counter=0")
	}

	nonce := make([]byte, s.recvAEAD.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], counter)

	plain, err := s.recvAEAD.Open(nil, nonce, pkt[13:], head)
	if err != nil {
		return 0, nil, err
	}

	s.recvMu.Lock()
	if !s.acceptCounterLocked(counter) {
		s.recvMu.Unlock()
		return 0, nil, fmt.Errorf("replayed or too old packet counter=%d max=%d", counter, s.recvMax)
	}
	s.recvMu.Unlock()

	return head[12], plain, nil
}

func (s *CryptoSession) acceptCounterLocked(counter uint64) bool {
	if s.recvSeen == nil {
		s.recvSeen = make(map[uint64]struct{}, replayWindowSize)
	}

	if s.recvMax > 0 && counter+replayWindowSize <= s.recvMax {
		return false
	}

	if _, ok := s.recvSeen[counter]; ok {
		return false
	}

	if counter > s.recvMax {
		s.recvMax = counter

		var cutoff uint64
		if s.recvMax > replayWindowSize {
			cutoff = s.recvMax - replayWindowSize
		}

		for c := range s.recvSeen {
			if c <= cutoff {
				delete(s.recvSeen, c)
			}
		}
	}

	s.recvSeen[counter] = struct{}{}
	return true
}

type SessionManager struct {
	mu       sync.RWMutex
	current  *CryptoSession
	previous *CryptoSession
}

func (m *SessionManager) Current() *CryptoSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}
func (m *SessionManager) Rotate(next *CryptoSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.previous = m.current
	m.current = next
}
func (m *SessionManager) Decrypt(pkt []byte) (byte, []byte, error) {
	if len(pkt) < 4 {
		return 0, nil, fmt.Errorf("secure payload missing key id")
	}
	kid := binary.BigEndian.Uint32(pkt[:4])
	m.mu.RLock()
	cur, prev := m.current, m.previous
	m.mu.RUnlock()
	if cur != nil && cur.KeyID() == kid {
		return cur.Decrypt(pkt)
	}
	if prev != nil && prev.KeyID() == kid {
		return prev.Decrypt(pkt)
	}
	return 0, nil, fmt.Errorf("unknown session key id: %d", kid)
}

type Handshaker struct {
	identity   Identity
	peerStatic []byte
}

func NewHandshaker(identity Identity, peerStatic []byte) *Handshaker {
	return &Handshaker{identity: identity, peerStatic: peerStatic}
}

func (h *Handshaker) InitiatorHandshake(writeMsg func([]byte) error, readMsg func() ([]byte, error), keyID uint32) (*CryptoSession, error) {
	if len(h.peerStatic) != 32 {
		return nil, fmt.Errorf("initiator requires server static public key (common.peerPublicKeys[0])")
	}
	ephPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephPriv); err != nil {
		return nil, err
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	msg1 := make([]byte, 0, 68)
	keyIDBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(keyIDBuf, keyID)
	msg1 = append(msg1, keyIDBuf...)
	msg1 = append(msg1, ephPub...)
	msg1 = append(msg1, h.identity.Public...)
	if err = writeMsg(msg1); err != nil {
		return nil, err
	}
	msg2, err := readMsg()
	if err != nil {
		return nil, err
	}
	if len(msg2) < 32 {
		return nil, fmt.Errorf("invalid handshake response")
	}
	serverEphPub := msg2[:32]

	es, err := curve25519.X25519(ephPriv, h.peerStatic)
	if err != nil {
		return nil, err
	}
	se, err := curve25519.X25519(h.identity.Private, serverEphPub)
	if err != nil {
		return nil, err
	}
	ee, err := curve25519.X25519(ephPriv, serverEphPub)
	if err != nil {
		return nil, err
	}
	return deriveSession(keyID, true, es, se, ee)
}

func (h *Handshaker) ResponderHandshake(writeMsg func([]byte) error, readMsg func() ([]byte, error), keyID uint32) (*CryptoSession, []byte, error) {
	msg1, err := readMsg()
	if err != nil {
		return nil, nil, err
	}
	if len(msg1) < 64 {
		return nil, nil, fmt.Errorf("invalid handshake init")
	}
	offset := 0
	if len(msg1) >= 68 {
		keyID = binary.BigEndian.Uint32(msg1[:4])
		offset = 4
	}
	clientEphPub, clientStatic := msg1[offset:offset+32], msg1[offset+32:offset+64]
	ephPriv := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, ephPriv); err != nil {
		return nil, nil, err
	}
	serverEphPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	if err = writeMsg(serverEphPub); err != nil {
		return nil, nil, err
	}

	es, err := curve25519.X25519(h.identity.Private, clientEphPub)
	if err != nil {
		return nil, nil, err
	}
	se, err := curve25519.X25519(ephPriv, clientStatic)
	if err != nil {
		return nil, nil, err
	}
	ee, err := curve25519.X25519(ephPriv, clientEphPub)
	if err != nil {
		return nil, nil, err
	}
	sess, err := deriveSession(keyID, false, es, se, ee)
	return sess, clientStatic, err
}

func deriveSession(keyID uint32, initiator bool, ss ...[]byte) (*CryptoSession, error) {
	ikm := append([]byte{}, protocolName...)
	for _, s := range ss {
		ikm = append(ikm, s...)
	}
	h := hkdf.New(sha256.New, ikm, nil, []byte("transport"))
	k1 := make([]byte, chacha20poly1305.KeySize)
	k2 := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, k1); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(h, k2); err != nil {
		return nil, err
	}
	if initiator {
		return NewSession(keyID, k1, k2)
	}
	return NewSession(keyID, k2, k1)
}
