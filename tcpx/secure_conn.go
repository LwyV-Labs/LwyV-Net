package tcpx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

type keyState struct {
	id      uint32
	key     []byte
	created time.Time
	expires time.Time
	seq     uint64
	replay  replayWindow
}

type SecureConn struct {
	conn net.Conn
	cfg  BaseConfig

	writeMu sync.Mutex
	readMu  sync.Mutex
	stateMu sync.Mutex

	sendKey *keyState
	recvKey *keyState
	oldRecv *keyState

	closed bool
}

func newSecureConn(conn net.Conn, cfg BaseConfig, sendKey, recvKey []byte) *SecureConn {
	now := time.Now()
	return &SecureConn{
		conn: conn,
		cfg:  cfg,
		sendKey: &keyState{
			id:      1,
			key:     cloneBytes(sendKey),
			created: now,
		},
		recvKey: &keyState{
			id:      1,
			key:     cloneBytes(recvKey),
			created: now,
			replay:  newReplayWindow(cfg.ReplayWindow),
		},
	}
}

func (c *SecureConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *SecureConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }

func (c *SecureConn) Close() error {
	c.stateMu.Lock()
	c.closed = true
	c.stateMu.Unlock()
	return c.conn.Close()
}

func (c *SecureConn) Write(payload []byte) error {
	return c.writeInner(InnerData, payload)
}

func (c *SecureConn) SendPing() error { return c.writeInner(InnerPing, nil) }
func (c *SecureConn) SendPong() error { return c.writeInner(InnerPong, nil) }

func (c *SecureConn) Read() ([]byte, error) {
	for {
		innerType, payload, err := c.readInner()
		if err != nil {
			return nil, err
		}
		switch innerType {
		case InnerData:
			return payload, nil
		case InnerPing:
			_ = c.SendPong()
		case InnerPong:
			// 心跳响应由库内部消费。
		case InnerKeyUpdate:
			// readInner 已经处理了换钥消息。
		default:
			return nil, ErrBadFrame
		}
	}
}

func (c *SecureConn) writeInner(innerType byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.rotateSendKeyIfNeededLocked(); err != nil {
		return err
	}
	return c.encryptAndWriteLocked(innerType, payload)
}

func (c *SecureConn) rotateSendKeyIfNeededLocked() error {
	if c.cfg.KeyRotateInterval <= 0 || time.Since(c.sendKey.created) < c.cfg.KeyRotateInterval {
		return nil
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	old := c.sendKey
	if err := c.encryptAndWriteLockedNoRotate(InnerKeyUpdate, salt); err != nil {
		return err
	}
	c.sendKey = &keyState{
		id:      old.id + 1,
		key:     deriveRotatedKey(old.key, salt),
		created: time.Now(),
	}
	return nil
}

func (c *SecureConn) encryptAndWriteLocked(innerType byte, payload []byte) error {
	return c.encryptAndWriteLockedNoRotate(innerType, payload)
}

func (c *SecureConn) encryptAndWriteLockedNoRotate(innerType byte, payload []byte) error {
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return ErrClosed
	}
	ks := c.sendKey
	ks.seq++
	seq := ks.seq
	keyID := ks.id
	key := cloneBytes(ks.key)
	c.stateMu.Unlock()

	plain := make([]byte, 1+len(payload))
	plain[0] = innerType
	copy(plain[1:], payload)

	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	nonce := seqNonce(seq)
	aad := encryptedAAD(c.cfg, keyID, seq)
	cipherText := aead.Seal(nil, nonce[:], plain, aad)

	out := make([]byte, 12+len(cipherText))
	binary.BigEndian.PutUint32(out[0:4], keyID)
	binary.BigEndian.PutUint64(out[4:12], seq)
	copy(out[12:], cipherText)
	return writeFrame(c.conn, c.cfg, FrameEncrypted, out)
}

func (c *SecureConn) readInner() (byte, []byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		fr, err := readFrame(c.conn, c.cfg)
		if err != nil {
			return 0, nil, err
		}
		if fr.Type == FrameClose {
			return 0, nil, ErrClosed
		}
		if fr.Type != FrameEncrypted || len(fr.Payload) < 12 {
			return 0, nil, ErrBadFrame
		}
		keyID := binary.BigEndian.Uint32(fr.Payload[0:4])
		seq := binary.BigEndian.Uint64(fr.Payload[4:12])
		cipherText := fr.Payload[12:]

		ks, err := c.lookupRecvKey(keyID)
		if err != nil {
			return 0, nil, err
		}

		aead, err := newAEAD(ks.key)
		if err != nil {
			return 0, nil, err
		}
		nonce := seqNonce(seq)
		aad := encryptedAAD(c.cfg, keyID, seq)
		plain, err := aead.Open(nil, nonce[:], cipherText, aad)
		if err != nil {
			return 0, nil, err
		}
		if len(plain) == 0 {
			return 0, nil, ErrBadFrame
		}
		if !c.markReplayOK(keyID, seq) {
			return 0, nil, ErrReplay
		}

		innerType := plain[0]
		payload := plain[1:]
		if innerType == InnerKeyUpdate {
			if len(payload) != 32 {
				return 0, nil, ErrBadFrame
			}
			if err := c.installRecvKey(keyID, payload); err != nil {
				return 0, nil, err
			}
			continue
		}
		return innerType, payload, nil
	}
}

func (c *SecureConn) lookupRecvKey(keyID uint32) (*keyState, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	now := time.Now()
	if c.recvKey != nil && c.recvKey.id == keyID {
		return &keyState{id: c.recvKey.id, key: cloneBytes(c.recvKey.key)}, nil
	}
	if c.oldRecv != nil && c.oldRecv.id == keyID && now.Before(c.oldRecv.expires) {
		return &keyState{id: c.oldRecv.id, key: cloneBytes(c.oldRecv.key)}, nil
	}
	return nil, fmt.Errorf("%w: unknown key id %d", ErrBadFrame, keyID)
}

func (c *SecureConn) markReplayOK(keyID uint32, seq uint64) bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.recvKey != nil && c.recvKey.id == keyID {
		return c.recvKey.replay.Accept(seq)
	}
	if c.oldRecv != nil && c.oldRecv.id == keyID && time.Now().Before(c.oldRecv.expires) {
		return c.oldRecv.replay.Accept(seq)
	}
	return false
}

func (c *SecureConn) installRecvKey(fromKeyID uint32, salt []byte) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.recvKey == nil || c.recvKey.id != fromKeyID {
		return fmt.Errorf("%w: invalid key update from %d", ErrBadFrame, fromKeyID)
	}
	now := time.Now()
	old := c.recvKey
	old.expires = now.Add(c.cfg.OldKeyGrace)
	c.oldRecv = old
	c.recvKey = &keyState{
		id:      fromKeyID + 1,
		key:     deriveRotatedKey(old.key, salt),
		created: now,
		replay:  newReplayWindow(c.cfg.ReplayWindow),
	}
	return nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func seqNonce(seq uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return nonce
}

func encryptedAAD(cfg BaseConfig, keyID uint32, seq uint64) []byte {
	buf := make([]byte, 4+2+1+4+8)
	binary.BigEndian.PutUint32(buf[0:4], cfg.Magic)
	binary.BigEndian.PutUint16(buf[4:6], cfg.Version)
	buf[6] = FrameEncrypted
	binary.BigEndian.PutUint32(buf[7:11], keyID)
	binary.BigEndian.PutUint64(buf[11:19], seq)
	return buf
}

func deriveRotatedKey(oldKey, salt []byte) []byte {
	return hkdfKey(oldKey, salt, []byte("tcpx rotate key v1"))
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
