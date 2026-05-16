package securetcp

import (
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Conn struct {
	netConn net.Conn
	cfg     CommonConfig
	role    Role

	peerStaticB64 string

	writeMu sync.Mutex
	keyMu   sync.RWMutex
	current *cryptoSession
	old     map[uint64]*cryptoSession

	pendingMu sync.Mutex
	pending   map[uint64]*ecdh.PrivateKey

	incoming  chan []byte
	errCh     chan error
	done      chan struct{}
	closeOnce sync.Once

	lastPong atomic.Int64
	rekeyID  atomic.Uint64

	allowHeartbeat bool
	allowRekey     bool
}

func newConn(nc net.Conn, cfg CommonConfig, role Role, hs handshakeResult, allowHeartbeat bool, allowRekey bool) (*Conn, error) {
	cfg.normalize()
	sess, err := newCryptoSession(hs.epoch, hs.root, role, cfg.ReplayWindow, time.Time{})
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	c := &Conn{
		netConn:        nc,
		cfg:            cfg,
		role:           role,
		peerStaticB64:  hs.peerStaticB64,
		current:        sess,
		old:            make(map[uint64]*cryptoSession),
		pending:        make(map[uint64]*ecdh.PrivateKey),
		incoming:       make(chan []byte, 128),
		errCh:          make(chan error, 1),
		done:           make(chan struct{}),
		allowHeartbeat: allowHeartbeat,
		allowRekey:     allowRekey,
	}
	c.lastPong.Store(time.Now().UnixNano())
	return c, nil
}

func (c *Conn) Start() {
	go c.readLoop()
	if c.allowHeartbeat {
		go c.heartbeatLoop()
	}
	if c.allowRekey {
		go c.rekeyLoop()
	}
}

func (c *Conn) PeerStaticPublicKeyB64() string { return c.peerStaticB64 }

func (c *Conn) LocalAddr() net.Addr  { return c.netConn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.netConn.RemoteAddr() }

func (c *Conn) Done() <-chan struct{} { return c.done }

func (c *Conn) Err() error {
	select {
	case err := <-c.errCh:
		if err == nil {
			return ErrClosed
		}
		return err
	default:
		return nil
	}
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		_ = c.sendEncrypted(FrameClose, []byte("close"))
		err = c.netConn.Close()
		close(c.done)
		close(c.incoming)
	})
	return err
}

func (c *Conn) fail(err error) {
	select {
	case c.errCh <- err:
	default:
	}
	c.closeOnce.Do(func() {
		_ = c.netConn.Close()
		close(c.done)
		close(c.incoming)
	})
}

func (c *Conn) Write(p []byte) error {
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	return c.sendEncrypted(FrameData, p)
}

func (c *Conn) Read(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case b, ok := <-c.incoming:
		if !ok {
			return nil, ErrClosed
		}
		return b, nil
	case <-c.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Conn) sendEncrypted(typ FrameType, plaintext []byte) error {
	c.keyMu.RLock()
	s := c.current
	if s == nil {
		c.keyMu.RUnlock()
		return ErrNoSession
	}
	epoch := s.epoch
	seq := s.sendSeq.Add(1)
	aead := s.sendAEAD
	c.keyMu.RUnlock()

	ciphertext := aead.Seal(nil, nonceFor(epoch, seq), plaintext, aadFor(typ, epoch, seq))
	payload := make([]byte, 16+len(ciphertext))
	binary.BigEndian.PutUint64(payload[0:8], epoch)
	binary.BigEndian.PutUint64(payload[8:16], seq)
	copy(payload[16:], ciphertext)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeFrame(c.netConn, c.cfg, typ, payload)
}

func aadFor(typ FrameType, epoch, seq uint64) []byte {
	var aad [17]byte
	aad[0] = byte(typ)
	binary.BigEndian.PutUint64(aad[1:9], epoch)
	binary.BigEndian.PutUint64(aad[9:17], seq)
	return aad[:]
}

func (c *Conn) decryptPayload(typ FrameType, payload []byte) ([]byte, error) {
	if len(payload) < 16 {
		return nil, fmt.Errorf("short encrypted payload")
	}
	epoch := binary.BigEndian.Uint64(payload[0:8])
	seq := binary.BigEndian.Uint64(payload[8:16])
	ciphertext := payload[16:]

	c.keyMu.RLock()
	s := c.current
	if s == nil || s.epoch != epoch {
		s = c.old[epoch]
		if s != nil && !s.expiresAt.IsZero() && time.Now().After(s.expiresAt) {
			s = nil
		}
	}
	if s == nil {
		c.keyMu.RUnlock()
		return nil, fmt.Errorf("unknown crypto epoch %d", epoch)
	}
	aead := s.recvAEAD
	c.keyMu.RUnlock()

	plaintext, err := aead.Open(nil, nonceFor(epoch, seq), ciphertext, aadFor(typ, epoch, seq))
	if err != nil {
		return nil, err
	}
	if !s.replay.CheckAndMark(seq) {
		return nil, ErrReplay
	}
	return plaintext, nil
}

func (c *Conn) readLoop() {
	for {
		typ, payload, err := readFrame(c.netConn, c.cfg)
		if err != nil {
			c.fail(err)
			return
		}
		switch typ {
		case FrameData:
			pt, err := c.decryptPayload(typ, payload)
			if err != nil {
				c.fail(err)
				return
			}
			select {
			case c.incoming <- pt:
			case <-c.done:
				return
			}
		case FramePing:
			pt, err := c.decryptPayload(typ, payload)
			if err != nil {
				c.fail(err)
				return
			}
			if c.role == RoleServer {
				_ = c.sendEncrypted(FramePong, pt)
			}
		case FramePong:
			_, err := c.decryptPayload(typ, payload)
			if err != nil {
				c.fail(err)
				return
			}
			c.lastPong.Store(time.Now().UnixNano())
		case FrameRekeyReq:
			pt, err := c.decryptPayload(typ, payload)
			if err != nil {
				c.fail(err)
				return
			}
			if err := c.handleRekeyRequest(pt); err != nil {
				c.fail(err)
				return
			}
		case FrameRekeyRes:
			pt, err := c.decryptPayload(typ, payload)
			if err != nil {
				c.fail(err)
				return
			}
			if err := c.handleRekeyResponse(pt); err != nil {
				c.fail(err)
				return
			}
		case FrameClose:
			_, _ = c.decryptPayload(typ, payload)
			c.fail(ErrClosed)
			return
		default:
			c.fail(fmt.Errorf("unknown frame type 0x%x", typ))
			return
		}
	}
}

func (c *Conn) heartbeatLoop() {
	for {
		interval := jittered(c.cfg.HeartbeatBase, c.cfg.HeartbeatJitter)
		select {
		case <-time.After(interval):
		case <-c.done:
			return
		}
		now := time.Now()
		last := time.Unix(0, c.lastPong.Load())
		// Allow at least two heartbeat periods before declaring the peer dead.
		maxSilent := 2*c.cfg.HeartbeatBase + c.cfg.HeartbeatJitter + c.cfg.ReadTimeout/2
		if maxSilent < c.cfg.ReadTimeout {
			maxSilent = c.cfg.ReadTimeout
		}
		if now.Sub(last) > maxSilent {
			c.fail(fmt.Errorf("heartbeat timeout: last pong %s ago", now.Sub(last)))
			return
		}
		ping, err := randBytes(16)
		if err != nil {
			continue
		}
		if err := c.sendEncrypted(FramePing, ping); err != nil {
			c.fail(err)
			return
		}
	}
}

func jittered(base, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return base
	}
	// math/rand is enough for timing jitter; cryptographic randomness is not required here.
	delta := time.Duration(mrand.Int63n(int64(jitter)*2+1)) - jitter
	v := base + delta
	if v < time.Second {
		return time.Second
	}
	return v
}

func (c *Conn) rekeyLoop() {
	for {
		interval := c.cfg.RekeyInterval
		select {
		case <-time.After(interval):
		case <-c.done:
			return
		}
		_ = c.InitiateRekey()
	}
}

func (c *Conn) InitiateRekey() error {
	eph, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		return err
	}
	id := c.rekeyID.Add(1)
	payload := make([]byte, 8+32)
	binary.BigEndian.PutUint64(payload[:8], id)
	copy(payload[8:], eph.PublicKey().Bytes())

	c.pendingMu.Lock()
	c.pending[id] = eph
	c.pendingMu.Unlock()

	if err := c.sendEncrypted(FrameRekeyReq, payload); err != nil {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		return err
	}
	return nil
}

func (c *Conn) handleRekeyRequest(pt []byte) error {
	if len(pt) != 40 {
		return fmt.Errorf("bad rekey request size %d", len(pt))
	}
	id := binary.BigEndian.Uint64(pt[:8])
	peerPub, err := ecdh.X25519().NewPublicKey(pt[8:])
	if err != nil {
		return err
	}
	eph, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		return err
	}
	shared, err := eph.ECDH(peerPub)
	if err != nil {
		return err
	}

	newRoot, newEpoch, err := c.deriveNextRootAndEpoch(shared, id)
	if err != nil {
		return err
	}

	resp := make([]byte, 8+32)
	binary.BigEndian.PutUint64(resp[:8], id)
	copy(resp[8:], eph.PublicKey().Bytes())
	// Response must be encrypted with the old/current key so the initiator can read it.
	if err := c.sendEncrypted(FrameRekeyRes, resp); err != nil {
		return err
	}
	return c.installSession(newEpoch, newRoot)
}

func (c *Conn) handleRekeyResponse(pt []byte) error {
	if len(pt) != 40 {
		return fmt.Errorf("bad rekey response size %d", len(pt))
	}
	id := binary.BigEndian.Uint64(pt[:8])
	peerPub, err := ecdh.X25519().NewPublicKey(pt[8:])
	if err != nil {
		return err
	}
	c.pendingMu.Lock()
	eph := c.pending[id]
	delete(c.pending, id)
	c.pendingMu.Unlock()
	if eph == nil {
		return fmt.Errorf("unknown rekey id %d", id)
	}
	shared, err := eph.ECDH(peerPub)
	if err != nil {
		return err
	}
	newRoot, newEpoch, err := c.deriveNextRootAndEpoch(shared, id)
	if err != nil {
		return err
	}
	return c.installSession(newEpoch, newRoot)
}

func (c *Conn) deriveNextRootAndEpoch(shared []byte, id uint64) ([]byte, uint64, error) {
	c.keyMu.RLock()
	cur := c.current
	if cur == nil {
		c.keyMu.RUnlock()
		return nil, 0, ErrNoSession
	}
	oldRoot := append([]byte(nil), cur.root...)
	newEpoch := cur.epoch + 1
	c.keyMu.RUnlock()
	info := appendAll([]byte("securetcp-rekey-root"), encodeU64(id), encodeU64(newEpoch))
	newRoot := hkdfSHA256(oldRoot, shared, info, 32)
	return newRoot, newEpoch, nil
}

func (c *Conn) installSession(epoch uint64, root []byte) error {
	newSess, err := newCryptoSession(epoch, root, c.role, c.cfg.ReplayWindow, time.Time{})
	if err != nil {
		return err
	}
	c.keyMu.Lock()
	if c.current != nil {
		c.current.expiresAt = time.Now().Add(c.cfg.OldKeyGrace)
		c.old[c.current.epoch] = c.current
	}
	for ep, s := range c.old {
		if !s.expiresAt.IsZero() && time.Now().After(s.expiresAt) {
			delete(c.old, ep)
		}
	}
	c.current = newSess
	c.keyMu.Unlock()
	return nil
}
