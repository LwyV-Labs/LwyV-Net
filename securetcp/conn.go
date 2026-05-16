package securetcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type connRole byte

const (
	roleClient connRole = 1
	roleServer connRole = 2
)

type sessionKeys struct {
	master     []byte
	generation uint64
	send       *cipherState
	recv       *cipherState
	sendSeq    uint64
	recvSeq    uint64
	expiresAt  time.Time
}

type pendingRekey struct {
	id         []byte
	privateKey []byte
	baseMaster []byte
	generation uint64
}

// Conn is a secure framed TCP connection.
type Conn struct {
	nc   net.Conn
	cfg  Config
	role connRole

	writeMu  sync.Mutex
	keyMu    sync.Mutex
	current  *sessionKeys
	previous *sessionKeys

	inbound     chan []byte
	done        chan struct{}
	closed      atomic.Bool
	activeClose atomic.Bool
	closeOnce   sync.Once
	closeErr    error
	closeErrMu  sync.Mutex

	lastPong atomic.Int64

	rekeyMu sync.Mutex
	pending *pendingRekey

	onClose func(error)
}

func newConn(nc net.Conn, cfg Config, role connRole, master []byte) (*Conn, error) {
	keys, err := deriveSessionKeys(master, role, 0)
	if err != nil {
		return nil, err
	}
	c := &Conn{
		nc:      nc,
		cfg:     cfg,
		role:    role,
		current: keys,
		inbound: make(chan []byte, cfg.InboundBuffer),
		done:    make(chan struct{}),
	}
	c.lastPong.Store(time.Now().UnixNano())
	go c.readLoop()
	if cfg.HeartbeatInterval > 0 {
		go c.heartbeatLoop()
	}
	if cfg.RekeyInterval > 0 {
		go c.rekeyLoop()
	}
	return c, nil
}

func deriveSessionKeys(master []byte, role connRole, generation uint64) (*sessionKeys, error) {
	c2s, err := newCipherState(master, fmt.Sprintf("securetcp-v1-c2s-generation-%d", generation))
	if err != nil {
		return nil, err
	}
	s2c, err := newCipherState(master, fmt.Sprintf("securetcp-v1-s2c-generation-%d", generation))
	if err != nil {
		return nil, err
	}
	keys := &sessionKeys{master: append([]byte(nil), master...), generation: generation}
	if role == roleClient {
		keys.send, keys.recv = c2s, s2c
	} else {
		keys.send, keys.recv = s2c, c2s
	}
	return keys, nil
}

// NetConn returns the underlying TCP connection. Avoid direct reads/writes on it.
func (c *Conn) NetConn() net.Conn { return c.nc }

// Done is closed when the connection is closed.
func (c *Conn) Done() <-chan struct{} { return c.done }

// IsClosed reports whether the connection has been closed.
func (c *Conn) IsClosed() bool { return c.closed.Load() }

// ActiveClose reports whether Close was called locally.
func (c *Conn) ActiveClose() bool { return c.activeClose.Load() }

// CloseError returns the first close error, if any.
func (c *Conn) CloseError() error {
	c.closeErrMu.Lock()
	defer c.closeErrMu.Unlock()
	return c.closeErr
}

// ReadMessage returns the next decrypted DATA frame.
func (c *Conn) ReadMessage() ([]byte, error) {
	select {
	case msg, ok := <-c.inbound:
		if !ok {
			if err := c.CloseError(); err != nil {
				return nil, err
			}
			return nil, ErrClosed
		}
		return msg, nil
	case <-c.done:
		if err := c.CloseError(); err != nil {
			return nil, err
		}
		return nil, ErrClosed
	}
}

// ReadMessageContext returns the next decrypted DATA frame or ctx error.
func (c *Conn) ReadMessageContext(ctx context.Context) ([]byte, error) {
	select {
	case msg, ok := <-c.inbound:
		if !ok {
			if err := c.CloseError(); err != nil {
				return nil, err
			}
			return nil, ErrClosed
		}
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		if err := c.CloseError(); err != nil {
			return nil, err
		}
		return nil, ErrClosed
	}
}

// WriteMessage sends one encrypted DATA frame.
func (c *Conn) WriteMessage(p []byte) error {
	if uint32(len(p)) > c.cfg.MaxFrameSize {
		return ErrMessageTooLarge
	}
	return c.writeEncrypted(FrameData, p)
}

// Close actively closes the secure connection.
func (c *Conn) Close() error {
	c.activeClose.Store(true)
	if !c.closed.Load() {
		_ = c.writeEncrypted(FrameClose, nil)
	}
	c.closeWithError(ErrClosed)
	return nil
}

func (c *Conn) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeErrMu.Lock()
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			c.closeErr = err
		}
		c.closeErrMu.Unlock()
		_ = c.nc.Close()
		close(c.done)
		close(c.inbound)
		if c.onClose != nil {
			c.onClose(err)
		}
	})
}

func (c *Conn) readLoop() {
	for {
		typ, payload, header, err := readRawFrame(c.nc, c.cfg)
		if err != nil {
			c.closeWithError(err)
			return
		}
		plain, err := c.decryptFrame(header[:], payload)
		if err != nil {
			c.closeWithError(err)
			return
		}
		switch typ {
		case FrameData:
			select {
			case c.inbound <- plain:
			case <-c.done:
				return
			}
		case FramePing:
			_ = c.writeEncrypted(FramePong, plain)
		case FramePong:
			c.lastPong.Store(time.Now().UnixNano())
		case FrameClose:
			c.closeWithError(ErrClosed)
			return
		case FrameRekey1:
			if err := c.handleRekey1(plain); err != nil {
				c.closeWithError(err)
				return
			}
		case FrameRekey2:
			if err := c.handleRekey2(plain); err != nil {
				c.closeWithError(err)
				return
			}
		case FrameError:
			c.closeWithError(fmt.Errorf("securetcp peer error: %s", string(plain)))
			return
		default:
			c.closeWithError(fmt.Errorf("%w: unsupported encrypted frame %s", ErrBadFrame, typ))
			return
		}
	}
}

func (c *Conn) heartbeatLoop() {
	ticker := time.NewTicker(c.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if c.cfg.HeartbeatTimeout > 0 {
				last := time.Unix(0, c.lastPong.Load())
				if time.Since(last) > c.cfg.HeartbeatTimeout {
					c.closeWithError(fmt.Errorf("securetcp: heartbeat timeout"))
					return
				}
			}
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
			if err := c.writeEncrypted(FramePing, b[:]); err != nil {
				c.closeWithError(err)
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Conn) rekeyLoop() {
	ticker := time.NewTicker(c.cfg.RekeyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = c.InitiateRekey()
		case <-c.done:
			return
		}
	}
}

// InitiateRekey starts an encrypted in-band key rotation.
func (c *Conn) InitiateRekey() error {
	if c.closed.Load() {
		return ErrClosed
	}
	id, err := randomBytes(16)
	if err != nil {
		return err
	}
	eph, err := GenerateKeyPair()
	if err != nil {
		return err
	}
	c.rekeyMu.Lock()
	if c.pending != nil {
		c.rekeyMu.Unlock()
		return nil
	}
	c.keyMu.Lock()
	baseMaster := append([]byte(nil), c.current.master...)
	generation := c.current.generation
	c.keyMu.Unlock()
	c.pending = &pendingRekey{id: id, privateKey: eph.Private, baseMaster: baseMaster, generation: generation}
	c.rekeyMu.Unlock()
	payload := bytes.Join([][]byte{id, eph.Public}, nil)
	return c.writeEncrypted(FrameRekey1, payload)
}

func (c *Conn) handleRekey1(payload []byte) error {
	if len(payload) != 16+x25519PublicKeySize {
		return fmt.Errorf("%w: bad REKEY1", ErrBadFrame)
	}
	peerID := append([]byte(nil), payload[:16]...)
	peerPub := append([]byte(nil), payload[16:]...)

	c.rekeyMu.Lock()
	if c.pending != nil {
		cmp := bytes.Compare(c.pending.id, peerID)
		if cmp < 0 {
			// Local lower id wins. The peer should cancel its pending rekey and answer ours.
			c.rekeyMu.Unlock()
			return nil
		}
		// Peer lower id wins. Cancel local pending and respond to peer.
		c.pending = nil
	}
	c.rekeyMu.Unlock()

	eph, err := GenerateKeyPair()
	if err != nil {
		return err
	}
	shared, err := ecdhShared(eph.Private, peerPub)
	if err != nil {
		return err
	}
	c.keyMu.Lock()
	baseMaster := append([]byte(nil), c.current.master...)
	generation := c.current.generation
	c.keyMu.Unlock()

	resp := bytes.Join([][]byte{peerID, eph.Public}, nil)
	// Important: reply is encrypted under the old current key. Then both sides switch.
	if err := c.writeEncrypted(FrameRekey2, resp); err != nil {
		return err
	}
	newMaster := hkdf(nil, bytes.Join([][]byte{baseMaster, shared, peerID}, nil), "securetcp-v1-rekey-master", 32)
	return c.installKeys(newMaster, generation+1)
}

func (c *Conn) handleRekey2(payload []byte) error {
	if len(payload) != 16+x25519PublicKeySize {
		return fmt.Errorf("%w: bad REKEY2", ErrBadFrame)
	}
	id := append([]byte(nil), payload[:16]...)
	peerPub := append([]byte(nil), payload[16:]...)
	c.rekeyMu.Lock()
	pending := c.pending
	if pending == nil || !bytes.Equal(pending.id, id) {
		c.rekeyMu.Unlock()
		return nil
	}
	c.pending = nil
	c.rekeyMu.Unlock()
	shared, err := ecdhShared(pending.privateKey, peerPub)
	if err != nil {
		return err
	}
	newMaster := hkdf(nil, bytes.Join([][]byte{pending.baseMaster, shared, pending.id}, nil), "securetcp-v1-rekey-master", 32)
	return c.installKeys(newMaster, pending.generation+1)
}

func (c *Conn) installKeys(master []byte, generation uint64) error {
	newKeys, err := deriveSessionKeys(master, c.role, generation)
	if err != nil {
		return err
	}
	c.keyMu.Lock()
	defer c.keyMu.Unlock()
	if c.current != nil {
		c.current.expiresAt = time.Now().Add(c.cfg.OldKeyGrace)
		c.previous = c.current
	}
	c.current = newKeys
	return nil
}

func (c *Conn) writeEncrypted(typ FrameType, plaintext []byte) error {
	if c.closed.Load() {
		return ErrClosed
	}
	if uint32(len(plaintext)) > c.cfg.MaxFrameSize {
		return ErrMessageTooLarge
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.keyMu.Lock()
	keys := c.current
	seq := keys.sendSeq
	keys.sendSeq++
	cipherLen := uint32(len(plaintext) + keys.send.aead.Overhead())
	header := encodeHeader(c.cfg.Magic, typ, cipherLen)
	ciphertext := keys.send.seal(seq, header[:], plaintext)
	c.keyMu.Unlock()

	if c.cfg.WriteTimeout > 0 {
		_ = c.nc.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
	}
	if _, err := c.nc.Write(header[:]); err != nil {
		return err
	}
	written := 0
	for written < len(ciphertext) {
		if c.cfg.WriteTimeout > 0 {
			_ = c.nc.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
		}
		n, err := c.nc.Write(ciphertext[written:])
		if err != nil {
			return err
		}
		written += n
	}
	return nil
}

func (c *Conn) decryptFrame(header []byte, ciphertext []byte) ([]byte, error) {
	c.keyMu.Lock()
	defer c.keyMu.Unlock()
	if c.current == nil {
		return nil, ErrClosed
	}
	plain, err := c.current.recv.open(c.current.recvSeq, header, ciphertext)
	if err == nil {
		c.current.recvSeq++
		return plain, nil
	}
	if c.previous != nil && time.Now().Before(c.previous.expiresAt) {
		plain, oldErr := c.previous.recv.open(c.previous.recvSeq, header, ciphertext)
		if oldErr == nil {
			c.previous.recvSeq++
			return plain, nil
		}
	}
	return nil, fmt.Errorf("securetcp: decrypt frame failed: %w", err)
}
