package securetcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	handshakeNonceSize = 32
)

type handshakeResult struct {
	master       []byte
	clientPublic []byte
	ticket       *SessionTicket
	resumed      bool
}

func clientHandshake(nc net.Conn, cfg Config, ticket *SessionTicket) (handshakeResult, error) {
	if cfg.AllowResume && ticket.valid(time.Now()) {
		res, err := clientResumeHandshake(nc, cfg, ticket)
		if err == nil {
			return res, nil
		}
		return handshakeResult{}, err
	}
	return clientFullHandshake(nc, cfg)
}

func clientFullHandshake(nc net.Conn, cfg Config) (handshakeResult, error) {
	eph, err := GenerateKeyPair()
	if err != nil {
		return handshakeResult{}, err
	}
	es, err := ecdhShared(eph.Private, cfg.ServerStaticPublicKey)
	if err != nil {
		return handshakeResult{}, err
	}
	clientNonce, err := randomBytes(handshakeNonceSize)
	if err != nil {
		return handshakeResult{}, err
	}
	key1 := hkdf(nil, es, "securetcp-v1-full-handshake1-key", aesGCMKeySize)
	plain1 := append(append([]byte(nil), cfg.ClientStaticPublicKey...), clientNonce...)
	aad1 := sha256Sum([]byte("securetcp-v1-full-hs1"), eph.Public, cfg.ServerStaticPublicKey)
	nonce1, cipher1, err := encryptOnce(key1, aad1, plain1)
	if err != nil {
		return handshakeResult{}, err
	}
	payload1 := append(append(append([]byte(nil), eph.Public...), nonce1...), cipher1...)
	if err := writeRawFrame(nc, cfg, FrameHandshake1, payload1); err != nil {
		return handshakeResult{}, err
	}

	typ, payload2, _, err := readRawFrame(nc, cfg)
	if err != nil {
		return handshakeResult{}, err
	}
	if typ != FrameHandshake2 {
		return handshakeResult{}, fmt.Errorf("%w: want HANDSHAKE2, got %s", ErrHandshakeFailed, typ)
	}
	if len(payload2) < x25519PublicKeySize+nonceSize+16 {
		return handshakeResult{}, fmt.Errorf("%w: short HANDSHAKE2", ErrHandshakeFailed)
	}
	serverEphPub := payload2[:x25519PublicKeySize]
	nonce2 := payload2[x25519PublicKeySize : x25519PublicKeySize+nonceSize]
	cipher2 := payload2[x25519PublicKeySize+nonceSize:]
	ss, err := ecdhShared(cfg.ClientStaticPrivateKey, cfg.ServerStaticPublicKey)
	if err != nil {
		return handshakeResult{}, err
	}
	ee, err := ecdhShared(eph.Private, serverEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	se, err := ecdhShared(cfg.ClientStaticPrivateKey, serverEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	transcript := sha256Sum([]byte("securetcp-v1-full-transcript"), eph.Public, serverEphPub, cfg.ClientStaticPublicKey, cfg.ServerStaticPublicKey)
	preMaster := bytes.Join([][]byte{es, ss, ee, se, clientNonce, transcript}, nil)
	key2 := hkdf(nil, preMaster, "securetcp-v1-full-handshake2-key", aesGCMKeySize)
	aad2 := sha256Sum([]byte("securetcp-v1-full-hs2"), eph.Public, serverEphPub, cfg.ClientStaticPublicKey, cfg.ServerStaticPublicKey)
	plain2, err := decryptOnce(key2, nonce2, aad2, cipher2)
	if err != nil {
		return handshakeResult{}, fmt.Errorf("%w: decrypt HANDSHAKE2: %v", ErrHandshakeFailed, err)
	}
	if len(plain2) != handshakeNonceSize+16+32+8 {
		return handshakeResult{}, fmt.Errorf("%w: bad HANDSHAKE2 payload", ErrHandshakeFailed)
	}
	serverNonce := plain2[:handshakeNonceSize]
	sessionID := append([]byte(nil), plain2[handshakeNonceSize:handshakeNonceSize+16]...)
	resumeSecret := append([]byte(nil), plain2[handshakeNonceSize+16:handshakeNonceSize+16+32]...)
	expiresUnix := int64(binary.BigEndian.Uint64(plain2[handshakeNonceSize+16+32:]))
	master := hkdf(nil, bytes.Join([][]byte{preMaster, serverNonce}, nil), "securetcp-v1-full-master", 32)
	return handshakeResult{
		master:       master,
		clientPublic: append([]byte(nil), cfg.ClientStaticPublicKey...),
		ticket:       &SessionTicket{ID: sessionID, Secret: resumeSecret, ExpiresAt: time.Unix(expiresUnix, 0)},
		resumed:      false,
	}, nil
}

func serverHandshake(nc net.Conn, cfg Config, cache *sessionCache) (handshakeResult, error) {
	typ, payload, _, err := readRawFrame(nc, cfg)
	if err != nil {
		return handshakeResult{}, err
	}
	switch typ {
	case FrameHandshake1:
		return serverFullHandshake(nc, cfg, cache, payload)
	case FrameResume1:
		if !cfg.AllowResume {
			return handshakeResult{}, fmt.Errorf("%w: resume disabled", ErrHandshakeFailed)
		}
		return serverResumeHandshake(nc, cfg, cache, payload)
	default:
		return handshakeResult{}, fmt.Errorf("%w: unexpected first frame %s", ErrHandshakeFailed, typ)
	}
}

func serverFullHandshake(nc net.Conn, cfg Config, cache *sessionCache, payload1 []byte) (handshakeResult, error) {
	if len(payload1) < x25519PublicKeySize+nonceSize+16 {
		return handshakeResult{}, fmt.Errorf("%w: short HANDSHAKE1", ErrHandshakeFailed)
	}
	clientEphPub := payload1[:x25519PublicKeySize]
	nonce1 := payload1[x25519PublicKeySize : x25519PublicKeySize+nonceSize]
	cipher1 := payload1[x25519PublicKeySize+nonceSize:]
	es, err := ecdhShared(cfg.ServerStaticPrivateKey, clientEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	key1 := hkdf(nil, es, "securetcp-v1-full-handshake1-key", aesGCMKeySize)
	aad1 := sha256Sum([]byte("securetcp-v1-full-hs1"), clientEphPub, cfg.ServerStaticPublicKey)
	plain1, err := decryptOnce(key1, nonce1, aad1, cipher1)
	if err != nil {
		return handshakeResult{}, fmt.Errorf("%w: decrypt HANDSHAKE1: %v", ErrHandshakeFailed, err)
	}
	if len(plain1) != x25519PublicKeySize+handshakeNonceSize {
		return handshakeResult{}, fmt.Errorf("%w: bad HANDSHAKE1 payload", ErrHandshakeFailed)
	}
	clientStaticPub := append([]byte(nil), plain1[:x25519PublicKeySize]...)
	clientNonce := append([]byte(nil), plain1[x25519PublicKeySize:]...)
	serverEph, err := GenerateKeyPair()
	if err != nil {
		return handshakeResult{}, err
	}
	ss, err := ecdhShared(cfg.ServerStaticPrivateKey, clientStaticPub)
	if err != nil {
		return handshakeResult{}, err
	}
	ee, err := ecdhShared(serverEph.Private, clientEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	se, err := ecdhShared(serverEph.Private, clientStaticPub)
	if err != nil {
		return handshakeResult{}, err
	}
	serverNonce, err := randomBytes(handshakeNonceSize)
	if err != nil {
		return handshakeResult{}, err
	}
	transcript := sha256Sum([]byte("securetcp-v1-full-transcript"), clientEphPub, serverEph.Public, clientStaticPub, cfg.ServerStaticPublicKey)
	preMaster := bytes.Join([][]byte{es, ss, ee, se, clientNonce, transcript}, nil)
	key2 := hkdf(nil, preMaster, "securetcp-v1-full-handshake2-key", aesGCMKeySize)
	ticket, err := newTicket(cfg.SessionTicketTTL)
	if err != nil {
		return handshakeResult{}, err
	}
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(ticket.ExpiresAt.Unix()))
	plain2 := bytes.Join([][]byte{serverNonce, ticket.ID, ticket.Secret, exp[:]}, nil)
	aad2 := sha256Sum([]byte("securetcp-v1-full-hs2"), clientEphPub, serverEph.Public, clientStaticPub, cfg.ServerStaticPublicKey)
	nonce2, cipher2, err := encryptOnce(key2, aad2, plain2)
	if err != nil {
		return handshakeResult{}, err
	}
	payload2 := append(append(append([]byte(nil), serverEph.Public...), nonce2...), cipher2...)
	if err := writeRawFrame(nc, cfg, FrameHandshake2, payload2); err != nil {
		return handshakeResult{}, err
	}
	master := hkdf(nil, bytes.Join([][]byte{preMaster, serverNonce}, nil), "securetcp-v1-full-master", 32)
	if cfg.AllowResume {
		cache.put(clientStaticPub, ticket)
	}
	return handshakeResult{master: master, clientPublic: clientStaticPub, ticket: ticket, resumed: false}, nil
}

func clientResumeHandshake(nc net.Conn, cfg Config, ticket *SessionTicket) (handshakeResult, error) {
	if !ticket.valid(time.Now()) {
		return handshakeResult{}, errors.New("securetcp: invalid resume ticket")
	}
	eph, err := GenerateKeyPair()
	if err != nil {
		return handshakeResult{}, err
	}
	es, err := ecdhShared(eph.Private, cfg.ServerStaticPublicKey)
	if err != nil {
		return handshakeResult{}, err
	}
	clientNonce, err := randomBytes(handshakeNonceSize)
	if err != nil {
		return handshakeResult{}, err
	}
	key1 := hkdf(nil, es, "securetcp-v1-resume1-key", aesGCMKeySize)
	plain1 := bytes.Join([][]byte{ticket.ID, cfg.ClientStaticPublicKey, clientNonce}, nil)
	aad1 := sha256Sum([]byte("securetcp-v1-resume1"), eph.Public, cfg.ServerStaticPublicKey)
	nonce1, cipher1, err := encryptOnce(key1, aad1, plain1)
	if err != nil {
		return handshakeResult{}, err
	}
	payload1 := append(append(append([]byte(nil), eph.Public...), nonce1...), cipher1...)
	if err := writeRawFrame(nc, cfg, FrameResume1, payload1); err != nil {
		return handshakeResult{}, err
	}

	typ, payload2, _, err := readRawFrame(nc, cfg)
	if err != nil {
		return handshakeResult{}, err
	}
	if typ != FrameResume2 {
		return handshakeResult{}, fmt.Errorf("%w: want RESUME2, got %s", ErrHandshakeFailed, typ)
	}
	if len(payload2) < x25519PublicKeySize+nonceSize+16 {
		return handshakeResult{}, fmt.Errorf("%w: short RESUME2", ErrHandshakeFailed)
	}
	serverEphPub := payload2[:x25519PublicKeySize]
	nonce2 := payload2[x25519PublicKeySize : x25519PublicKeySize+nonceSize]
	cipher2 := payload2[x25519PublicKeySize+nonceSize:]
	ee, err := ecdhShared(eph.Private, serverEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	respKeyMaterial := bytes.Join([][]byte{ticket.Secret, es, ee, clientNonce, eph.Public, serverEphPub}, nil)
	key2 := hkdf(nil, respKeyMaterial, "securetcp-v1-resume2-key", aesGCMKeySize)
	aad2 := sha256Sum([]byte("securetcp-v1-resume2"), eph.Public, serverEphPub, ticket.ID, cfg.ClientStaticPublicKey, cfg.ServerStaticPublicKey)
	plain2, err := decryptOnce(key2, nonce2, aad2, cipher2)
	if err != nil {
		return handshakeResult{}, fmt.Errorf("%w: decrypt RESUME2: %v", ErrHandshakeFailed, err)
	}
	if len(plain2) != handshakeNonceSize+16+32+8 {
		return handshakeResult{}, fmt.Errorf("%w: bad RESUME2 payload", ErrHandshakeFailed)
	}
	serverNonce := plain2[:handshakeNonceSize]
	newID := append([]byte(nil), plain2[handshakeNonceSize:handshakeNonceSize+16]...)
	newSecret := append([]byte(nil), plain2[handshakeNonceSize+16:handshakeNonceSize+16+32]...)
	expiresUnix := int64(binary.BigEndian.Uint64(plain2[handshakeNonceSize+16+32:]))
	preMaster := bytes.Join([][]byte{ticket.Secret, es, ee, clientNonce, serverNonce, ticket.ID, cfg.ClientStaticPublicKey, cfg.ServerStaticPublicKey}, nil)
	master := hkdf(nil, preMaster, "securetcp-v1-resume-master", 32)
	return handshakeResult{master: master, clientPublic: append([]byte(nil), cfg.ClientStaticPublicKey...), ticket: &SessionTicket{ID: newID, Secret: newSecret, ExpiresAt: time.Unix(expiresUnix, 0)}, resumed: true}, nil
}

func serverResumeHandshake(nc net.Conn, cfg Config, cache *sessionCache, payload1 []byte) (handshakeResult, error) {
	if len(payload1) < x25519PublicKeySize+nonceSize+16 {
		return handshakeResult{}, fmt.Errorf("%w: short RESUME1", ErrHandshakeFailed)
	}
	clientEphPub := payload1[:x25519PublicKeySize]
	nonce1 := payload1[x25519PublicKeySize : x25519PublicKeySize+nonceSize]
	cipher1 := payload1[x25519PublicKeySize+nonceSize:]
	es, err := ecdhShared(cfg.ServerStaticPrivateKey, clientEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	key1 := hkdf(nil, es, "securetcp-v1-resume1-key", aesGCMKeySize)
	aad1 := sha256Sum([]byte("securetcp-v1-resume1"), clientEphPub, cfg.ServerStaticPublicKey)
	plain1, err := decryptOnce(key1, nonce1, aad1, cipher1)
	if err != nil {
		return handshakeResult{}, fmt.Errorf("%w: decrypt RESUME1: %v", ErrHandshakeFailed, err)
	}
	if len(plain1) != 16+x25519PublicKeySize+handshakeNonceSize {
		return handshakeResult{}, fmt.Errorf("%w: bad RESUME1 payload", ErrHandshakeFailed)
	}
	oldID := append([]byte(nil), plain1[:16]...)
	clientStaticPub := append([]byte(nil), plain1[16:16+x25519PublicKeySize]...)
	clientNonce := append([]byte(nil), plain1[16+x25519PublicKeySize:]...)
	entry, ok := cache.get(oldID)
	if !ok {
		return handshakeResult{}, fmt.Errorf("%w: unknown resume ticket", ErrHandshakeFailed)
	}
	if !bytes.Equal(entry.clientPublic, clientStaticPub) {
		return handshakeResult{}, fmt.Errorf("%w: resume identity mismatch", ErrHandshakeFailed)
	}
	serverEph, err := GenerateKeyPair()
	if err != nil {
		return handshakeResult{}, err
	}
	ee, err := ecdhShared(serverEph.Private, clientEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	serverNonce, err := randomBytes(handshakeNonceSize)
	if err != nil {
		return handshakeResult{}, err
	}
	newTicket, err := newTicket(cfg.SessionTicketTTL)
	if err != nil {
		return handshakeResult{}, err
	}
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(newTicket.ExpiresAt.Unix()))
	plain2 := bytes.Join([][]byte{serverNonce, newTicket.ID, newTicket.Secret, exp[:]}, nil)
	respKeyMaterial := bytes.Join([][]byte{entry.ticket.Secret, es, ee, clientNonce, clientEphPub, serverEph.Public}, nil)
	key2 := hkdf(nil, respKeyMaterial, "securetcp-v1-resume2-key", aesGCMKeySize)
	aad2 := sha256Sum([]byte("securetcp-v1-resume2"), clientEphPub, serverEph.Public, oldID, clientStaticPub, cfg.ServerStaticPublicKey)
	nonce2, cipher2, err := encryptOnce(key2, aad2, plain2)
	if err != nil {
		return handshakeResult{}, err
	}
	payload2 := append(append(append([]byte(nil), serverEph.Public...), nonce2...), cipher2...)
	if err := writeRawFrame(nc, cfg, FrameResume2, payload2); err != nil {
		return handshakeResult{}, err
	}
	preMaster := bytes.Join([][]byte{entry.ticket.Secret, es, ee, clientNonce, serverNonce, oldID, clientStaticPub, cfg.ServerStaticPublicKey}, nil)
	master := hkdf(nil, preMaster, "securetcp-v1-resume-master", 32)
	cache.delete(oldID)
	cache.put(clientStaticPub, newTicket)
	return handshakeResult{master: master, clientPublic: clientStaticPub, ticket: newTicket, resumed: true}, nil
}
