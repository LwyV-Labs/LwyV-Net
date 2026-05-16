package tcpx

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	clientHelloSize = 32
	serverProofSize = 24
)

func clientHandshake(conn net.Conn, cfg BaseConfig, serverPub *ecdh.PublicKey) (*SecureConn, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	clientPub := eph.PublicKey().Bytes()
	if err := writeFrame(conn, cfg, FrameHandshakeClient, clientPub); err != nil {
		return nil, err
	}

	dh, err := eph.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	transcript := handshakeTranscript(cfg, clientPub, serverPub.Bytes())
	c2s, s2c := deriveSessionKeys(dh, transcript)

	fr, err := readFrame(conn, cfg)
	if err != nil {
		return nil, err
	}
	if fr.Type != FrameHandshakeServer || len(fr.Payload) < 12 {
		return nil, ErrHandshake
	}
	aead, err := newAEAD(s2c)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	copy(nonce[:], fr.Payload[:12])
	proof, err := aead.Open(nil, nonce[:], fr.Payload[12:], transcript)
	if err != nil {
		return nil, fmt.Errorf("%w: server proof invalid", ErrHandshake)
	}
	if len(proof) != serverProofSize || !bytes.Equal(proof[:4], []byte("SOK1")) {
		return nil, fmt.Errorf("%w: bad server proof", ErrHandshake)
	}
	return newSecureConn(conn, cfg, c2s, s2c), nil
}

func serverHandshake(conn net.Conn, cfg BaseConfig, serverPriv *ecdh.PrivateKey) (*SecureConn, error) {
	fr, err := readFrame(conn, cfg)
	if err != nil {
		return nil, err
	}
	if fr.Type != FrameHandshakeClient || len(fr.Payload) != clientHelloSize {
		return nil, ErrHandshake
	}
	clientPubBytes := cloneBytes(fr.Payload)
	clientPub, err := ecdh.X25519().NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: bad client public key", ErrHandshake)
	}
	dh, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, err
	}
	serverPubBytes := serverPriv.PublicKey().Bytes()
	transcript := handshakeTranscript(cfg, clientPubBytes, serverPubBytes)
	c2s, s2c := deriveSessionKeys(dh, transcript)

	proof := make([]byte, serverProofSize)
	copy(proof[:4], []byte("SOK1"))
	binary.BigEndian.PutUint64(proof[4:12], uint64(time.Now().Unix()))
	if _, err := rand.Read(proof[12:]); err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aead, err := newAEAD(s2c)
	if err != nil {
		return nil, err
	}
	payload := append(nonce, aead.Seal(nil, nonce, proof, transcript)...)
	if err := writeFrame(conn, cfg, FrameHandshakeServer, payload); err != nil {
		return nil, err
	}
	return newSecureConn(conn, cfg, s2c, c2s), nil
}

func handshakeTranscript(cfg BaseConfig, clientPub, serverPub []byte) []byte {
	buf := make([]byte, 0, 4+2+len(clientPub)+len(serverPub)+16)
	buf = append(buf, []byte("tcpx-handshake-v1")...)
	var tmp [6]byte
	binary.BigEndian.PutUint32(tmp[0:4], cfg.Magic)
	binary.BigEndian.PutUint16(tmp[4:6], cfg.Version)
	buf = append(buf, tmp[:]...)
	buf = append(buf, clientPub...)
	buf = append(buf, serverPub...)
	return buf
}

func deriveSessionKeys(dh, transcript []byte) (c2s []byte, s2c []byte) {
	prk := hkdfExtract(transcript, dh)
	c2s = hkdfExpand(prk, []byte("tcpx c2s aes-gcm v1"), 32)
	s2c = hkdfExpand(prk, []byte("tcpx s2c aes-gcm v1"), 32)
	return c2s, s2c
}
