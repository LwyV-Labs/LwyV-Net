package securetcp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
)

type handshakeResult struct {
	root          []byte
	epoch         uint64
	peerStaticB64 string
}

func clientHandshake(c net.Conn, cfg CommonConfig, clientStatic *ecdh.PrivateKey, serverStaticPub *ecdh.PublicKey) (handshakeResult, error) {
	cEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return handshakeResult{}, err
	}
	cEphPub := cEph.PublicKey().Bytes()

	es, err := cEph.ECDH(serverStaticPub)
	if err != nil {
		return handshakeResult{}, err
	}
	staticKey := hkdfSHA256(appendAll(prologue(cfg), cEphPub), es, []byte("client-static-v1"), 32)
	staticAEAD, err := newGCM(staticKey)
	if err != nil {
		return handshakeResult{}, err
	}
	encStatic := staticAEAD.Seal(nil, zeroNonce(), clientStatic.PublicKey().Bytes(), cEphPub)
	initPayload := appendAll(cEphPub, encStatic)
	if err := writeFrame(c, cfg, FrameHandshakeInit, initPayload); err != nil {
		return handshakeResult{}, err
	}

	typ, resp, err := readFrame(c, cfg)
	if err != nil {
		return handshakeResult{}, err
	}
	if typ != FrameHandshakeResp {
		return handshakeResult{}, fmt.Errorf("%w: expected handshake resp, got 0x%x", ErrHandshake, typ)
	}
	if len(resp) < 32+16 {
		return handshakeResult{}, fmt.Errorf("%w: short handshake response", ErrHandshake)
	}
	sEphPubBytes := resp[:32]
	sEphPub, err := ecdh.X25519().NewPublicKey(sEphPubBytes)
	if err != nil {
		return handshakeResult{}, err
	}

	ss, err := clientStatic.ECDH(serverStaticPub)
	if err != nil {
		return handshakeResult{}, err
	}
	ee, err := cEph.ECDH(sEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	se, err := clientStatic.ECDH(sEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	transcript := appendAll(initPayload, sEphPubBytes)
	ikm := appendAll(es, ss, ee, se)
	root := hkdfSHA256(prologue(cfg), ikm, appendAll([]byte("securetcp-noise-ik-style-root"), transcript), 32)
	proofKey := hkdfSHA256(root, transcript, []byte("server-proof-key"), 32)
	proofAEAD, err := newGCM(proofKey)
	if err != nil {
		return handshakeResult{}, err
	}
	proof, err := proofAEAD.Open(nil, zeroNonce(), resp[32:], transcript)
	if err != nil {
		return handshakeResult{}, fmt.Errorf("%w: server proof decrypt: %v", ErrHandshake, err)
	}
	expectProof := hmacSHA256(root, []byte("server-proof"), serverStaticPub.Bytes(), clientStatic.PublicKey().Bytes(), transcript)
	if !bytes.Equal(proof, expectProof) {
		return handshakeResult{}, fmt.Errorf("%w: server proof mismatch", ErrHandshake)
	}
	return handshakeResult{root: root, epoch: 1, peerStaticB64: base64.StdEncoding.EncodeToString(serverStaticPub.Bytes())}, nil
}

func serverHandshake(c net.Conn, cfg CommonConfig, serverStatic *ecdh.PrivateKey) (handshakeResult, error) {
	typ, initPayload, err := readFrame(c, cfg)
	if err != nil {
		return handshakeResult{}, err
	}
	if typ != FrameHandshakeInit {
		return handshakeResult{}, fmt.Errorf("%w: expected handshake init, got 0x%x", ErrHandshake, typ)
	}
	if len(initPayload) < 32+16 {
		return handshakeResult{}, fmt.Errorf("%w: short handshake init", ErrHandshake)
	}
	cEphPubBytes := initPayload[:32]
	cEphPub, err := ecdh.X25519().NewPublicKey(cEphPubBytes)
	if err != nil {
		return handshakeResult{}, err
	}
	es, err := serverStatic.ECDH(cEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	staticKey := hkdfSHA256(appendAll(prologue(cfg), cEphPubBytes), es, []byte("client-static-v1"), 32)
	staticAEAD, err := newGCM(staticKey)
	if err != nil {
		return handshakeResult{}, err
	}
	cStaticPubBytes, err := staticAEAD.Open(nil, zeroNonce(), initPayload[32:], cEphPubBytes)
	if err != nil {
		return handshakeResult{}, fmt.Errorf("%w: client static decrypt: %v", ErrHandshake, err)
	}
	if err := requireLen("client static pub", len(cStaticPubBytes), 32); err != nil {
		return handshakeResult{}, err
	}
	cStaticPub, err := ecdh.X25519().NewPublicKey(cStaticPubBytes)
	if err != nil {
		return handshakeResult{}, err
	}

	ss, err := serverStatic.ECDH(cStaticPub)
	if err != nil {
		return handshakeResult{}, err
	}
	sEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return handshakeResult{}, err
	}
	sEphPubBytes := sEph.PublicKey().Bytes()
	ee, err := sEph.ECDH(cEphPub)
	if err != nil {
		return handshakeResult{}, err
	}
	se, err := sEph.ECDH(cStaticPub)
	if err != nil {
		return handshakeResult{}, err
	}
	transcript := appendAll(initPayload, sEphPubBytes)
	ikm := appendAll(es, ss, ee, se)
	root := hkdfSHA256(prologue(cfg), ikm, appendAll([]byte("securetcp-noise-ik-style-root"), transcript), 32)

	proofKey := hkdfSHA256(root, transcript, []byte("server-proof-key"), 32)
	proofAEAD, err := newGCM(proofKey)
	if err != nil {
		return handshakeResult{}, err
	}
	proof := hmacSHA256(root, []byte("server-proof"), serverStatic.PublicKey().Bytes(), cStaticPubBytes, transcript)
	encProof := proofAEAD.Seal(nil, zeroNonce(), proof, transcript)
	respPayload := appendAll(sEphPubBytes, encProof)
	if err := writeFrame(c, cfg, FrameHandshakeResp, respPayload); err != nil {
		return handshakeResult{}, err
	}
	return handshakeResult{root: root, epoch: 1, peerStaticB64: base64.StdEncoding.EncodeToString(cStaticPubBytes)}, nil
}
