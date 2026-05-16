package securetcp

import (
	"crypto/cipher"
	"sync/atomic"
	"time"
)

type Role byte

const (
	RoleClient Role = 1
	RoleServer Role = 2
)

type cryptoSession struct {
	epoch     uint64
	root      []byte
	sendAEAD  cipher.AEAD
	recvAEAD  cipher.AEAD
	sendSeq   atomic.Uint64
	replay    *ReplayWindow
	expiresAt time.Time
}

func newCryptoSession(epoch uint64, root []byte, role Role, replayWindow uint64, expiresAt time.Time) (*cryptoSession, error) {
	send, recv, err := makeAEADsForRole(root, role)
	if err != nil {
		return nil, err
	}
	return &cryptoSession{
		epoch:     epoch,
		root:      root,
		sendAEAD:  send,
		recvAEAD:  recv,
		replay:    NewReplayWindow(replayWindow),
		expiresAt: expiresAt,
	}, nil
}
