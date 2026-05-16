//go:build !android

package mobile

import (
	"context"
	"errors"
)

type androidTun struct{}

func newAndroidTun(fd int, mtu int) *androidTun {
	return &androidTun{}
}

func (t *androidTun) readLoop(ctx context.Context, onPacket func([]byte), onError func(error)) {
}

func (t *androidTun) Write(pkt []byte) error {
	return errors.New("android tun is only available on android")
}

func (t *androidTun) Close() error {
	return nil
}
