//go:build android

package mobile

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"
)

type androidTun struct {
	file *os.File
	mtu  int

	writeMu sync.Mutex
	once    sync.Once
}

func newAndroidTun(fd int, mtu int) *androidTun {
	if mtu <= 0 {
		mtu = 1300
	}

	// VpnService fd may be non-blocking on some Android versions/devices. The Go
	// forwarding loop is simpler and steadier in blocking mode.
	_ = syscall.SetNonblock(fd, false)

	return &androidTun{
		file: os.NewFile(uintptr(fd), "lwyv-android-vpn-tun"),
		mtu:  mtu,
	}
}

func (t *androidTun) readLoop(ctx context.Context, onPacket func([]byte), onError func(error)) {
	if t == nil || t.file == nil {
		return
	}

	bufSize := t.mtu + 512
	if bufSize < 2048 {
		bufSize = 2048
	}
	buf := make([]byte, bufSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := t.file.Read(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return
			}
			if onError != nil {
				onError(err)
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if n <= 0 {
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if onPacket != nil {
			onPacket(pkt)
		}
	}
}

func (t *androidTun) Write(pkt []byte) error {
	if t == nil || t.file == nil {
		return errors.New("android tun is closed")
	}
	if len(pkt) == 0 {
		return nil
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.file.Write(pkt)
	return err
}

func (t *androidTun) Close() error {
	if t == nil {
		return nil
	}
	var err error
	t.once.Do(func() {
		if t.file != nil {
			err = t.file.Close()
		}
	})
	return err
}
