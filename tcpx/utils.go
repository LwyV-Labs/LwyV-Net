package tcpx

import (
	"context"
	crand "crypto/rand"
	"math/big"
	"time"
)

func randomInterval(base, jitter time.Duration) time.Duration {
	if base <= 0 {
		base = time.Second
	}
	if jitter <= 0 {
		return base
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(jitter)))
	if err != nil {
		return base
	}
	return base + time.Duration(n.Int64())
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
