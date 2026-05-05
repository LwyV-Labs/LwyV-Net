package vlan

import (
	"sync/atomic"
	"time"
)

type TrafficStats struct {
	UploadBytes   uint64
	DownloadBytes uint64
	UploadBps     float64
	DownloadBps   float64
}

type trafficCounter struct {
	uploadBytes   atomic.Uint64
	downloadBytes atomic.Uint64
	lastUpload    atomic.Uint64
	lastDownload  atomic.Uint64
	lastUnixNano  atomic.Int64
}

func (t *trafficCounter) addUpload(n int) {
	if n > 0 {
		t.uploadBytes.Add(uint64(n))
	}
}

func (t *trafficCounter) addDownload(n int) {
	if n > 0 {
		t.downloadBytes.Add(uint64(n))
	}
}

func (t *trafficCounter) snapshot() TrafficStats {
	now := time.Now().UnixNano()
	last := t.lastUnixNano.Load()
	up := t.uploadBytes.Load()
	down := t.downloadBytes.Load()
	if last == 0 {
		t.lastUnixNano.Store(now)
		t.lastUpload.Store(up)
		t.lastDownload.Store(down)
		return TrafficStats{UploadBytes: up, DownloadBytes: down}
	}
	dt := float64(now-last) / float64(time.Second)
	if dt <= 0 {
		return TrafficStats{UploadBytes: up, DownloadBytes: down}
	}
	prevUp := t.lastUpload.Swap(up)
	prevDown := t.lastDownload.Swap(down)
	t.lastUnixNano.Store(now)
	return TrafficStats{
		UploadBytes:   up,
		DownloadBytes: down,
		UploadBps:     float64(up-prevUp) / dt,
		DownloadBps:   float64(down-prevDown) / dt,
	}
}
