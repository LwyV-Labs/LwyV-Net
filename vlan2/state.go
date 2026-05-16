package vlan2

import (
	"net"
	"sync/atomic"
	"time"
)

//=========================== IP 报文解析 ===========================

// IsBroadcast 判断是否是IPv4广播包
func IsBroadcast(dst net.IP) bool {
	// 受限广播 255.255.255.255
	if dst.Equal(net.IPv4bcast) {
		return true
	}
	// 也可扩展判断子网广播，这里先做最常用的受限广播
	return false
}

// IsSubnetBroadcast 判断是否是当前虚拟网段的子网广播地址
func IsSubnetBroadcast(dst net.IP, gateway string, subnetMask string) bool {
	dst4 := dst.To4()
	gw4 := net.ParseIP(gateway).To4()
	maskIP := net.ParseIP(subnetMask).To4()

	if dst4 == nil || gw4 == nil || maskIP == nil {
		return false
	}

	mask := net.IPv4Mask(maskIP[0], maskIP[1], maskIP[2], maskIP[3])

	broadcast := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		broadcast[i] = gw4[i] | ^mask[i]
	}

	return dst4.Equal(broadcast)
}

// IsMulticast 判断是否是IPv4组播包
func IsMulticast(dst net.IP) bool {
	// 不是IPv4直接返回false
	if len(dst) != net.IPv4len {
		return false
	}
	// 组播地址第一段：224~239
	first := dst[0]
	return first >= 0xE0 && first <= 0xEF // 224=0xE0, 239=0xEF
}

type TrafficStats struct {
	UploadBytes   uint64
	DownloadBytes uint64
	UploadBps     float64
	DownloadBps   float64
}

type TrafficCounter struct {
	uploadBytes   atomic.Uint64
	downloadBytes atomic.Uint64
	lastUpload    atomic.Uint64
	lastDownload  atomic.Uint64
	lastUnixNano  atomic.Int64
}

func (t *TrafficCounter) AddUpload(n int) {
	if n > 0 {
		t.uploadBytes.Add(uint64(n))
	}
}

func (t *TrafficCounter) AddDownload(n int) {
	if n > 0 {
		t.downloadBytes.Add(uint64(n))
	}
}

func (t *TrafficCounter) Snapshot() TrafficStats {
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
