package vlan

import (
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

const tunPacketQueueSize = 16 * 1024

//=========================== TUN 读写 ===========================

type TUNTunnel struct {
	dev       tun.Device
	readBufs  [][]byte
	readSizes []int
	writeBufs [][]byte
	mu        sync.Mutex
}

func NewTUNTunnel(dev tun.Device, mtu int) *TUNTunnel {
	batchSize := dev.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}

	readBufs := make([][]byte, batchSize)
	for i := range readBufs {
		readBufs[i] = make([]byte, mtu)
	}

	return &TUNTunnel{
		dev:       dev,
		readBufs:  readBufs,
		readSizes: make([]int, batchSize),
		writeBufs: make([][]byte, 1),
	}
}

func (t *TUNTunnel) Read() ([][]byte, error) {
	n, err := t.dev.Read(t.readBufs, t.readSizes, 0)
	if err != nil {
		return nil, err
	}
	packets := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		sz := t.readSizes[i]
		if sz <= 0 || sz > len(t.readBufs[i]) {
			continue
		}
		packets = append(packets, t.readBufs[i][:sz])
	}
	return packets, nil
}

func (t *TUNTunnel) Write(packets [][]byte) (int, error) {
	return t.dev.Write(packets, 0)
}
