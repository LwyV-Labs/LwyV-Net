package vlan

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

const tunPacketQueueSize = 16 * 1024

var ErrTUNTunnelClosed = errors.New("tun tunnel closed")

// TUNTunnel 把 TUN 设备的阻塞读写封装成两个队列：
//   - readChan：TUN -> 外部，外部只需要监听 ReadChan()
//   - writeChan：外部 -> TUN，外部只需要调用 Write(pkt)
//
// 注意：Write(pkt) 内部会 copy pkt，所以调用方后续复用 pkt 不会污染异步写入。
// ReadChan() 读出的 pkt 也是独立 copy，不会被下一次 TUN Read 覆盖。
type TUNTunnel struct {
	dev tun.Device

	batchSize int
	readBufs  [][]byte
	readSizes []int

	readChan  chan []byte
	writeChan chan []byte

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func NewTUNTunnel(ifName string, mtu int) (*TUNTunnel, error) {
	dev, err := tun.CreateTUN(ifName, mtu)

	if err != nil {
		return nil, fmt.Errorf("创建虚拟网卡失败: %w", err)
	}

	batchSize := dev.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}

	readBufs := make([][]byte, batchSize)
	for i := range readBufs {
		readBufs[i] = make([]byte, mtu)
	}

	t := &TUNTunnel{
		dev:       dev,
		batchSize: batchSize,
		readBufs:  readBufs,
		readSizes: make([]int, batchSize),
		readChan:  make(chan []byte, tunPacketQueueSize),
		writeChan: make(chan []byte, tunPacketQueueSize),
		done:      make(chan struct{}),
	}

	go t.readLoop()
	go t.writeLoop()

	return t, nil
}

func (t *TUNTunnel) ReadChan() <-chan []byte {
	return t.readChan
}

func (t *TUNTunnel) Write(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}

	// 异步写入必须 copy，避免调用方复用 pkt 后污染写队列里的数据。
	buf := make([]byte, len(pkt))
	copy(buf, pkt)

	select {
	case <-t.done:
		return ErrTUNTunnelClosed
	case t.writeChan <- buf:
		return nil
	}
}

func (t *TUNTunnel) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		t.closeErr = t.dev.Close()
	})
	return t.closeErr
}

func (t *TUNTunnel) readLoop() {
	defer close(t.readChan)

	for {
		select {
		case <-t.done:
			return
		default:
		}

		n, err := t.dev.Read(t.readBufs, t.readSizes, 0)
		if err != nil {
			t.Close()
			return
		}

		for i := 0; i < n; i++ {
			sz := t.readSizes[i]
			if sz <= 0 || sz > len(t.readBufs[i]) {
				continue
			}

			// readBufs 会被下一次 Read 复用，所以入队前必须 copy。
			pkt := make([]byte, sz)
			copy(pkt, t.readBufs[i][:sz])

			select {
			case <-t.done:
				return
			case t.readChan <- pkt:
			}
		}
	}
}

func (t *TUNTunnel) writeLoop() {
	batch := make([][]byte, 0, t.batchSize)

	for {
		batch = batch[:0]

		select {
		case <-t.done:
			return
		case pkt := <-t.writeChan:
			if len(pkt) == 0 {
				continue
			}
			batch = append(batch, pkt)
		}

		// 非阻塞地把当前队列里已有的包尽量凑成一批，减少 TUN Write 次数。
	drain:
		for len(batch) < t.batchSize {
			select {
			case <-t.done:
				return
			case pkt := <-t.writeChan:
				if len(pkt) > 0 {
					batch = append(batch, pkt)
				}
			default:
				break drain
			}
		}

		// 注意：不同平台/实现返回的 n 语义可能不是“包数量”。
		// 你当前 Linux TUN 返回的是写入字节数，比如 66。
		// 所以这里只判断 err。
		if _, err := t.dev.Write(batch, 0); err != nil {
			log.Printf("tun write failed: %v", err)
			t.Close()
			return
		}
	}
}
