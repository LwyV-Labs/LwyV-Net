package vlan_net

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"golang.zx2c4.com/wireguard/tun"
)

func setupKCPSession(conn *kcp.UDPSession) {
	conn.SetWriteDelay(false)
	conn.SetNoDelay(1, 20, 2, 1)
	conn.SetWindowSize(1024, 1024)
	conn.SetMtu(1350)
	conn.SetACKNoDelay(true)
	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(4 * 1024 * 1024)
}

// readPacket 读包
func readPacket(conn net.Conn, maxSize int) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}

	pktLen := binary.BigEndian.Uint32(lenBuf)
	if pktLen == 0 || pktLen > uint32(maxSize) {
		return nil, fmt.Errorf("invalid pkt len: %d", pktLen)
	}

	pkt := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}

// writePacket 写包
func writePacket(conn net.Conn, pkt []byte) error {
	buf := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(pkt)))
	copy(buf[4:], pkt)

	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

// writeToTun 写网卡
func writeToTun(dev tun.Device, pkt []byte) error {
	buf := make([]byte, tunWriteOffset+len(pkt))
	copy(buf[tunWriteOffset:], pkt)

	_, err := dev.Write([][]byte{buf}, tunWriteOffset)
	return err
}

type tunPacketReader struct {
	dev   tun.Device
	bufs  [][]byte
	sizes []int
}

func newTunPacketReader(dev tun.Device, mtu int) *tunPacketReader {
	batchSize := dev.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}

	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}

	return &tunPacketReader{
		dev:   dev,
		bufs:  bufs,
		sizes: sizes,
	}
}

func (r *tunPacketReader) BatchSize() int {
	return len(r.bufs)
}

func (r *tunPacketReader) ReadPackets() ([][]byte, error) {
	n, err := r.dev.Read(r.bufs, r.sizes, 0)
	if err != nil {
		return nil, err
	}

	packets := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		if r.sizes[i] <= 0 || r.sizes[i] > len(r.bufs[i]) {
			continue
		}

		pkt := make([]byte, r.sizes[i])
		copy(pkt, r.bufs[i][:r.sizes[i]])
		packets = append(packets, pkt)
	}

	return packets, nil
}

// 广播数据
func broadcastPacket(heardInfo *IPHeaderInfo, pkt []byte) {
	var targets = make(map[string]*ClientPeer)

	clientKcpTable.RLock()
	for ip, targetPeer := range clientKcpTable.m {
		if ip == heardInfo.SrcIP {
			continue
		}
		targets[ip] = targetPeer
	}
	clientKcpTable.RUnlock()

	for ip, targetPeer := range targets {
		targetPeer.mu.Lock()
		err := writePacket(targetPeer.conn, pkt)
		targetPeer.mu.Unlock()
		if err != nil {
			log.Printf("广播转发 %s 失败: %v", ip, err)
		}
	}
}
