package vlan_net

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/xtaci/kcp-go/v5"
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
