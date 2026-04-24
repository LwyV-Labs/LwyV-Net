package vlan

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"golang.zx2c4.com/wireguard/tun"
)

//=========================== IP 报文解析 ===========================

type IPHeaderInfo struct {
	SrcIP       string
	DstIP       string
	IsBroadcast bool
	ProtoName   string
}

// 解析IP报文头信息
func headerParsing(pkt []byte) (IPHeaderInfo, error) {
	var info IPHeaderInfo

	// IPv4 最短头部 20 字节
	if len(pkt) < 20 {
		return info, fmt.Errorf("收到过短IP包，丢弃: %d bytes, 需要至少 20 bytes", len(pkt))
	}

	// 高4位是版本号，低4位是首部长度（单位是4字节）
	version := pkt[0] >> 4

	if version != 4 {
		return info, fmt.Errorf("收到非IPv4数据，丢弃: version=%d", version)
	}

	ihl := pkt[0] & 0x0F
	if ihl < 5 {
		return info, fmt.Errorf("非法IPv4头长度: %d", ihl)
	}
	headerLen := int(ihl) * 4
	if len(pkt) < headerLen {
		return info, fmt.Errorf("IP包长度不足: len=%d, ihl=%d", len(pkt), headerLen)
	}

	info = IPHeaderInfo{
		SrcIP:       net.IP(pkt[12:16]).String(),
		DstIP:       net.IP(pkt[16:20]).String(),
		IsBroadcast: isBroadcastIP(pkt[16:20]),
		ProtoName:   protoName(pkt[9]),
	}

	return info, nil
}

// 判断是否是广播地址
func isBroadcastIP(ip []byte) bool {
	if len(ip) != 4 {
		return false
	}
	if ip[0] == 0xff && ip[1] == 0xff && ip[2] == 0xff && ip[3] == 0xff {
		return true
	}
	if ip[0] == 172 && ip[1] == 19 && ip[2] == 0 && ip[3] == 255 {
		return true
	}
	if ip[0] >= 224 && ip[0] <= 239 {
		return true
	}
	return false
}

// 解析IP包类型
func protoName(proto byte) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO-%d", proto)
	}
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

//=========================== TCP，KCP 配置与读写 ===========================

// setupKCPSession设置KCP
func setupKCPSession(conn *kcp.UDPSession) {
	conn.SetWriteDelay(false)
	conn.SetNoDelay(1, 20, 2, 1)
	conn.SetWindowSize(1024, 1024)
	conn.SetMtu(Conf.Common.MTU + 64)
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

//=========================== TUN 读写 ===========================

// writeToTun 写网卡
func writeToTun(dev tun.Device, pkt []byte) error {
	buf := make([]byte, tunWriteOffset+len(pkt))
	copy(buf[tunWriteOffset:], pkt)

	_, err := dev.Write([][]byte{buf}, tunWriteOffset)
	return err
}

func readFromTun(dev tun.Device, mtu int) ([][]byte, error) {
	batchSize := dev.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}

	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}

	n, err := dev.Read(bufs, sizes, 0)
	if err != nil {
		return nil, err
	}

	packets := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		if sizes[i] <= 0 || sizes[i] > len(bufs[i]) {
			continue
		}

		pkt := make([]byte, sizes[i])
		copy(pkt, bufs[i][:sizes[i]])
		packets = append(packets, pkt)
	}

	return packets, nil
}
