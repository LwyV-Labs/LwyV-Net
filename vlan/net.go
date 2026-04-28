package vlan

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

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

	// IPv4 最短头部长度是 20 字节；比这更短的一定是坏包。
	if len(pkt) < 20 {
		return info, fmt.Errorf("收到过短IP包，丢弃: %d bytes, 需要至少 20 bytes", len(pkt))
	}

	// 第 1 字节：高4位=版本，低4位=IHL(头长度，单位 4 字节)。
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
	// 255.255.255.255：全局广播
	if ip[0] == 0xff && ip[1] == 0xff && ip[2] == 0xff && ip[3] == 0xff {
		return true
	}
	// 子网定向广播（例如 192.168.1.255）
	if isSubnetBroadcast(ip, Conf.Common.Gateway, Conf.Common.SubnetMask) {
		return true
	}
	// 224.0.0.0 ~ 239.255.255.255：组播地址，按广播型流量处理。
	if ip[0] >= 224 && ip[0] <= 239 {
		return true
	}
	return false
}

func isSubnetBroadcast(dst []byte, gateway, mask string) bool {
	// 利用网关+掩码算出当前子网的广播地址，再和目标地址比较。
	gw := net.ParseIP(gateway).To4()
	m := net.ParseIP(mask).To4()
	if gw == nil || m == nil || len(dst) != 4 {
		return false
	}

	network := []byte{gw[0] & m[0], gw[1] & m[1], gw[2] & m[2], gw[3] & m[3]}
	broadcast := []byte{network[0] | ^m[0], network[1] | ^m[1], network[2] | ^m[2], network[3] | ^m[3]}
	return dst[0] == broadcast[0] && dst[1] == broadcast[1] && dst[2] == broadcast[2] && dst[3] == broadcast[3]
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

//=========================== 隧道帧格式与读写 ===========================

type PacketType uint8

const (
	PacketTypeIP PacketType = iota + 1
	PacketTypePing
	PacketTypePong
	PacketTypeVDHCP
	PacketTypeHandshakeInit
	PacketTypeHandshakeResp
	PacketTypeSecure
)

type TunnelFrame struct {
	Length   uint32
	Type     PacketType
	IPPacket []byte
}

const defaultReadFrameTimeout = 16 * time.Second

// readPacket 读包
func readFrame(conn net.Conn, maxPayloadSize int, timeout time.Duration) (*TunnelFrame, error) {
	// 协议格式：
	// [4字节长度][1字节Type][N字节Payload]
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}

	frameLen := binary.BigEndian.Uint32(lenBuf)
	if frameLen < 1 || frameLen > uint32(maxPayloadSize+1) {
		return nil, fmt.Errorf("invalid frame len: %d", frameLen)
	}

	raw := make([]byte, frameLen)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return nil, err
	}

	payload := raw[1:]
	frame := &TunnelFrame{
		// Length 只记录业务负载长度，不包含 Type 字节。
		Length:   uint32(len(payload)),
		Type:     PacketType(raw[0]),
		IPPacket: payload,
	}
	return frame, nil
}

// writePacket 写包
func writeFrame(conn net.Conn, packetType PacketType, payload []byte) error {
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(1+len(payload)))
	buf[4] = byte(packetType)
	copy(buf[5:], payload)
	return writeAll(conn, buf)
}

func writeAll(conn net.Conn, buf []byte) error {
	// net.Conn.Write 可能只写入部分字节，所以循环直到写完。
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

func maxFramePayload() int {
	// 为加密头/控制字段预留额外空间，避免边界溢出。
	return Conf.Common.MTU + 256
}

//=========================== TUN 读写 ===========================

// writeToTun 写网卡
func writeToTun(dev tun.Device, pkt []byte) error {
	fixIPv4Checksums(pkt)
	_, err := dev.Write([][]byte{pkt}, 0)
	return err
}

func readFromTun(dev tun.Device, mtu int) ([][]byte, error) {
	// BatchSize 表示底层驱动建议一次读取多少包，能减少系统调用次数。
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

	// 从复用 buffer 中拷贝出独立切片，避免后续被下一次 Read 覆盖。
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

func fixIPv4Checksums(pkt []byte) {
	if len(pkt) < 20 {
		return
	}

	version := pkt[0] >> 4
	if version != 4 {
		return
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return
	}

	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen <= 0 || totalLen > len(pkt) {
		totalLen = len(pkt)
	}
	if totalLen < ihl {
		return
	}

	// 修 IPv4 header checksum
	pkt[10] = 0
	pkt[11] = 0
	ipSum := checksum16(pkt[:ihl])
	binary.BigEndian.PutUint16(pkt[10:12], ipSum)

	proto := pkt[9]
	l4 := pkt[ihl:totalLen]

	switch proto {
	case 6: // TCP
		if len(l4) < 20 {
			return
		}
		l4[16] = 0
		l4[17] = 0
		sum := transportChecksumIPv4(pkt[12:16], pkt[16:20], proto, l4)
		binary.BigEndian.PutUint16(l4[16:18], sum)

	case 17: // UDP
		if len(l4) < 8 {
			return
		}
		l4[6] = 0
		l4[7] = 0
		sum := transportChecksumIPv4(pkt[12:16], pkt[16:20], proto, l4)

		// IPv4 UDP checksum 为 0 表示不校验，但我们这里主动填正确值
		if sum == 0 {
			sum = 0xffff
		}
		binary.BigEndian.PutUint16(l4[6:8], sum)
	}
}

func transportChecksumIPv4(src, dst []byte, proto byte, payload []byte) uint16 {
	pseudoLen := 12 + len(payload)
	buf := make([]byte, pseudoLen)

	copy(buf[0:4], src)
	copy(buf[4:8], dst)
	buf[8] = 0
	buf[9] = proto
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(payload)))
	copy(buf[12:], payload)

	return checksum16(buf)
}

func checksum16(data []byte) uint16 {
	var sum uint32

	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}

	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}

	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}
