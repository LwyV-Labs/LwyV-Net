package vlan

import (
	"encoding/binary"
	"fmt"
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
const udpPacketBufferSize = 64 * 1024

const (
	// Conf.Common.MTU 的语义：最外层单个 UDP 发送报文的总长度上限（含外层 IP+UDP 头）。
	defaultOuterPacketMTU = 1400

	// 外层开销（IPv4 + UDP）。
	outerIPv4HeaderBytes        = 20
	outerUDPHeaderBytes         = 8
	outerTransportOverheadBytes = outerIPv4HeaderBytes + outerUDPHeaderBytes

	// 隧道帧开销：[4字节Length][1字节Type]。
	tunnelFrameHeaderBytes = 5

	// 安全层开销（secure/session.go）：
	// Encrypt 输出 = 13字节头(keyID+counter+innerType) + AEAD密文(含16字节Tag)。
	secureHeaderBytes   = 13
	secureAEADTagBytes  = 16
	secureOverheadBytes = secureHeaderBytes + secureAEADTagBytes

	// TUN 三层报文的保底 MTU（避免配置过小导致异常）。
	minInnerIPMTU = 576
)

func configuredOuterPacketMTU() int {
	mtu := Conf.Common.MTU
	if mtu <= 0 {
		mtu = defaultOuterPacketMTU
	}
	return mtu
}

func securePayloadMTU() int {
	// 最大 TunnelFrame.Payload（即 UDP 数据中的业务负载）：
	// outer_total - outer(IP+UDP) - frame_header
	mtu := configuredOuterPacketMTU() - outerTransportOverheadBytes - tunnelFrameHeaderBytes
	if mtu < 1 {
		return 1
	}
	return mtu
}

func tunPayloadMTU() int {
	// 最大原始 IP 负载（TUN 侧）：
	// secure_payload_mtu - secure_overhead
	//
	// 分层关系（从外到内）：
	// 1) Conf.Common.MTU：外层总包大小
	// 2) 减去外层 IP/UDP 头
	// 3) 减去 TunnelFrame 头，得到 frame payload 上限
	// 4) 安全数据帧还需减去加密层开销，得到可承载原始 IP 报文的最大长度（TUN MTU）
	payloadMTU := securePayloadMTU() - secureOverheadBytes
	if payloadMTU < minInnerIPMTU {
		payloadMTU = minInnerIPMTU
	}
	return payloadMTU
}

func decodeFrame(datagram []byte) (*TunnelFrame, error) {
	// 协议格式：
	// [4字节长度][1字节Type][N字节Payload]
	if len(datagram) < 5 {
		return nil, fmt.Errorf("frame too short: %d", len(datagram))
	}
	frameLen := binary.BigEndian.Uint32(datagram[:4])
	if frameLen < 1 || frameLen > uint32(maxFramePayload()+1) {
		return nil, fmt.Errorf("invalid frame len: %d", frameLen)
	}
	if int(frameLen)+4 != len(datagram) {
		return nil, fmt.Errorf("frame size mismatch: header=%d actual=%d", frameLen, len(datagram)-4)
	}
	raw := datagram[4:]
	payload := raw[1:]
	frame := &TunnelFrame{
		// Length 只记录业务负载长度，不包含 Type 字节。
		Length:   uint32(len(payload)),
		Type:     PacketType(raw[0]),
		IPPacket: payload,
	}
	return frame, nil
}

func encodeFrame(packetType PacketType, payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(1+len(payload)))
	buf[4] = byte(packetType)
	copy(buf[5:], payload)
	return buf
}

func readUDPFrame(conn *net.UDPConn) (*TunnelFrame, error) {
	_ = conn.SetReadDeadline(time.Now().Add(defaultReadFrameTimeout))
	buf := make([]byte, udpPacketBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return decodeFrame(buf[:n])
}

func writeUDPFrame(conn *net.UDPConn, packetType PacketType, payload []byte) error {
	_, err := conn.Write(encodeFrame(packetType, payload))
	return err
}

func writeUDPFrameTo(conn *net.UDPConn, remote *net.UDPAddr, packetType PacketType, payload []byte) error {
	_, err := conn.WriteToUDP(encodeFrame(packetType, payload), remote)
	return err
}

func maxFramePayload() int {
	// TunnelFrame.Payload 的协议上限（用于解码校验）。
	// 对于 PacketTypeSecure，它对应密文长度上限；
	// 对于控制帧，它是统一的 payload 上限。
	return securePayloadMTU()
}

//=========================== TUN 读写 ===========================

// writeToTun 写网卡
func writeToTun(dev tun.Device, pkt []byte) error {
	_, err := dev.Write([][]byte{pkt}, 0)
	return err
}

func readFromTun(dev tun.Device) ([][]byte, error) {
	// BatchSize 表示底层驱动建议一次读取多少包，能减少系统调用次数。
	batchSize := dev.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	mtu := tunPayloadMTU()

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
