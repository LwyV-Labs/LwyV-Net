package vlan

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/secure"

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

//=========================== TCP，KCP 配置与读写 ===========================

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

// writeSecureFrame 写加密帧
func writeSecureFrame(conn net.Conn, sessionMgr *secure.SessionManager, packetType PacketType, payload []byte) error {
	s := sessionMgr.Current()
	if s == nil {
		return fmt.Errorf("no active session")
	}
	sealed, err := s.Encrypt(byte(packetType), payload)
	if err != nil {
		return err
	}
	return writeFrame(conn, PacketTypeSecure, sealed)
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

func (t *TUNTunnel) ReadBatch() ([][]byte, error) {
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

func (t *TUNTunnel) Write(pkt []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writeBufs[0] = pkt
	_, err := t.dev.Write(t.writeBufs, 0)
	return err
}

func (t *TUNTunnel) WriteBatch(packets [][]byte) (int, error) {
	return t.dev.Write(packets, 0)
}
