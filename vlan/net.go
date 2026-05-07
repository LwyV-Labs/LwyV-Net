package vlan

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/secure"
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
const maxPayloadSize = 4096

// readPacket 读包
func readFrame(conn net.Conn) (*TunnelFrame, error) {
	// 协议格式：
	// [4字节长度][1字节Type][N字节Payload]
	_ = conn.SetReadDeadline(time.Now().Add(defaultReadFrameTimeout))

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}

	frameLen := binary.BigEndian.Uint32(lenBuf)
	if frameLen < 1 || frameLen > uint32(maxPayloadSize) {
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
