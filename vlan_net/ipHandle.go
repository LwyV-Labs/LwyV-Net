package vlan_net

import (
	"fmt"
	"net"
)

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
