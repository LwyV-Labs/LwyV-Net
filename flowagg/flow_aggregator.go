package flowagg

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"sync"
	"time"
)

type FlowKey struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

type FeatureJSON struct {
	FlowID string `json:"flow_id"`

	Features map[string]float64 `json:"features"`
}

type Aggregator struct {
	mu sync.Mutex

	flows map[FlowKey]*FlowState

	Window     time.Duration
	IdleTTL    time.Duration
	MaxPackets int
}

type FlowState struct {
	Key FlowKey

	FirstSeen time.Time
	LastSeen  time.Time

	Proto uint8

	HeaderLengthSum float64
	TTLSum          float64

	PacketCount int
	TotalSize   float64
	MinSize     float64
	MaxSize     float64

	MeanSize float64
	M2Size   float64

	TotalIAT float64
	IATCount int

	FinCount int
	SynCount int
	RstCount int
	PshCount int
	AckCount int
	EceCount int
	CwrCount int

	HTTP   float64
	HTTPS  float64
	DNS    float64
	Telnet float64
	SMTP   float64
	SSH    float64
	IRC    float64
	DHCP   float64
}

type ParsedPacket struct {
	SrcIP netip.Addr
	DstIP netip.Addr

	SrcPort uint16
	DstPort uint16

	Proto uint8
	TTL   uint8

	IPHeaderLen        int
	TransportHeaderLen int
	TotalLen           int

	Fin bool
	Syn bool
	Rst bool
	Psh bool
	Ack bool
	Ece bool
	Cwr bool
}

func NewAggregator(window time.Duration, idleTTL time.Duration, maxPackets int) *Aggregator {
	return &Aggregator{
		flows:      make(map[FlowKey]*FlowState),
		Window:     window,
		IdleTTL:    idleTTL,
		MaxPackets: maxPackets,
	}
}

func MakeBidirectionalKey(pp ParsedPacket) FlowKey {
	srcIP := pp.SrcIP
	dstIP := pp.DstIP
	srcPort := pp.SrcPort
	dstPort := pp.DstPort

	// 用字符串比较，简单稳定。
	// 规则：较小的一端放前面，较大的一端放后面。
	srcEndpoint := srcIP.String() + ":" + uint16ToString(srcPort)
	dstEndpoint := dstIP.String() + ":" + uint16ToString(dstPort)

	if srcEndpoint > dstEndpoint {
		return FlowKey{
			SrcIP:   dstIP,
			DstIP:   srcIP,
			SrcPort: dstPort,
			DstPort: srcPort,
			Proto:   pp.Proto,
		}
	}

	return FlowKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   pp.Proto,
	}
}

func (a *Aggregator) AddIPv4Packet(pkt []byte, now time.Time) ([]FeatureJSON, error) {
	pp, err := ParseIPv4Packet(pkt)
	if err != nil {
		return nil, err
	}

	key := MakeBidirectionalKey(pp)

	a.mu.Lock()
	defer a.mu.Unlock()

	st := a.flows[key]
	if st == nil {
		st = &FlowState{
			Key:       key,
			FirstSeen: now,
			LastSeen:  now,
			Proto:     pp.Proto,
			MinSize:   float64(pp.TotalLen),
			MaxSize:   float64(pp.TotalLen),
		}
		a.flows[key] = st
	}

	st.Update(pp, now)

	shouldFlush := false

	if now.Sub(st.FirstSeen) >= a.Window {
		shouldFlush = true
	}

	if a.MaxPackets > 0 && st.PacketCount >= a.MaxPackets {
		shouldFlush = true
	}

	if shouldFlush {
		if st.PacketCount < 3 {
			delete(a.flows, key)
			return nil, nil
		}

		feature := st.ToFeatureJSON()
		delete(a.flows, key)
		return []FeatureJSON{feature}, nil
	}

	return nil, nil
}

func (a *Aggregator) FlushIdle(now time.Time) []FeatureJSON {
	a.mu.Lock()
	defer a.mu.Unlock()

	var outputs []FeatureJSON

	for key, st := range a.flows {
		if now.Sub(st.LastSeen) >= a.IdleTTL {
			if st.PacketCount >= 3 {
				outputs = append(outputs, st.ToFeatureJSON())
			}
			delete(a.flows, key)
		}
	}

	return outputs
}

func (s *FlowState) Update(pp ParsedPacket, now time.Time) {
	if s.PacketCount > 0 {
		iat := now.Sub(s.LastSeen).Seconds()
		if iat >= 0 {
			s.TotalIAT += iat
			s.IATCount++
		}
	}

	s.LastSeen = now

	packetSize := float64(pp.TotalLen)

	s.PacketCount++
	s.TotalSize += packetSize

	if packetSize < s.MinSize {
		s.MinSize = packetSize
	}

	if packetSize > s.MaxSize {
		s.MaxSize = packetSize
	}

	// Welford 在线均值/方差
	delta := packetSize - s.MeanSize
	s.MeanSize += delta / float64(s.PacketCount)
	delta2 := packetSize - s.MeanSize
	s.M2Size += delta * delta2

	s.HeaderLengthSum += float64(pp.IPHeaderLen + pp.TransportHeaderLen)
	s.TTLSum += float64(pp.TTL)

	if pp.Fin {
		s.FinCount++
	}
	if pp.Syn {
		s.SynCount++
	}
	if pp.Rst {
		s.RstCount++
	}
	if pp.Psh {
		s.PshCount++
	}
	if pp.Ack {
		s.AckCount++
	}
	if pp.Ece {
		s.EceCount++
	}
	if pp.Cwr {
		s.CwrCount++
	}

	updateAppProtocolFlags(s, pp)
}

func (s *FlowState) ToFeatureJSON() FeatureJSON {

	duration := s.LastSeen.Sub(s.FirstSeen).Seconds()

	if duration <= 0 || s.PacketCount < 2 {
		duration = 1.0
	}

	avgTTL := 0.0
	if s.PacketCount > 0 {
		avgTTL = s.TTLSum / float64(s.PacketCount)
	}

	std := 0.0
	variance := 0.0

	if s.PacketCount > 1 {
		variance = s.M2Size / float64(s.PacketCount-1)
		std = math.Sqrt(variance)
	}

	avgIAT := 0.0
	if s.IATCount > 0 {
		avgIAT = s.TotalIAT / float64(s.IATCount)
	}

	proto := float64(s.Proto)

	tcp := 0.0
	udp := 0.0
	icmp := 0.0
	igmp := 0.0

	switch s.Proto {
	case 6:
		tcp = 1
	case 17:
		udp = 1
	case 1:
		icmp = 1
	case 2:
		igmp = 1
	}

	headerLength := 0.0
	if s.PacketCount > 0 {
		headerLength = s.HeaderLengthSum / float64(s.PacketCount)
	}

	totSize := s.MeanSize

	features := map[string]float64{
		"Header_Length": headerLength,
		"Protocol Type": proto,
		"Time_To_Live":  avgTTL,
		"Rate":          float64(s.PacketCount) / duration,

		"fin_flag_number": boolToFloat(s.FinCount > 0),
		"syn_flag_number": boolToFloat(s.SynCount > 0),
		"rst_flag_number": boolToFloat(s.RstCount > 0),
		"psh_flag_number": boolToFloat(s.PshCount > 0),
		"ack_flag_number": boolToFloat(s.AckCount > 0),
		"ece_flag_number": boolToFloat(s.EceCount > 0),
		"cwr_flag_number": boolToFloat(s.CwrCount > 0),

		"ack_count": float64(s.AckCount),
		"syn_count": float64(s.SynCount),
		"fin_count": float64(s.FinCount),
		"rst_count": float64(s.RstCount),

		"HTTP":   s.HTTP,
		"HTTPS":  s.HTTPS,
		"DNS":    s.DNS,
		"Telnet": s.Telnet,
		"SMTP":   s.SMTP,
		"SSH":    s.SSH,
		"IRC":    s.IRC,

		"TCP":  tcp,
		"UDP":  udp,
		"DHCP": s.DHCP,
		"ARP":  0,
		"ICMP": icmp,
		"IGMP": igmp,
		"IPv":  1,
		"LLC":  0,

		"Tot sum":  s.TotalSize,
		"Min":      s.MinSize,
		"Max":      s.MaxSize,
		"AVG":      s.MeanSize,
		"Std":      std,
		"Tot size": totSize,
		"IAT":      avgIAT,
		"Number":   float64(s.PacketCount),
		"Variance": variance,
	}

	flowID := s.Key.SrcIP.String() + ":" + uint16ToString(s.Key.SrcPort) +
		"->" + s.Key.DstIP.String() + ":" + uint16ToString(s.Key.DstPort) +
		"/" + uint8ToString(s.Key.Proto)

	return FeatureJSON{
		FlowID:   flowID,
		Features: features,
	}
}

func ParseIPv4Packet(pkt []byte) (ParsedPacket, error) {
	if len(pkt) < 20 {
		return ParsedPacket{}, errors.New("packet too short")
	}

	version := pkt[0] >> 4
	if version != 4 {
		return ParsedPacket{}, errors.New("not ipv4")
	}

	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return ParsedPacket{}, errors.New("invalid ipv4 header length")
	}

	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen <= 0 || totalLen > len(pkt) {
		totalLen = len(pkt)
	}

	ttl := pkt[8]
	proto := pkt[9]

	srcIP := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
	dstIP := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})

	pp := ParsedPacket{
		SrcIP:       srcIP,
		DstIP:       dstIP,
		Proto:       proto,
		TTL:         ttl,
		IPHeaderLen: ihl,
		TotalLen:    totalLen,
	}

	l4 := pkt[ihl:totalLen]

	switch proto {
	case 6: // TCP
		if len(l4) < 20 {
			return ParsedPacket{}, errors.New("tcp packet too short")
		}

		pp.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		pp.DstPort = binary.BigEndian.Uint16(l4[2:4])

		dataOffset := int(l4[12]>>4) * 4
		if dataOffset < 20 || dataOffset > len(l4) {
			dataOffset = 20
		}
		pp.TransportHeaderLen = dataOffset

		flags := l4[13]
		pp.Fin = flags&0x01 != 0
		pp.Syn = flags&0x02 != 0
		pp.Rst = flags&0x04 != 0
		pp.Psh = flags&0x08 != 0
		pp.Ack = flags&0x10 != 0
		pp.Ece = flags&0x40 != 0
		pp.Cwr = flags&0x80 != 0

	case 17: // UDP
		if len(l4) < 8 {
			return ParsedPacket{}, errors.New("udp packet too short")
		}

		pp.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		pp.DstPort = binary.BigEndian.Uint16(l4[2:4])
		pp.TransportHeaderLen = 8

	case 1: // ICMP
		pp.TransportHeaderLen = 8

	case 2: // IGMP
		pp.TransportHeaderLen = 8

	default:
		pp.TransportHeaderLen = 0
	}

	return pp, nil
}

func updateAppProtocolFlags(s *FlowState, pp ParsedPacket) {
	sp := pp.SrcPort
	dp := pp.DstPort

	hasPort := func(port uint16) bool {
		return sp == port || dp == port
	}

	switch {
	case hasPort(80) || hasPort(8080):
		s.HTTP = 1
	case hasPort(443):
		s.HTTPS = 1
	case hasPort(53):
		s.DNS = 1
	case hasPort(23):
		s.Telnet = 1
	case hasPort(25):
		s.SMTP = 1
	case hasPort(22):
		s.SSH = 1
	case hasPort(194):
		s.IRC = 1
	}

	if pp.Proto == 17 {
		if hasPort(67) || hasPort(68) {
			s.DHCP = 1
		}
	}
}

func boolToFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func uint16ToString(v uint16) string {
	return fmtUint(uint64(v))
}

func uint8ToString(v uint8) string {
	return fmtUint(uint64(v))
}

func fmtUint(v uint64) string {
	if v == 0 {
		return "0"
	}

	var buf [20]byte
	i := len(buf)

	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}

	return string(buf[i:])
}
