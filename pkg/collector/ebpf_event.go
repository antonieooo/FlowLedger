package collector

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	ebpfEventConnect = 1
	ebpfEventClose   = 2
	ebpfEventStats   = 3
	ebpfEventDrop    = 4

	ebpfFamilyIPv4  = 2
	ebpfProtocolTCP = 6
)

var ebpfPacketSizeHistogramBuckets = []string{
	"0-63",
	"64-127",
	"128-255",
	"256-511",
	"512-1023",
	"1024-1500",
	">1500",
}

var ebpfIATHistogramBuckets = []string{
	"<100",
	"100-1000",
	"1000-10000",
	"10000-100000",
	"100000-1000000",
	">1000000",
}

type rawEBPFEvent struct {
	TimestampNS                uint64
	EventType                  uint32
	PID                        uint32
	TGID                       uint32
	_                          uint32
	CgroupID                   uint64
	NetnsIno                   uint64
	Family                     uint16
	Protocol                   uint8
	_                          uint8
	SrcIPv4                    uint32
	DstIPv4                    uint32
	SrcPort                    uint16
	DstPort                    uint16
	BytesSent                  uint64
	BytesRecv                  uint64
	PacketsSent                uint64
	PacketsRecv                uint64
	PktSizeBuckets             [7]uint64
	IATBuckets                 [6]uint64
	PktSizeMin                 uint64
	PktSizeMax                 uint64
	IdleGapCount               uint64
	BurstCount                 uint64
	RealPacketsSent            uint64
	RealPacketsRecv            uint64
	SYNCount                   uint32
	FINCount                   uint32
	RSTCount                   uint32
	TrafficAccountingAvailable uint8
	PacketTimingAvailable      uint8
	TCPMetricsAvailable        uint8
	_                          uint8
}

type rawTLSHandshakeEvent struct {
	SrcIPv4     uint32
	DstIPv4     uint32
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	Direction   uint8
	_           uint16
	TimestampNS uint64
	PayloadLen  uint32
	CapturedLen uint32
	Data        [1024]byte
}

func convertRawEBPFEventToFlowEvent(raw rawEBPFEvent) (FlowEvent, error) {
	eventType, err := ebpfEventType(raw.EventType)
	if err != nil {
		return FlowEvent{}, err
	}
	if raw.Family != ebpfFamilyIPv4 {
		return FlowEvent{}, fmt.Errorf("unsupported ebpf address family %d", raw.Family)
	}
	if raw.Protocol != ebpfProtocolTCP {
		return FlowEvent{}, fmt.Errorf("unsupported ebpf protocol %d", raw.Protocol)
	}

	ev := FlowEvent{
		TimestampNS:                raw.TimestampNS,
		EventType:                  eventType,
		PID:                        raw.PID,
		TGID:                       raw.TGID,
		CgroupID:                   raw.CgroupID,
		NetnsIno:                   raw.NetnsIno,
		SrcIP:                      ipv4String(raw.SrcIPv4),
		SrcPort:                    raw.SrcPort,
		DstIP:                      ipv4String(raw.DstIPv4),
		DstPort:                    raw.DstPort,
		Protocol:                   "tcp",
		BytesSent:                  raw.BytesSent,
		BytesRecv:                  raw.BytesRecv,
		PacketsSent:                raw.PacketsSent,
		PacketsRecv:                raw.PacketsRecv,
		PacketSizeHistogram:        histogramFromArray(ebpfPacketSizeHistogramBuckets, raw.PktSizeBuckets[:]),
		IATHistogram:               histogramFromArray(ebpfIATHistogramBuckets, raw.IATBuckets[:]),
		PktSizeMin:                 pointerIfNonZero(raw.PktSizeMin),
		PktSizeMax:                 pointerIfNonZero(raw.PktSizeMax),
		IdleGapCount:               raw.IdleGapCount,
		BurstCount:                 raw.BurstCount,
		RealPacketsSent:            raw.RealPacketsSent,
		RealPacketsRecv:            raw.RealPacketsRecv,
		SYNCount:                   uint64(raw.SYNCount),
		FINCount:                   uint64(raw.FINCount),
		RSTCount:                   uint64(raw.RSTCount),
		TrafficAccountingAvailable: raw.TrafficAccountingAvailable != 0,
		PacketTimingAvailable:      raw.PacketTimingAvailable != 0,
		TCPMetricsAvailable:        raw.TCPMetricsAvailable != 0,
	}
	switch eventType {
	case "CONNECT":
		ev.TCPState = "established"
	case "CLOSE":
		ev.TCPState = "close"
		ev.CloseReason = "unknown"
	case "DROP":
		ev.DropReason = "ebpf_drop_counter"
	}
	return ev, nil
}

func convertRawTLSHandshakeEventToFlowEvent(raw rawTLSHandshakeEvent) FlowEvent {
	capturedLen := int(raw.CapturedLen)
	if capturedLen > len(raw.Data) {
		capturedLen = len(raw.Data)
	}
	info := ParseTLSClientHello(raw.Data[:capturedLen])
	return FlowEvent{
		TimestampNS:    raw.TimestampNS,
		EventType:      "TLS_HANDSHAKE",
		SrcIP:          ipv4String(raw.SrcIPv4),
		SrcPort:        raw.SrcPort,
		DstIP:          ipv4String(raw.DstIPv4),
		DstPort:        raw.DstPort,
		Protocol:       "tcp",
		HandshakeSeen:  info.HandshakeSeen,
		TLSVersion:     info.TLSVersion,
		SNIHash:        info.SNIHash,
		ALPN:           info.ALPN,
		JA4:            info.JA4,
		TLSParseStatus: info.Status,
	}
}

func ebpfEventType(rawType uint32) (string, error) {
	switch rawType {
	case ebpfEventConnect:
		return "CONNECT", nil
	case ebpfEventClose:
		return "CLOSE", nil
	case ebpfEventStats:
		return "STATS", nil
	case ebpfEventDrop:
		return "DROP", nil
	default:
		return "", fmt.Errorf("unknown ebpf event type %d", rawType)
	}
}

func ipv4String(raw uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], raw)
	return netip.AddrFrom4(b).String()
}

func histogramFromArray(labels []string, values []uint64) map[string]uint64 {
	hasValues := false
	for _, value := range values {
		if value != 0 {
			hasValues = true
			break
		}
	}
	if !hasValues {
		return nil
	}
	out := make(map[string]uint64, len(labels))
	for i, label := range labels {
		if i < len(values) {
			out[label] = values[i]
		} else {
			out[label] = 0
		}
	}
	return out
}

func pointerIfNonZero(v uint64) *uint64 {
	if v == 0 {
		return nil
	}
	return &v
}
