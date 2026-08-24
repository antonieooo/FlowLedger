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

	tlsDirectionUnknown     = 0
	tlsDirectionClientHello = 1
	tlsDirectionServerHello = 2
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
	TimestampNS             uint64
	EventType               uint32
	PID                     uint32
	TGID                    uint32
	_                       uint32
	CgroupID                uint64
	NetnsIno                uint64
	Family                  uint16
	Protocol                uint8
	_                       uint8
	SrcIPv4                 uint32
	DstIPv4                 uint32
	SrcPort                 uint16
	DstPort                 uint16
	BytesSent               uint64
	BytesRecv               uint64
	PacketsSent             uint64
	PacketsRecv             uint64
	PktSizeBuckets          [7]uint64
	IATBuckets              [6]uint64
	PktSizeMin              uint64
	PktSizeMax              uint64
	IdleGapCount            uint64
	BurstCount              uint64
	RealPacketsSent         uint64
	RealPacketsRecv         uint64
	DirectionDurationNsSent uint64
	DirectionDurationNsRecv uint64
	NfIpSizeBuckets         [6]uint64
	RetransSkbCount         uint64
	RetransSkbBytes         uint64
	// v1alpha5 per-direction additions. Field ORDER here is the wire layout:
	// binary.Read is padding-blind, so every byte of struct flow_event —
	// including its explicit _pad members — must appear in order.
	// TestRawEBPFEventLayoutMatchesBTF checks this against the compiled BTF.
	PktSizeBucketsOut [7]uint64
	PktSizeBucketsIn  [7]uint64
	IATBucketsOut     [6]uint64
	IATBucketsIn      [6]uint64
	SYNCount          uint32
	FINCount          uint32
	RSTCount          uint32
	SYNCountOut       uint32
	SYNCountIn        uint32
	FINCountOut       uint32
	FINCountIn        uint32
	RSTCountOut       uint32
	RSTCountIn        uint32
	// Flags stay uint32 (the BPF side needs a 4-aligned 32-bit operand for
	// the atomic OR); window/tot_len are 16-bit wire fields, TTL is 8-bit.
	TcpFlagsOrSent             uint32
	TcpFlagsOrRecv             uint32
	TcpWinMaxSent              uint16
	TcpWinMaxRecv              uint16
	IpPktLenMin                uint16
	IpPktLenMax                uint16
	IpTtlMin                   uint8
	IpTtlMax                   uint8
	IpTtlMinOut                uint8
	IpTtlMaxOut                uint8
	IpTtlMinIn                 uint8
	IpTtlMaxIn                 uint8
	TrafficAccountingAvailable uint8
	PacketTimingAvailable      uint8
	TCPMetricsAvailable        uint8
	TcpHeaderObservedSent      uint8
	TcpHeaderObservedRecv      uint8
	_                          [9]uint8
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
	Data        [2048]byte
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

		IPTTLMin:    pointerIfNonZero32(uint32(raw.IpTtlMin)),
		IPTTLMax:    pointerIfNonZero32(uint32(raw.IpTtlMax)),
		TCPFlagsOut: raw.TcpFlagsOrSent,
		TCPFlagsIn:  raw.TcpFlagsOrRecv,
		// Per-direction observation comes exclusively from the kernel's
		// tcp_header_observed_* witness (set when the TCP byte-12..15 load
		// succeeded), NEVER inferred from flag/window values: a TCP NULL
		// scan (flags==0) or an all-zero-window direction must survive as an
		// observed 0, not collapse to null.
		TCPHeaderObservedOut:         raw.TcpHeaderObservedSent != 0,
		TCPHeaderObservedIn:          raw.TcpHeaderObservedRecv != 0,
		TCPWindowMaxOut:              u32IfObserved(uint32(raw.TcpWinMaxSent), raw.TcpHeaderObservedSent != 0),
		TCPWindowMaxIn:               u32IfObserved(uint32(raw.TcpWinMaxRecv), raw.TcpHeaderObservedRecv != 0),
		DirectionDurationOutNS:       raw.DirectionDurationNsSent,
		DirectionDurationInNS:        raw.DirectionDurationNsRecv,
		DirectionDurationOutObserved: raw.RealPacketsSent > 0,
		DirectionDurationInObserved:  raw.RealPacketsRecv > 0,
		IPPktLenMin:                  pointerIfNonZero32(uint32(raw.IpPktLenMin)),
		IPPktLenMax:                  pointerIfNonZero32(uint32(raw.IpPktLenMax)),

		// --- v1alpha5 per-direction split ---
		// The per-direction histograms are labelled from the SAME bucket-name
		// slices as the mixed ones above, so a bucket edge can never diverge
		// between the two: there is one label table per family, not three.
		PacketSizeHistogramOut: histogramFromArray(ebpfPacketSizeHistogramBuckets, raw.PktSizeBucketsOut[:]),
		PacketSizeHistogramIn:  histogramFromArray(ebpfPacketSizeHistogramBuckets, raw.PktSizeBucketsIn[:]),
		IATHistogramOut:        histogramFromArray(ebpfIATHistogramBuckets, raw.IATBucketsOut[:]),
		IATHistogramIn:         histogramFromArray(ebpfIATHistogramBuckets, raw.IATBucketsIn[:]),
		SYNCountOut:            uint64(raw.SYNCountOut),
		SYNCountIn:             uint64(raw.SYNCountIn),
		FINCountOut:            uint64(raw.FINCountOut),
		FINCountIn:             uint64(raw.FINCountIn),
		RSTCountOut:            uint64(raw.RSTCountOut),
		RSTCountIn:             uint64(raw.RSTCountIn),
		// TTL 0 is invalid on the wire, so 0 unambiguously means "this
		// direction never observed a packet" — same convention as the mixed
		// pair, hence the same pointerIfNonZero32 treatment and no
		// *_available companion flag.
		IPTTLMinOut: pointerIfNonZero32(uint32(raw.IpTtlMinOut)),
		IPTTLMaxOut: pointerIfNonZero32(uint32(raw.IpTtlMaxOut)),
		IPTTLMinIn:  pointerIfNonZero32(uint32(raw.IpTtlMinIn)),
		IPTTLMaxIn:  pointerIfNonZero32(uint32(raw.IpTtlMaxIn)),
		// Availability/source are NOT set here: only the collector knows
		// whether the tcp_retransmit_skb tracepoint actually attached.
		LocalRetransSKBCount:     raw.RetransSkbCount,
		LocalRetransSKBBytes:     raw.RetransSkbBytes,
		NetFlowV2IPSizeHistogram: histogramFromArray(netFlowV2IPSizeBucketLabels, raw.NfIpSizeBuckets[:]),

		// The BPF flow_stats entry is a per-flow monotonic accumulator; every
		// emitted event carries totals since flow start, so downstream
		// aggregation must not sum across events.
		CounterSemantics:         CounterSemanticsCumulative,
		ObservedSKBPacketsSource: ObservedSKBPacketsSourceCgroupSKB,
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
	ev := FlowEvent{
		TimestampNS: raw.TimestampNS,
		EventType:   "TLS_HANDSHAKE",
		SrcIP:       ipv4String(raw.SrcIPv4),
		SrcPort:     raw.SrcPort,
		DstIP:       ipv4String(raw.DstIPv4),
		DstPort:     raw.DstPort,
		Protocol:    "tcp",
	}
	switch raw.Direction {
	case tlsDirectionServerHello:
		info := ParseTLSServerHello(raw.Data[:capturedLen])
		ev.TLSHandshakeDirection = tlsDirectionServerHello
		ev.ServerHelloSeen = info.HandshakeSeen
		ev.TLSVersionNegotiated = info.TLSVersion
		ev.ALPNNegotiated = info.ALPN
		ev.JA4S = info.JA4S
		ev.TLSServerParseStatus = info.Status
	case tlsDirectionUnknown, tlsDirectionClientHello:
		info := ParseTLSClientHello(raw.Data[:capturedLen])
		ev.TLSHandshakeDirection = raw.Direction
		ev.HandshakeSeen = info.HandshakeSeen
		ev.TLSVersion = info.TLSVersion
		ev.SNIHash = info.SNIHash
		ev.ALPN = info.ALPN
		ev.JA4 = info.JA4
		ev.TLSParseStatus = info.Status
	default:
		info := ParseTLSClientHello(raw.Data[:capturedLen])
		ev.TLSHandshakeDirection = raw.Direction
		ev.HandshakeSeen = info.HandshakeSeen
		ev.TLSVersion = info.TLSVersion
		ev.SNIHash = info.SNIHash
		ev.ALPN = info.ALPN
		ev.JA4 = info.JA4
		ev.TLSParseStatus = info.Status
	}
	return ev
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

// netFlowV2IPSizeBucketLabels must stay in sync with the BPF
// nf_ip_size_bucket() edges and features.NetFlowV2IPSizeBuckets.
var netFlowV2IPSizeBucketLabels = []string{
	"<=128",
	"129-256",
	"257-512",
	"513-1024",
	"1025-1514",
	">1514",
}

func pointerIfNonZero(v uint64) *uint64 {
	if v == 0 {
		return nil
	}
	return &v
}

func pointerIfNonZero32(v uint32) *uint32 {
	if v == 0 {
		return nil
	}
	return &v
}

// u32IfObserved returns a pointer to the value only when the direction was
// actually observed (kernel tcp_header_observed_* witness); otherwise nil.
// A present value may legitimately be 0 — never fabricate a 0 for an
// unobserved direction, and never turn an observed 0 into null.
func u32IfObserved(v uint32, observed bool) *uint32 {
	if !observed {
		return nil
	}
	return &v
}
