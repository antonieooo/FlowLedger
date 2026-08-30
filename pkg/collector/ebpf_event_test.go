package collector

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestRawTLSHandshakeEventBinarySize(t *testing.T) {
	const want = uintptr(2080)
	if got := unsafe.Sizeof(rawTLSHandshakeEvent{}); got != want {
		t.Fatalf("rawTLSHandshakeEvent size = %d, want %d", got, want)
	}
}

func TestConvertRawEBPFEventIPv4Connect(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		TimestampNS: 123,
		EventType:   ebpfEventConnect,
		PID:         10,
		TGID:        20,
		CgroupID:    30,
		Family:      ebpfFamilyIPv4,
		Protocol:    ebpfProtocolTCP,
		SrcIPv4:     ipv4Raw(10, 244, 1, 10),
		DstIPv4:     ipv4Raw(10, 96, 0, 10),
		SrcPort:     43120,
		DstPort:     443,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent: %v", err)
	}
	if ev.EventType != "CONNECT" || ev.SrcIP != "10.244.1.10" || ev.DstIP != "10.96.0.10" || ev.Protocol != "tcp" {
		t.Fatalf("unexpected event: %#v", ev)
	}
	if ev.TCPState != "established" {
		t.Fatalf("TCPState = %q, want established", ev.TCPState)
	}
	if ev.SrcPort != 43120 || ev.DstPort != 443 || ev.PID != 10 || ev.TGID != 20 || ev.CgroupID != 30 {
		t.Fatalf("unexpected metadata: %#v", ev)
	}
}

func TestConvertRawEBPFEventClose(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType: ebpfEventClose,
		Family:    ebpfFamilyIPv4,
		Protocol:  ebpfProtocolTCP,
		SrcIPv4:   ipv4Raw(10, 244, 1, 10),
		DstIPv4:   ipv4Raw(10, 96, 0, 10),
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent: %v", err)
	}
	if ev.EventType != "CLOSE" || ev.TCPState != "close" || ev.CloseReason != "unknown" {
		t.Fatalf("EventType = %q, want CLOSE", ev.EventType)
	}
}

func TestConvertRawEBPFEventStats(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType:                  ebpfEventStats,
		Family:                     ebpfFamilyIPv4,
		Protocol:                   ebpfProtocolTCP,
		SrcIPv4:                    ipv4Raw(10, 244, 1, 10),
		DstIPv4:                    ipv4Raw(10, 96, 0, 10),
		SrcPort:                    43120,
		DstPort:                    443,
		BytesSent:                  1000,
		BytesRecv:                  2000,
		PacketsSent:                3,
		PacketsRecv:                4,
		PktSizeBuckets:             [7]uint64{1, 2, 3, 4, 5, 6, 7},
		IATBuckets:                 [6]uint64{8, 9, 10, 11, 12, 13},
		PktSizeMin:                 60,
		PktSizeMax:                 1500,
		IdleGapCount:               2,
		BurstCount:                 3,
		RealPacketsSent:            9,
		RealPacketsRecv:            10,
		SYNCount:                   1,
		TrafficAccountingAvailable: 1,
		PacketTimingAvailable:      1,
		TCPMetricsAvailable:        1,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent: %v", err)
	}
	if ev.EventType != "STATS" || ev.BytesSent != 1000 || ev.BytesRecv != 2000 || ev.PacketsSent != 3 || ev.PacketsRecv != 4 {
		t.Fatalf("unexpected stats event: %#v", ev)
	}
	if !ev.TrafficAccountingAvailable || !ev.PacketTimingAvailable || !ev.TCPMetricsAvailable || ev.SYNCount != 1 {
		t.Fatalf("unexpected availability flags: %#v", ev)
	}
	if ev.PacketSizeHistogram["0-63"] != 1 || ev.PacketSizeHistogram[">1500"] != 7 {
		t.Fatalf("unexpected packet size histogram: %#v", ev.PacketSizeHistogram)
	}
	if ev.IATHistogram["<100"] != 8 || ev.IATHistogram[">1000000"] != 13 {
		t.Fatalf("unexpected iat histogram: %#v", ev.IATHistogram)
	}
	if ev.PktSizeMin == nil || *ev.PktSizeMin != 60 || ev.PktSizeMax == nil || *ev.PktSizeMax != 1500 {
		t.Fatalf("unexpected packet size min/max: min=%v max=%v", ev.PktSizeMin, ev.PktSizeMax)
	}
	if ev.IdleGapCount != 2 || ev.BurstCount != 3 || ev.RealPacketsSent != 9 || ev.RealPacketsRecv != 10 {
		t.Fatalf("unexpected packet counters: %#v", ev)
	}
}

func TestConvertRawEBPFEventTrafficAccountingFlags(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType: ebpfEventStats,
		Family:    ebpfFamilyIPv4,
		Protocol:  ebpfProtocolTCP,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent false flag: %v", err)
	}
	if ev.TrafficAccountingAvailable {
		t.Fatalf("TrafficAccountingAvailable = true, want false")
	}

	ev, err = convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType:                  ebpfEventStats,
		Family:                     ebpfFamilyIPv4,
		Protocol:                   ebpfProtocolTCP,
		TrafficAccountingAvailable: 1,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent true flag: %v", err)
	}
	if !ev.TrafficAccountingAvailable {
		t.Fatalf("TrafficAccountingAvailable = false, want true")
	}
}

func TestConvertRawEBPFEventUnknownType(t *testing.T) {
	if _, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType: 99,
		Family:    ebpfFamilyIPv4,
		Protocol:  ebpfProtocolTCP,
	}); err == nil {
		t.Fatal("expected error for unknown event type")
	}
}

func TestConvertRawEBPFEventDrop(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType: ebpfEventDrop,
		Family:    ebpfFamilyIPv4,
		Protocol:  ebpfProtocolTCP,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent drop: %v", err)
	}
	if ev.EventType != "DROP" {
		t.Fatalf("EventType = %q, want DROP", ev.EventType)
	}
}

func TestConvertRawTLSHandshakeEvent(t *testing.T) {
	hello := buildClientHelloForTest(clientHelloSpec{
		sni:               "Example.COM",
		alpn:              "h2",
		supportedVersions: []uint16{0x0304},
		ciphers:           []uint16{0x1301, 0x1302},
		extensions:        []uint16{0x0000, 0x0010, 0x002b},
	})
	var data [2048]byte
	copy(data[:], hello)
	ev := convertRawTLSHandshakeEventToFlowEvent(rawTLSHandshakeEvent{
		SrcIPv4:     ipv4Raw(10, 244, 1, 10),
		DstIPv4:     ipv4Raw(93, 184, 216, 34),
		SrcPort:     43120,
		DstPort:     443,
		Protocol:    ebpfProtocolTCP,
		TimestampNS: 123,
		PayloadLen:  uint32(len(hello)),
		CapturedLen: uint32(len(hello)),
		Data:        data,
	})
	if ev.EventType != "TLS_HANDSHAKE" || !ev.HandshakeSeen || ev.TLSParseStatus != TLSParseStatusParsed {
		t.Fatalf("unexpected tls event: %#v", ev)
	}
	if ev.SrcIP != "10.244.1.10" || ev.DstIP != "93.184.216.34" || ev.SNIHash != "a379a6f6eeafb9a5" || ev.ALPN != "h2" || ev.JA4 == "" {
		t.Fatalf("unexpected tls fields: %#v", ev)
	}
}

func TestConvertRawTLSServerHelloEvent(t *testing.T) {
	hello := mustDecodeHex(t, "160303005b020000570303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f130100000f002b00020304001000050003026832")
	var data [2048]byte
	copy(data[:], hello)
	ev := convertRawTLSHandshakeEventToFlowEvent(rawTLSHandshakeEvent{
		SrcIPv4:     ipv4Raw(10, 244, 1, 10),
		DstIPv4:     ipv4Raw(93, 184, 216, 34),
		SrcPort:     43120,
		DstPort:     443,
		Protocol:    ebpfProtocolTCP,
		Direction:   tlsDirectionServerHello,
		TimestampNS: 123,
		PayloadLen:  uint32(len(hello)),
		CapturedLen: uint32(len(hello)),
		Data:        data,
	})
	if ev.EventType != "TLS_HANDSHAKE" || !ev.ServerHelloSeen || ev.TLSServerParseStatus != TLSParseStatusParsed {
		t.Fatalf("unexpected tls server event: %#v", ev)
	}
	if ev.JA4 != "" || ev.SNIHash != "" || ev.JA4S != "t1302h2_1301_14e9539264dc" || ev.TLSVersionNegotiated != "1.3" {
		t.Fatalf("unexpected tls server fields: %#v", ev)
	}
}

func ipv4Raw(a, b, c, d byte) uint32 {
	return binary.LittleEndian.Uint32([]byte{a, b, c, d})
}

// Every converted eBPF flow event must declare cumulative counter semantics
// and the cgroup_skb provenance of its skb-level packet counts — downstream
// aggregation depends on this marking to avoid re-summing snapshots.
func TestConvertRawEBPFEventMarksCumulativeSemantics(t *testing.T) {
	for _, eventType := range []uint32{ebpfEventConnect, ebpfEventClose, ebpfEventStats} {
		ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
			EventType: eventType,
			Family:    ebpfFamilyIPv4,
			Protocol:  ebpfProtocolTCP,
		})
		if err != nil {
			t.Fatalf("convertRawEBPFEventToFlowEvent(type=%d): %v", eventType, err)
		}
		if ev.CounterSemantics != CounterSemanticsCumulative {
			t.Fatalf("type=%d CounterSemantics = %q, want cumulative", eventType, ev.CounterSemantics)
		}
		if ev.ObservedSKBPacketsSource != ObservedSKBPacketsSourceCgroupSKB {
			t.Fatalf("type=%d ObservedSKBPacketsSource = %q, want cgroup_skb", eventType, ev.ObservedSKBPacketsSource)
		}
	}
}

// The C struct flow_event in bpf/flow_events.bpf.c and rawEBPFEvent must stay
// byte-identical: 320 bytes through retrans_skb_bytes + v1alpha5's 208 bytes
// of per-direction histograms (2×7 + 2×6 u64) = 528 + 11×4 (syn/fin/rst,
// their 6 per-direction counterparts, and 2 flag OR-masks, u32) = 572 + 4×2
// (window/ip-length, u16) = 580 + 11×1 (2 mixed TTL + 4 per-direction TTL +
// 3 availability + 2 tcp_header_observed, u8) + 9 explicit pad = 600.
func TestRawEBPFEventBinarySize(t *testing.T) {
	const want = uintptr(600)
	if got := unsafe.Sizeof(rawEBPFEvent{}); got != want {
		t.Fatalf("rawEBPFEvent size = %d, want %d", got, want)
	}
}

// Key offsets of rawEBPFEvent, hand-computed from the C layout of flow_event.
// TestRawEBPFEventLayoutMatchesBTF cross-checks the same offsets against the
// compiled object's BTF; this test keeps failing loudly even on builds where
// the BTF-carrying object is unavailable.
func TestRawEBPFEventKeyOffsets(t *testing.T) {
	raw := rawEBPFEvent{}
	for _, tc := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		// v1alpha5 inserts the four per-direction histograms immediately
		// after retrans_skb_bytes (offset 320), which shifts everything
		// below by 208 bytes.
		{"PktSizeBucketsOut", unsafe.Offsetof(raw.PktSizeBucketsOut), 320},
		{"PktSizeBucketsIn", unsafe.Offsetof(raw.PktSizeBucketsIn), 376},
		{"IATBucketsOut", unsafe.Offsetof(raw.IATBucketsOut), 432},
		{"IATBucketsIn", unsafe.Offsetof(raw.IATBucketsIn), 480},
		{"SYNCount", unsafe.Offsetof(raw.SYNCount), 528},
		{"SYNCountOut", unsafe.Offsetof(raw.SYNCountOut), 540},
		{"SYNCountIn", unsafe.Offsetof(raw.SYNCountIn), 544},
		{"FINCountOut", unsafe.Offsetof(raw.FINCountOut), 548},
		{"FINCountIn", unsafe.Offsetof(raw.FINCountIn), 552},
		{"RSTCountOut", unsafe.Offsetof(raw.RSTCountOut), 556},
		{"RSTCountIn", unsafe.Offsetof(raw.RSTCountIn), 560},
		// Flags stay u32 at 4-aligned offsets (atomic OR operand requirement).
		{"TcpFlagsOrSent", unsafe.Offsetof(raw.TcpFlagsOrSent), 564},
		{"TcpFlagsOrRecv", unsafe.Offsetof(raw.TcpFlagsOrRecv), 568},
		{"TcpWinMaxSent", unsafe.Offsetof(raw.TcpWinMaxSent), 572},
		{"TcpWinMaxRecv", unsafe.Offsetof(raw.TcpWinMaxRecv), 574},
		{"IpPktLenMin", unsafe.Offsetof(raw.IpPktLenMin), 576},
		{"IpPktLenMax", unsafe.Offsetof(raw.IpPktLenMax), 578},
		{"IpTtlMin", unsafe.Offsetof(raw.IpTtlMin), 580},
		{"IpTtlMax", unsafe.Offsetof(raw.IpTtlMax), 581},
		{"IpTtlMinOut", unsafe.Offsetof(raw.IpTtlMinOut), 582},
		{"IpTtlMaxOut", unsafe.Offsetof(raw.IpTtlMaxOut), 583},
		{"IpTtlMinIn", unsafe.Offsetof(raw.IpTtlMinIn), 584},
		{"IpTtlMaxIn", unsafe.Offsetof(raw.IpTtlMaxIn), 585},
		{"TrafficAccountingAvailable", unsafe.Offsetof(raw.TrafficAccountingAvailable), 586},
		{"TcpHeaderObservedSent", unsafe.Offsetof(raw.TcpHeaderObservedSent), 589},
		{"TcpHeaderObservedRecv", unsafe.Offsetof(raw.TcpHeaderObservedRecv), 590},
	} {
		if tc.got != tc.want {
			t.Errorf("offsetof(%s) = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

func TestConvertRawEBPFEventP1HeaderAggregates(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType:               ebpfEventStats,
		Family:                  ebpfFamilyIPv4,
		Protocol:                ebpfProtocolTCP,
		RealPacketsSent:         3,
		RealPacketsRecv:         0,
		DirectionDurationNsSent: 900_000_000,
		DirectionDurationNsRecv: 0,
		NfIpSizeBuckets:         [6]uint64{1, 2, 3, 4, 5, 6},
		IpTtlMin:                61,
		IpTtlMax:                64,
		TcpFlagsOrSent:          0x1a, // PSH|ACK|SYN
		TcpFlagsOrRecv:          0,
		TcpHeaderObservedSent:   1,
		TcpHeaderObservedRecv:   0,
		TcpWinMaxSent:           64240,
		TcpWinMaxRecv:           65160,
		IpPktLenMin:             52,
		IpPktLenMax:             1500,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent: %v", err)
	}
	if ev.IPTTLMin == nil || *ev.IPTTLMin != 61 || ev.IPTTLMax == nil || *ev.IPTTLMax != 64 {
		t.Fatalf("ttl fields wrong: %#v", ev)
	}
	if ev.TCPFlagsOut != 0x1a || ev.TCPFlagsIn != 0 {
		t.Fatalf("flag masks wrong: %#v", ev)
	}
	if ev.TCPWindowMaxOut == nil || *ev.TCPWindowMaxOut != 64240 {
		t.Fatalf("window out wrong: %#v", ev.TCPWindowMaxOut)
	}
	// No TCP header was observed inbound (tcp_header_observed_recv == 0), so
	// the inbound window must be null even though the raw field carries a
	// non-zero garbage value — and observation must come from the witness
	// flag, never be re-inferred from the flags OR-mask.
	if ev.TCPWindowMaxIn != nil {
		t.Fatalf("window in = %v, want nil when direction unobserved", *ev.TCPWindowMaxIn)
	}
	if !ev.TCPHeaderObservedOut || ev.TCPHeaderObservedIn {
		t.Fatalf("header observed flags wrong: out=%v in=%v", ev.TCPHeaderObservedOut, ev.TCPHeaderObservedIn)
	}
	if ev.DirectionDurationOutNS != 900_000_000 || !ev.DirectionDurationOutObserved {
		t.Fatalf("out duration wrong: %#v", ev)
	}
	if ev.DirectionDurationInObserved {
		t.Fatalf("in direction marked observed with zero packets")
	}
	if ev.IPPktLenMin == nil || *ev.IPPktLenMin != 52 || ev.IPPktLenMax == nil || *ev.IPPktLenMax != 1500 {
		t.Fatalf("ip pkt len wrong: %#v", ev)
	}
	if ev.NetFlowV2IPSizeHistogram["<=128"] != 1 || ev.NetFlowV2IPSizeHistogram[">1514"] != 6 {
		t.Fatalf("nf histogram wrong: %#v", ev.NetFlowV2IPSizeHistogram)
	}
}

// Unobserved header signals stay nil/zero — no fabricated values.
func TestConvertRawEBPFEventP1Unavailable(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType: ebpfEventStats,
		Family:    ebpfFamilyIPv4,
		Protocol:  ebpfProtocolTCP,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent: %v", err)
	}
	if ev.IPTTLMin != nil || ev.IPTTLMax != nil || ev.TCPWindowMaxOut != nil || ev.TCPWindowMaxIn != nil {
		t.Fatalf("nullable header fields fabricated: %#v", ev)
	}
	if ev.IPPktLenMin != nil || ev.IPPktLenMax != nil || ev.NetFlowV2IPSizeHistogram != nil {
		t.Fatalf("ip length fields fabricated: %#v", ev)
	}
	if ev.DirectionDurationOutObserved || ev.DirectionDurationInObserved {
		t.Fatalf("direction observation fabricated: %#v", ev)
	}
}

// P2: the converter copies the retransmit counters but must NOT set
// availability/source — only the collector's attach path knows whether the
// tracepoint is live, so a converted event alone never claims availability.
func TestConvertRawEBPFEventRetransCountersWithoutAvailability(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType:       ebpfEventStats,
		Family:          ebpfFamilyIPv4,
		Protocol:        ebpfProtocolTCP,
		RetransSkbCount: 3,
		RetransSkbBytes: 4200,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent: %v", err)
	}
	if ev.LocalRetransSKBCount != 3 || ev.LocalRetransSKBBytes != 4200 {
		t.Fatalf("retrans counters not copied: %#v", ev)
	}
	if ev.LocalRetransAvailable || ev.LocalRetransSource != "" {
		t.Fatalf("availability/source fabricated by converter: %#v", ev)
	}
}

// A TCP NULL scan (flag byte 0) with a zero advertised window is a legitimate
// observation: with the header-observed witness set, the converter must keep
// flags==0 alongside observed=true and produce a NON-nil zero window pointer —
// never collapse the direction to "unobserved".
func TestConvertRawEBPFEventNullScanObservedZeroFlagsZeroWindow(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType:             ebpfEventStats,
		Family:                ebpfFamilyIPv4,
		Protocol:              ebpfProtocolTCP,
		TcpFlagsOrSent:        0,
		TcpFlagsOrRecv:        0,
		TcpWinMaxSent:         0,
		TcpWinMaxRecv:         0,
		TcpHeaderObservedSent: 1,
		TcpHeaderObservedRecv: 1,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent: %v", err)
	}
	if !ev.TCPHeaderObservedOut || !ev.TCPHeaderObservedIn {
		t.Fatalf("observed witnesses lost: %#v", ev)
	}
	if ev.TCPFlagsOut != 0 || ev.TCPFlagsIn != 0 {
		t.Fatalf("flags masks wrong: %#v", ev)
	}
	if ev.TCPWindowMaxOut == nil || *ev.TCPWindowMaxOut != 0 {
		t.Fatalf("window out = %v, want pointer to 0 for observed zero-window", ev.TCPWindowMaxOut)
	}
	if ev.TCPWindowMaxIn == nil || *ev.TCPWindowMaxIn != 0 {
		t.Fatalf("window in = %v, want pointer to 0 for observed zero-window", ev.TCPWindowMaxIn)
	}
}

// Asymmetric observation: only the egress direction saw a TCP header (with an
// all-zero flag byte); the ingress direction was never read. The observed side
// keeps its genuine zeros, the unobserved side stays nil/false.
func TestConvertRawEBPFEventOneDirectionObserved(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(rawEBPFEvent{
		EventType:             ebpfEventStats,
		Family:                ebpfFamilyIPv4,
		Protocol:              ebpfProtocolTCP,
		TcpHeaderObservedSent: 1,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent: %v", err)
	}
	if !ev.TCPHeaderObservedOut || ev.TCPHeaderObservedIn {
		t.Fatalf("observed flags wrong: %#v", ev)
	}
	if ev.TCPWindowMaxOut == nil || *ev.TCPWindowMaxOut != 0 {
		t.Fatalf("observed-out window = %v, want pointer to 0", ev.TCPWindowMaxOut)
	}
	if ev.TCPWindowMaxIn != nil {
		t.Fatalf("unobserved-in window = %v, want nil", *ev.TCPWindowMaxIn)
	}
}
