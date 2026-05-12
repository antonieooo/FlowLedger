package collector

import (
	"encoding/binary"
	"testing"
)

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
	var data [1024]byte
	copy(data[:], hello)
	ev := convertRawTLSHandshakeEventToFlowEvent(rawTLSHandshakeEvent{
		SrcIPv4:     ipv4Raw(10, 244, 1, 10),
		DstIPv4:     ipv4Raw(93, 184, 216, 34),
		SrcPort:     43120,
		DstPort:     443,
		Protocol:    ebpfProtocolTCP,
		CgroupID:    99,
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

func ipv4Raw(a, b, c, d byte) uint32 {
	return binary.LittleEndian.Uint32([]byte{a, b, c, d})
}
