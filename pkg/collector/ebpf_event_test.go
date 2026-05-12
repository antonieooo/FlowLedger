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
		SYNCount:                   1,
		TrafficAccountingAvailable: 1,
		TCPMetricsAvailable:        1,
	})
	if err != nil {
		t.Fatalf("convertRawEBPFEventToFlowEvent: %v", err)
	}
	if ev.EventType != "STATS" || ev.BytesSent != 1000 || ev.BytesRecv != 2000 || ev.PacketsSent != 3 || ev.PacketsRecv != 4 {
		t.Fatalf("unexpected stats event: %#v", ev)
	}
	if !ev.TrafficAccountingAvailable || ev.PacketTimingAvailable || !ev.TCPMetricsAvailable || ev.SYNCount != 1 {
		t.Fatalf("unexpected availability flags: %#v", ev)
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

func ipv4Raw(a, b, c, d byte) uint32 {
	return binary.LittleEndian.Uint32([]byte{a, b, c, d})
}
