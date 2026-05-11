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
	if ev.EventType != "CLOSE" {
		t.Fatalf("EventType = %q, want CLOSE", ev.EventType)
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

func ipv4Raw(a, b, c, d byte) uint32 {
	return binary.LittleEndian.Uint32([]byte{a, b, c, d})
}
