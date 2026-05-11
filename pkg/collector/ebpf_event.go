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

	ebpfFamilyIPv4  = 2
	ebpfProtocolTCP = 6
)

type rawEBPFEvent struct {
	TimestampNS uint64
	EventType   uint32
	PID         uint32
	TGID        uint32
	_           uint32
	CgroupID    uint64
	NetnsIno    uint64
	Family      uint16
	Protocol    uint8
	_           uint8
	SrcIPv4     uint32
	DstIPv4     uint32
	SrcPort     uint16
	DstPort     uint16
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
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
		TimestampNS: raw.TimestampNS,
		EventType:   eventType,
		PID:         raw.PID,
		TGID:        raw.TGID,
		CgroupID:    raw.CgroupID,
		NetnsIno:    raw.NetnsIno,
		SrcIP:       ipv4String(raw.SrcIPv4),
		SrcPort:     raw.SrcPort,
		DstIP:       ipv4String(raw.DstIPv4),
		DstPort:     raw.DstPort,
		Protocol:    "tcp",
		BytesSent:   raw.BytesSent,
		BytesRecv:   raw.BytesRecv,
		PacketsSent: raw.PacketsSent,
		PacketsRecv: raw.PacketsRecv,
	}
	switch eventType {
	case "CONNECT":
		ev.TCPState = "established"
	case "CLOSE":
		ev.TCPState = "close"
		ev.CloseReason = "unknown"
	}
	return ev, nil
}

func ebpfEventType(rawType uint32) (string, error) {
	switch rawType {
	case ebpfEventConnect:
		return "CONNECT", nil
	case ebpfEventClose:
		return "CLOSE", nil
	case ebpfEventStats:
		return "STATS", nil
	default:
		return "", fmt.Errorf("unknown ebpf event type %d", rawType)
	}
}

func ipv4String(raw uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], raw)
	return netip.AddrFrom4(b).String()
}
