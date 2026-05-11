package collector

import "context"

type FlowEvent struct {
	TimestampNS uint64 `json:"timestamp_ns"`
	EventType   string `json:"event_type"`
	PID         uint32 `json:"pid"`
	TGID        uint32 `json:"tgid"`
	CgroupID    uint64 `json:"cgroup_id"`
	NetnsIno    uint64 `json:"netns_ino"`

	SrcIP    string `json:"src_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`

	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
}

type Collector interface {
	Run(ctx context.Context) (<-chan FlowEvent, <-chan error)
}
