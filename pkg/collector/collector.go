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

	PacketSizes []uint64 `json:"packet_sizes,omitempty"`
	IATMicros   []uint64 `json:"iat_us,omitempty"`

	PacketSizeHistogram map[string]uint64 `json:"packet_size_histogram,omitempty"`
	IATHistogram        map[string]uint64 `json:"iat_histogram,omitempty"`
	PktSizeMin          *uint64           `json:"pkt_size_min,omitempty"`
	PktSizeMax          *uint64           `json:"pkt_size_max,omitempty"`
	IdleGapCount        uint64            `json:"idle_gap_count,omitempty"`
	BurstCount          uint64            `json:"burst_count,omitempty"`
	RealPacketsSent     uint64            `json:"real_packets_sent,omitempty"`
	RealPacketsRecv     uint64            `json:"real_packets_recv,omitempty"`

	DirectionChanges uint64 `json:"direction_changes,omitempty"`
	SYNCount         uint64 `json:"syn_count,omitempty"`
	FINCount         uint64 `json:"fin_count,omitempty"`
	RSTCount         uint64 `json:"rst_count,omitempty"`
	RetransCount     uint64 `json:"retrans_count,omitempty"`
	RTTEstimateUS    uint64 `json:"rtt_estimate_us,omitempty"`

	TCPState    string `json:"tcp_state,omitempty"`
	CloseReason string `json:"close_reason,omitempty"`
	DropReason  string `json:"drop_reason,omitempty"`
	DropCount   uint64 `json:"drop_count,omitempty"`

	HandshakeSeen  bool   `json:"handshake_seen,omitempty"`
	TLSVersion     string `json:"tls_version,omitempty"`
	SNIHash        string `json:"sni_hash,omitempty"`
	ALPN           string `json:"alpn,omitempty"`
	JA4            string `json:"ja4,omitempty"`
	TLSParseStatus string `json:"tls_parse_status,omitempty"`

	TLSHandshakeDirection  uint8  `json:"direction,omitempty"`
	TLSHandshakePayloadHex string `json:"tls_payload_hex,omitempty"`
	ServerHelloSeen        bool   `json:"server_hello_seen,omitempty"`
	TLSVersionNegotiated   string `json:"tls_version_negotiated,omitempty"`
	ALPNNegotiated         string `json:"alpn_negotiated,omitempty"`
	JA4S                   string `json:"ja4s,omitempty"`
	TLSServerParseStatus   string `json:"tls_server_parse_status,omitempty"`

	TrafficAccountingAvailable bool `json:"traffic_accounting_available,omitempty"`
	PacketTimingAvailable      bool `json:"packet_timing_available,omitempty"`
	TCPMetricsAvailable        bool `json:"tcp_metrics_available,omitempty"`
}

type Collector interface {
	Run(ctx context.Context) (<-chan FlowEvent, <-chan error)
}
