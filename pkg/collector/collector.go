package collector

import "context"

// Counter semantics of a FlowEvent's byte/packet/histogram/TCP counters.
//
//   - cumulative: every event carries the flow's totals since flow start
//     (eBPF mode: the kernel emits monotonic snapshots of the same
//     flow_stats entry). Aggregators must keep the latest monotonic value /
//     replace histograms, never sum across events.
//   - delta (or empty, the legacy default): counters are per-event
//     increments (mock mode); aggregators sum them.
const (
	CounterSemanticsCumulative = "cumulative"
	CounterSemanticsDelta      = "delta"
)

// ObservedSKBPacketsSourceCgroupSKB identifies cgroup_skb hooks as the origin
// of RealPacketsSent/Recv. These are skb-level counts (post-GSO/GRO), not
// calibrated wire packets.
const ObservedSKBPacketsSourceCgroupSKB = "cgroup_skb"

// LocalRetransSourceTCPRetransmitSKB identifies the tcp/tcp_retransmit_skb
// tracepoint as the origin of the local retransmission counters.
const LocalRetransSourceTCPRetransmitSKB = "tcp_retransmit_skb"

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

	// v1alpha3 P1: TCP/IP header aggregates observed at the cgroup_skb hooks.
	// All cumulative per flow. "out" = local egress, "in" = local ingress —
	// NOT client/server; only a downstream consumer that knows the local end
	// is the active initiator may map these to client/server.
	IPTTLMin *uint32 `json:"ip_ttl_min,omitempty"` // both directions combined
	IPTTLMax *uint32 `json:"ip_ttl_max,omitempty"`
	// Bitwise OR of the raw TCP flag byte per direction. Interpretation
	// requires TCPHeaderObserved*: observed=true with flags==0 is a genuine
	// all-zero flag byte (TCP NULL scan), NOT "unobserved".
	TCPFlagsOut uint32 `json:"tcp_flags_out,omitempty"`
	TCPFlagsIn  uint32 `json:"tcp_flags_in,omitempty"`
	// Monotonic per-direction witness that TCP header bytes 12-15 were
	// successfully read at least once. Set on read success ONLY — never
	// inferred from flag/window values. Mock fixtures modelling TCP header
	// observation must set these explicitly.
	TCPHeaderObservedOut bool `json:"tcp_header_observed_out,omitempty"`
	TCPHeaderObservedIn  bool `json:"tcp_header_observed_in,omitempty"`
	// Raw advertised window (host order), NOT corrected for window scaling.
	// Nil when TCPHeaderObserved* is false for that direction; a present
	// value may legitimately be 0 if every observed segment advertised a
	// zero window.
	TCPWindowMaxOut *uint32 `json:"tcp_window_max_out,omitempty"`
	TCPWindowMaxIn  *uint32 `json:"tcp_window_max_in,omitempty"`
	// Active span per direction (last-first packet, kernel-derived). A
	// direction with exactly one packet has duration 0 but Observed=true;
	// Observed=false means the direction was never seen.
	DirectionDurationOutNS       uint64 `json:"direction_duration_out_ns,omitempty"`
	DirectionDurationInNS        uint64 `json:"direction_duration_in_ns,omitempty"`
	DirectionDurationOutObserved bool   `json:"direction_duration_out_observed,omitempty"`
	DirectionDurationInObserved  bool   `json:"direction_duration_in_observed,omitempty"`
	// ntohs(ip.tot_len) envelope (may reflect GSO/GRO aggregates).
	IPPktLenMin *uint32 `json:"ip_pkt_len_min,omitempty"`
	IPPktLenMax *uint32 `json:"ip_pkt_len_max,omitempty"`
	// NetFlow-v2 edge histogram over ntohs(ip.tot_len), both directions.
	// The ">1514" bucket is overflow (GSO/GRO) and must never be folded into
	// "1025-1514".
	NetFlowV2IPSizeHistogram map[string]uint64 `json:"netflow_v2_ip_size_histogram,omitempty"`

	// v1alpha3 P2: LOCAL egress retransmissions from tcp/tcp_retransmit_skb,
	// cumulative per flow. skb granularity — one retransmitted skb may be a
	// GSO aggregate of several wire segments — NOT a wire-packet count. Peer
	// (dst->src) retransmissions are not observable from this hook and have
	// no event fields. Available/Source are set by the collector from the
	// tracepoint attach status, never inferred from counter values: a flow
	// with zero retransmissions and an attached hook is a genuine 0, while an
	// unattached hook leaves Available=false so 0 never impersonates
	// "confirmed no retransmissions".
	LocalRetransSKBCount  uint64 `json:"local_retrans_skb_count,omitempty"`
	LocalRetransSKBBytes  uint64 `json:"local_retrans_skb_bytes,omitempty"`
	LocalRetransAvailable bool   `json:"local_retrans_available,omitempty"`
	LocalRetransSource    string `json:"local_retrans_source,omitempty"`

	// --- v1alpha5: per-direction split of three existing families ---
	// "Out" = local egress, "In" = local ingress — the SAME direction
	// predicate that produces RealPacketsSent/Recv, decided once in the BPF
	// packet path. NOT client/server.
	//
	// The two histogram pairs are EXACT decompositions of PacketSizeHistogram
	// and IATHistogram: out[b] + in[b] == mixed[b] for every bucket. That
	// holds for IAT too, because the kernel has always measured each
	// inter-arrival gap against the previous packet in the SAME direction and
	// merely merged the results into one array.
	PacketSizeHistogramOut map[string]uint64 `json:"packet_size_histogram_out,omitempty"`
	PacketSizeHistogramIn  map[string]uint64 `json:"packet_size_histogram_in,omitempty"`
	IATHistogramOut        map[string]uint64 `json:"iat_histogram_out,omitempty"`
	IATHistogramIn         map[string]uint64 `json:"iat_histogram_in,omitempty"`
	// Per-PACKET counts of packets bearing each TCP flag, per direction, read
	// from the raw flag byte at cgroup_skb. A DIFFERENT quantity from
	// SYNCount/FINCount/RSTCount above, which are per-CONNECTION values from
	// the socket-state tracepoint: a SYN retransmission increments
	// SYNCountOut and never SYNCount, and a SYN+ACK increments SYNCountIn.
	// Coverage is bounded by the packet path: a connection that never reached
	// ESTABLISHED has no BPF flow entry, so refused/unanswered connection
	// attempts contribute nothing here.
	SYNCountOut uint64 `json:"syn_count_out,omitempty"`
	SYNCountIn  uint64 `json:"syn_count_in,omitempty"`
	FINCountOut uint64 `json:"fin_count_out,omitempty"`
	FINCountIn  uint64 `json:"fin_count_in,omitempty"`
	RSTCountOut uint64 `json:"rst_count_out,omitempty"`
	RSTCountIn  uint64 `json:"rst_count_in,omitempty"`
	// Per-direction TTL envelope, same rolling semantics as IPTTLMin/Max
	// (cumulative over the flow, never reset per window). Nil = that
	// direction observed no packet.
	IPTTLMinOut *uint32 `json:"ip_ttl_min_out,omitempty"`
	IPTTLMaxOut *uint32 `json:"ip_ttl_max_out,omitempty"`
	IPTTLMinIn  *uint32 `json:"ip_ttl_min_in,omitempty"`
	IPTTLMaxIn  *uint32 `json:"ip_ttl_max_in,omitempty"`

	// CounterSemantics marks whether this event's counters are cumulative
	// flow snapshots or per-event deltas; see CounterSemantics* constants.
	// Empty means delta (legacy mock behaviour).
	CounterSemantics string `json:"counter_semantics,omitempty"`
	// Provenance of RealPacketsSent/Recv ("cgroup_skb" in eBPF mode, "mock"
	// for mock fixtures). Empty when no skb-level counts were observed.
	ObservedSKBPacketsSource string `json:"observed_skb_packets_source,omitempty"`
}

type Collector interface {
	Run(ctx context.Context) (<-chan FlowEvent, <-chan error)
}

// EBPFMapOccupancy is one low-frequency occupancy sample of a kernel map,
// delivered through EBPFOptions.OnMapOccupancy. Entries is counted by walking
// the map keys outside the packet/event hot path; concurrent churn during a
// walk can slightly under- or over-count, so treat it as a sample, not an
// exact census. Map names: flow_stats | local_ep | tls_seen | recv_args.
type EBPFMapOccupancy struct {
	Name       string
	Entries    uint64
	MaxEntries uint64
}
