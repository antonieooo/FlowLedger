//go:build linux && (386 || amd64)

package collector

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/btf"
)

// rawEBPFEventBTFOffsets maps every parsed rawEBPFEvent field to its Go
// offset, keyed by the corresponding C member name in struct flow_event.
// Blank padding fields are excluded (they have no C member counterpart that
// the parser depends on).
func rawEBPFEventBTFOffsets() map[string]uintptr {
	raw := rawEBPFEvent{}
	return map[string]uintptr{
		"timestamp_ns":                 unsafe.Offsetof(raw.TimestampNS),
		"event_type":                   unsafe.Offsetof(raw.EventType),
		"pid":                          unsafe.Offsetof(raw.PID),
		"tgid":                         unsafe.Offsetof(raw.TGID),
		"cgroup_id":                    unsafe.Offsetof(raw.CgroupID),
		"netns_ino":                    unsafe.Offsetof(raw.NetnsIno),
		"family":                       unsafe.Offsetof(raw.Family),
		"protocol":                     unsafe.Offsetof(raw.Protocol),
		"src_ipv4":                     unsafe.Offsetof(raw.SrcIPv4),
		"dst_ipv4":                     unsafe.Offsetof(raw.DstIPv4),
		"src_port":                     unsafe.Offsetof(raw.SrcPort),
		"dst_port":                     unsafe.Offsetof(raw.DstPort),
		"bytes_sent":                   unsafe.Offsetof(raw.BytesSent),
		"bytes_recv":                   unsafe.Offsetof(raw.BytesRecv),
		"packets_sent":                 unsafe.Offsetof(raw.PacketsSent),
		"packets_recv":                 unsafe.Offsetof(raw.PacketsRecv),
		"pkt_size_buckets":             unsafe.Offsetof(raw.PktSizeBuckets),
		"iat_buckets":                  unsafe.Offsetof(raw.IATBuckets),
		"pkt_size_min":                 unsafe.Offsetof(raw.PktSizeMin),
		"pkt_size_max":                 unsafe.Offsetof(raw.PktSizeMax),
		"idle_gap_count":               unsafe.Offsetof(raw.IdleGapCount),
		"burst_count":                  unsafe.Offsetof(raw.BurstCount),
		"real_packets_sent":            unsafe.Offsetof(raw.RealPacketsSent),
		"real_packets_recv":            unsafe.Offsetof(raw.RealPacketsRecv),
		"direction_duration_ns_sent":   unsafe.Offsetof(raw.DirectionDurationNsSent),
		"direction_duration_ns_recv":   unsafe.Offsetof(raw.DirectionDurationNsRecv),
		"nf_ip_size_buckets":           unsafe.Offsetof(raw.NfIpSizeBuckets),
		"retrans_skb_count":            unsafe.Offsetof(raw.RetransSkbCount),
		"retrans_skb_bytes":            unsafe.Offsetof(raw.RetransSkbBytes),
		"syn_count":                    unsafe.Offsetof(raw.SYNCount),
		"fin_count":                    unsafe.Offsetof(raw.FINCount),
		"rst_count":                    unsafe.Offsetof(raw.RSTCount),
		"ip_ttl_min":                   unsafe.Offsetof(raw.IpTtlMin),
		"ip_ttl_max":                   unsafe.Offsetof(raw.IpTtlMax),
		"pkt_size_buckets_out":         unsafe.Offsetof(raw.PktSizeBucketsOut),
		"pkt_size_buckets_in":          unsafe.Offsetof(raw.PktSizeBucketsIn),
		"iat_buckets_out":              unsafe.Offsetof(raw.IATBucketsOut),
		"iat_buckets_in":               unsafe.Offsetof(raw.IATBucketsIn),
		"syn_count_out":                unsafe.Offsetof(raw.SYNCountOut),
		"syn_count_in":                 unsafe.Offsetof(raw.SYNCountIn),
		"fin_count_out":                unsafe.Offsetof(raw.FINCountOut),
		"fin_count_in":                 unsafe.Offsetof(raw.FINCountIn),
		"rst_count_out":                unsafe.Offsetof(raw.RSTCountOut),
		"rst_count_in":                 unsafe.Offsetof(raw.RSTCountIn),
		"ip_ttl_min_out":               unsafe.Offsetof(raw.IpTtlMinOut),
		"ip_ttl_max_out":               unsafe.Offsetof(raw.IpTtlMaxOut),
		"ip_ttl_min_in":                unsafe.Offsetof(raw.IpTtlMinIn),
		"ip_ttl_max_in":                unsafe.Offsetof(raw.IpTtlMaxIn),
		"tcp_flags_or_sent":            unsafe.Offsetof(raw.TcpFlagsOrSent),
		"tcp_flags_or_recv":            unsafe.Offsetof(raw.TcpFlagsOrRecv),
		"tcp_win_max_sent":             unsafe.Offsetof(raw.TcpWinMaxSent),
		"tcp_win_max_recv":             unsafe.Offsetof(raw.TcpWinMaxRecv),
		"ip_pkt_len_min":               unsafe.Offsetof(raw.IpPktLenMin),
		"ip_pkt_len_max":               unsafe.Offsetof(raw.IpPktLenMax),
		"traffic_accounting_available": unsafe.Offsetof(raw.TrafficAccountingAvailable),
		"packet_timing_available":      unsafe.Offsetof(raw.PacketTimingAvailable),
		"tcp_metrics_available":        unsafe.Offsetof(raw.TCPMetricsAvailable),
		"tcp_header_observed_sent":     unsafe.Offsetof(raw.TcpHeaderObservedSent),
		"tcp_header_observed_recv":     unsafe.Offsetof(raw.TcpHeaderObservedRecv),
	}
}

// TestRawEBPFEventLayoutMatchesBTF is the authoritative C<->Go layout check:
// it loads the BTF embedded in the compiled amd64 BPF object and verifies that
// struct flow_event's size and every member offset match rawEBPFEvent. Any
// drift between bpf/flow_events.bpf.c and pkg/collector/ebpf_event.go fails
// here without needing a kernel to load the program.
func TestRawEBPFEventLayoutMatchesBTF(t *testing.T) {
	spec, err := loadFlowEvents()
	if err != nil {
		t.Fatalf("loadFlowevents: %v", err)
	}
	if spec.Types == nil {
		t.Fatal("collection spec carries no BTF")
	}
	var flowEvent *btf.Struct
	if err := spec.Types.TypeByName("flow_event", &flowEvent); err != nil {
		t.Fatalf("BTF lookup of struct flow_event: %v", err)
	}

	if got, want := uintptr(flowEvent.Size), unsafe.Sizeof(rawEBPFEvent{}); got != want {
		t.Errorf("BTF flow_event size = %d, Go rawEBPFEvent size = %d", got, want)
	}

	btfOffsets := make(map[string]uintptr, len(flowEvent.Members))
	for _, m := range flowEvent.Members {
		if m.BitfieldSize != 0 {
			t.Fatalf("unexpected bitfield member %q", m.Name)
		}
		btfOffsets[m.Name] = uintptr(m.Offset.Bytes())
	}

	for name, goOffset := range rawEBPFEventBTFOffsets() {
		cOffset, ok := btfOffsets[name]
		if !ok {
			t.Errorf("C struct flow_event has no member %q expected by rawEBPFEvent", name)
			continue
		}
		if cOffset != goOffset {
			t.Errorf("member %q: C offset %d != Go offset %d", name, cOffset, goOffset)
		}
	}
}

// Static resource budget: flow_stats is the per-entry cost of a 65536-entry
// map (every byte is ×65536 of kernel memory), flow_event is the per-event
// ringbuf payload. These budgets are deliberate design limits — a change that
// exceeds them must be an explicit decision, not an accident of field growth.
//
// RAISED FOR v1alpha5 (was 384/376). The per-direction split adds 240 bytes
// to each struct, 208 of them the four histogram arrays; both are now 600
// bytes. The cost was accepted knowingly:
//   - flow_stats_map: 600 × 65536 = 37.5 MiB of kernel memory per node, up
//     from 22.5 MiB. Charged to the agent's memcg, whose limit is 2 GiB.
//   - events ringbuf (16 MiB): ~27.9k in-flight events instead of ~46.6k.
//     STATS emission is once per 5 s per flow, so the headroom is ample.
//
// Keeping the histograms u64 (rather than shrinking them to u32 to squeeze
// under the old budget) is what makes out[b] + in[b] == mixed[b] exact for
// arbitrarily long flows; a narrower counter could overflow where the mixed
// one does not and silently break the identity.
func TestBPFStructResourceBudget(t *testing.T) {
	const (
		flowStatsBudget = 608
		flowEventBudget = 608
	)
	spec, err := loadFlowEvents()
	if err != nil {
		t.Fatalf("loadFlowEvents: %v", err)
	}
	var flowStats, flowEvent *btf.Struct
	if err := spec.Types.TypeByName("flow_stats", &flowStats); err != nil {
		t.Fatalf("BTF lookup of struct flow_stats: %v", err)
	}
	if err := spec.Types.TypeByName("flow_event", &flowEvent); err != nil {
		t.Fatalf("BTF lookup of struct flow_event: %v", err)
	}
	if flowStats.Size > flowStatsBudget {
		t.Errorf("flow_stats = %d bytes, exceeds %d-byte budget (×65536 entries = %d KiB)",
			flowStats.Size, flowStatsBudget, flowStats.Size*65536/1024)
	}
	if flowEvent.Size > flowEventBudget {
		t.Errorf("flow_event = %d bytes, exceeds %d-byte budget", flowEvent.Size, flowEventBudget)
	}
	// The atomic OR operands must stay 32-bit and 4-byte aligned.
	for _, m := range flowStats.Members {
		if m.Name == "tcp_flags_or_sent" || m.Name == "tcp_flags_or_recv" {
			if m.Offset.Bytes()%4 != 0 {
				t.Errorf("flow_stats.%s at offset %d is not 4-byte aligned (atomic OR operand)", m.Name, m.Offset.Bytes())
			}
		}
	}
}

// bpfFlowConfig (written into config_map by configureBPF) must stay
// byte-identical to struct flow_config in the BPF object, so the kernel-side
// feature gates read the bits Go actually wrote.
func TestFlowConfigLayoutMatchesBTF(t *testing.T) {
	spec, err := loadFlowEvents()
	if err != nil {
		t.Fatalf("loadFlowEvents: %v", err)
	}
	var flowConfig *btf.Struct
	if err := spec.Types.TypeByName("flow_config", &flowConfig); err != nil {
		t.Fatalf("BTF lookup of struct flow_config: %v", err)
	}
	if got, want := uintptr(flowConfig.Size), unsafe.Sizeof(bpfFlowConfig{}); got != want {
		t.Errorf("BTF flow_config size = %d, Go bpfFlowConfig size = %d", got, want)
	}
	cfg := bpfFlowConfig{}
	wantOffsets := map[string]uintptr{
		"tls_handshake_inspect_enabled": unsafe.Offsetof(cfg.TLSHandshakeInspectEnabled),
		"collect_header_aggregates":     unsafe.Offsetof(cfg.CollectHeaderAggregates),
		"collect_netflow_v2_histogram":  unsafe.Offsetof(cfg.CollectNetFlowV2Histogram),
	}
	btfOffsets := make(map[string]uintptr, len(flowConfig.Members))
	for _, m := range flowConfig.Members {
		btfOffsets[m.Name] = uintptr(m.Offset.Bytes())
	}
	for name, goOffset := range wantOffsets {
		cOffset, ok := btfOffsets[name]
		if !ok {
			t.Errorf("C struct flow_config has no member %q expected by bpfFlowConfig", name)
			continue
		}
		if cOffset != goOffset {
			t.Errorf("flow_config member %q: C offset %d != Go offset %d", name, cOffset, goOffset)
		}
	}
}
