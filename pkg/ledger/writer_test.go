package ledger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"FlowLedger/pkg/collector"
	"FlowLedger/pkg/experiment"
	"FlowLedger/pkg/features"
	"FlowLedger/pkg/identity"
	"FlowLedger/pkg/sessionizer"
)

func TestLedgerWriterJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	record := Record{
		RecordType: "session_summary",
		FlowID:     "flow-1",
		NodeName:   "node-a",
		SrcIP:      "10.1.1.10",
		SrcPort:    40000,
		DstIP:      "10.1.1.20",
		DstPort:    443,
		Protocol:   "tcp",
	}
	if err := w.Write(record); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got Record
	if err := json.Unmarshal(b[:len(b)-1], &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got.FlowID != "flow-1" || got.RecordType != "session_summary" || got.DstPort != 443 {
		t.Fatalf("unexpected record: %#v", got)
	}
}

func TestBuildRecordV1Alpha2Fields(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	ratio := 2.0
	session := sessionizer.FlowSession{
		RecordType:           "session_summary",
		FlowID:               "flow-1",
		NodeName:             "node-a",
		StartTime:            now,
		EndTime:              now.Add(time.Second),
		DurationMS:           1000,
		SrcIP:                "10.1.1.10",
		SrcPort:              40000,
		DstIP:                "1.1.1.1",
		DstPort:              443,
		Protocol:             "tcp",
		IPFamily:             "ipv4",
		BytesOut:             200,
		BytesIn:              100,
		PacketsOut:           2,
		PacketsIn:            1,
		CloseReason:          "fin",
		HandshakeSeen:        true,
		TLSVersion:           "1.3",
		ALPN:                 "h2",
		JA4:                  "t13d1516h2_8daaf6152771_e5627efa2ab1",
		TLSParseStatus:       "parsed",
		ServerHelloSeen:      true,
		TLSVersionNegotiated: "1.2",
		ALPNNegotiated:       "h2",
		JA4S:                 "t1201h2_c02f_0b08e3dcc50f",
		TLSServerParseStatus: "parsed",
		FeatureSnapshot: features.Snapshot{
			BytesTotal:                 300,
			PacketsTotal:               3,
			ByteRatioOutIn:             &ratio,
			PktSizeHistogram:           features.EmptyPacketSizeHistogram(),
			TrafficAccountingAvailable: true,
		},
	}
	resolved := identity.ResolvedFlow{
		Src: identity.EndpointIdentity{
			Namespace:  "default",
			PodName:    "api",
			Confidence: "high",
			Method:     "pod_ip",
		},
		Dst: identity.EndpointIdentity{
			External:   true,
			Confidence: "low",
			Method:     "external",
		},
		MappingMethod: "external",
	}

	record := BuildRecordWithContext(session, resolved, experiment.Labels{
		ExperimentID:  "exp-1",
		ScenarioLabel: "baseline",
	}, BuildContext{
		ClusterID:      "kind-thesis",
		AgentID:        "node-a/pod-a",
		CollectionMode: "mock",
		HookSource:     "mock",
	})
	if record.SchemaVersion != features.SchemaVersion || record.FeatureSetVersion != features.FeatureSetVersion {
		t.Fatalf("unexpected schema/feature versions: %#v", record)
	}
	if record.PayloadCollected || record.ProtocolGuess != "tls" || !record.IsTLSLike || !record.ReviewRequired {
		t.Fatalf("unexpected reserved/model fields: %#v", record)
	}
	if record.Direction != "egress" || record.BytesTotal != 300 || record.ByteRatioOutIn == nil || *record.ByteRatioOutIn != 2 {
		t.Fatalf("unexpected derived fields: %#v", record)
	}

	b, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatalf("json.Unmarshal map: %v", err)
	}
	for _, forbidden := range []string{"payload", "raw_payload", "http_path", "http_headers", "http_body"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("record contains forbidden field %q: %s", forbidden, b)
		}
	}
	if record.JA4 == "" || record.JA4S == "" || !record.ServerHelloSeen || record.TLSVersionNegotiated != "1.2" {
		t.Fatalf("missing TLS client/server fields: %#v", record)
	}
	if strings.Contains(string(b), "http_path") || strings.Contains(string(b), "http_headers") || strings.Contains(string(b), "http_body") {
		t.Fatalf("record contains forbidden HTTP payload metadata: %s", b)
	}
}

func TestLedgerWriterRotatesBySize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flows.jsonl")
	w, err := NewWriterWithOptions(WriterOptions{Path: path, MaxBytes: 1})
	if err != nil {
		t.Fatalf("NewWriterWithOptions: %v", err)
	}

	for _, flowID := range []string{"flow-1", "flow-2"} {
		if err := w.Write(Record{RecordType: "session_summary", FlowID: flowID}); err != nil {
			t.Fatalf("Write(%s): %v", flowID, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rotated, err := filepath.Glob(filepath.Join(dir, "flows-*.jsonl"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(rotated) != 1 {
		t.Fatalf("rotated files = %v, want 1 file", rotated)
	}
	assertJSONLLines(t, rotated[0], 1)
	assertJSONLLines(t, path, 1)
}

func assertJSONLLines(t *testing.T, path string, wantLines int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	defer f.Close()

	var lines int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines++
		var got Record
		if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
			t.Fatalf("json.Unmarshal(%s line %d): %v", path, lines, err)
		}
		if got.FlowID == "" {
			t.Fatalf("missing flow_id in %s line %d", path, lines)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("Scan(%s): %v", path, err)
	}
	if lines != wantLines {
		t.Fatalf("%s lines = %d, want %d", path, lines, wantLines)
	}
}

func processEBPFStats(t *testing.T, s *sessionizer.Sessionizer, base time.Time, offset time.Duration, eventType string, sent, recv uint64) []sessionizer.FlowSession {
	t.Helper()
	return s.Process(collector.FlowEvent{
		TimestampNS:              uint64(base.Add(offset).UnixNano()),
		EventType:                eventType,
		SrcIP:                    "10.1.1.10",
		SrcPort:                  40000,
		DstIP:                    "10.1.1.20",
		DstPort:                  443,
		Protocol:                 "tcp",
		CounterSemantics:         collector.CounterSemanticsCumulative,
		RealPacketsSent:          sent,
		RealPacketsRecv:          recv,
		ObservedSKBPacketsSource: collector.ObservedSKBPacketsSourceCgroupSKB,
	})
}

// Required test C — cumulative real packet counters 10/8 → 15/12 → 20/17 must
// land in the ledger as 20/17 (latest monotonic value, not 45/37).
func TestLedgerObservedSKBPacketsLatestCumulative(t *testing.T) {
	base := time.Unix(600, 0).UTC()
	s := sessionizer.New("node-a", time.Minute, 30*time.Second)
	processEBPFStats(t, s, base, 0, "CONNECT", 0, 0)
	processEBPFStats(t, s, base, 1*time.Second, "STATS", 10, 8)
	processEBPFStats(t, s, base, 2*time.Second, "STATS", 15, 12)
	processEBPFStats(t, s, base, 3*time.Second, "STATS", 20, 17)
	out := processEBPFStats(t, s, base, 4*time.Second, "CLOSE", 20, 17)
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}

	record := BuildRecord(out[1], identity.ResolvedFlow{}, experiment.Labels{})
	if record.ObservedSKBPacketsOut != 20 || record.ObservedSKBPacketsIn != 17 {
		t.Fatalf("observed_skb_packets = %d/%d, want 20/17", record.ObservedSKBPacketsOut, record.ObservedSKBPacketsIn)
	}
	if record.ObservedSKBPacketsTotal != 37 {
		t.Fatalf("observed_skb_packets_total = %d, want 37", record.ObservedSKBPacketsTotal)
	}
	if !record.ObservedSKBPacketsAvailable {
		t.Fatalf("observed_skb_packets_available = false, want true")
	}
	if record.ObservedSKBPacketsSource != "cgroup_skb" {
		t.Fatalf("observed_skb_packets_source = %q, want cgroup_skb", record.ObservedSKBPacketsSource)
	}
	if record.CounterResetDetected || record.CounterResetCount != 0 {
		t.Fatalf("monotonic counters flagged as reset: %#v", record)
	}
	// Legacy syscall-level counters must be untouched by skb accounting.
	if record.PacketsOut != 0 || record.PacketsIn != 0 {
		t.Fatalf("legacy packets_out/in changed: %d/%d", record.PacketsOut, record.PacketsIn)
	}
}

// Required test D — a regression to 3/2 after 20/17 is a kernel counter reset:
// the ledger must keep 20/17, must not output negatives or the 23/19 sum, and
// must record the reset explicitly.
func TestLedgerObservedSKBPacketsResetRecorded(t *testing.T) {
	base := time.Unix(700, 0).UTC()
	s := sessionizer.New("node-a", time.Minute, 30*time.Second)
	processEBPFStats(t, s, base, 0, "CONNECT", 0, 0)
	processEBPFStats(t, s, base, 1*time.Second, "STATS", 20, 17)
	processEBPFStats(t, s, base, 2*time.Second, "STATS", 3, 2)
	out := processEBPFStats(t, s, base, 3*time.Second, "CLOSE", 0, 0)
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}

	record := BuildRecord(out[1], identity.ResolvedFlow{}, experiment.Labels{})
	if record.ObservedSKBPacketsOut != 20 || record.ObservedSKBPacketsIn != 17 {
		t.Fatalf("observed_skb_packets = %d/%d, want pre-reset 20/17 (not 23/19)", record.ObservedSKBPacketsOut, record.ObservedSKBPacketsIn)
	}
	if !record.CounterResetDetected || record.CounterResetCount == 0 {
		t.Fatalf("reset not recorded: detected=%v count=%d", record.CounterResetDetected, record.CounterResetCount)
	}
}

// A session with no skb-level observations must not fabricate availability or
// a source.
func TestLedgerObservedSKBPacketsUnavailable(t *testing.T) {
	record := BuildRecord(sessionizer.FlowSession{
		RecordType: "session_summary",
		FlowID:     "flow-x",
		Protocol:   "tcp",
	}, identity.ResolvedFlow{}, experiment.Labels{})
	if record.ObservedSKBPacketsAvailable || record.ObservedSKBPacketsSource != "" {
		t.Fatalf("availability/source fabricated: %#v", record)
	}
	if record.ObservedSKBPacketsOut != 0 || record.ObservedSKBPacketsIn != 0 || record.ObservedSKBPacketsTotal != 0 {
		t.Fatalf("counters fabricated: %#v", record)
	}
}

func u32p(v uint32) *uint32 { return &v }

func TestBuildRecordP1HeaderAggregates(t *testing.T) {
	now := time.Unix(900, 0).UTC()
	session := sessionizer.FlowSession{
		RecordType: "session_summary",
		FlowID:     "flow-p1",
		Protocol:   "tcp",
		StartTime:  now,
		EndTime:    now.Add(2 * time.Second),
		DurationMS: 2000,
		BytesOut:   1000,
		BytesIn:    500,

		IPTTLMin:                     u32p(58),
		IPTTLMax:                     u32p(64),
		TCPFlagsOut:                  0x1a,
		TCPFlagsIn:                   0x12,
		TCPHeaderObservedOut:         true,
		TCPHeaderObservedIn:          true,
		TCPWindowMaxOut:              u32p(64240),
		TCPWindowMaxIn:               u32p(65535),
		DirectionDurationOutNS:       900_000_000,
		DirectionDurationInNS:        0, // exactly one inbound packet
		DirectionDurationOutObserved: true,
		DirectionDurationInObserved:  true,
		IPPktLenMin:                  u32p(52),
		IPPktLenMax:                  u32p(1500),
		FeatureSnapshot: features.Snapshot{
			TrafficAccountingAvailable: true,
			NetFlowV2IPSizeHistogram: map[string]uint64{
				"<=128": 6, "129-256": 4, "257-512": 1, "513-1024": 0, "1025-1514": 1, ">1514": 2,
			},
			NetFlowV2IPSizeHistogramAvailable: true,
		},
	}

	record := BuildRecord(session, identity.ResolvedFlow{}, experiment.Labels{})
	if !record.IPTTLAvailable || record.IPTTLMin == nil || *record.IPTTLMin != 58 || record.IPTTLMax == nil || *record.IPTTLMax != 64 {
		t.Fatalf("ttl fields wrong: %#v", record)
	}
	if !record.TCPFlagsAvailable || record.TCPFlagsOut == nil || *record.TCPFlagsOut != 0x1a || record.TCPFlagsIn == nil || *record.TCPFlagsIn != 0x12 {
		t.Fatalf("flag fields wrong: %#v", record)
	}
	if record.TCPFlagsAll == nil || *record.TCPFlagsAll != 0x1a {
		t.Fatalf("tcp_flags_all = %v, want OR 0x1a", record.TCPFlagsAll)
	}
	if !record.TCPWindowAvailable || record.TCPWindowMaxOut == nil || *record.TCPWindowMaxOut != 64240 || record.TCPWindowMaxIn == nil || *record.TCPWindowMaxIn != 65535 {
		t.Fatalf("window fields wrong: %#v", record)
	}
	if !record.DirectionDurationAvailable {
		t.Fatalf("direction duration available = false")
	}
	if record.DirectionDurationOutMS == nil || *record.DirectionDurationOutMS != 900 {
		t.Fatalf("direction_duration_out_ms = %v, want 900", record.DirectionDurationOutMS)
	}
	// One packet in a direction: duration 0 but present (available), not null.
	if record.DirectionDurationInMS == nil || *record.DirectionDurationInMS != 0 {
		t.Fatalf("direction_duration_in_ms = %v, want genuine 0", record.DirectionDurationInMS)
	}
	if !record.IPPktLenAvailable || record.IPPktLenMin == nil || *record.IPPktLenMin != 52 || record.IPPktLenMax == nil || *record.IPPktLenMax != 1500 {
		t.Fatalf("ip pkt len fields wrong: %#v", record)
	}
	if !record.NetFlowV2IPSizeHistogramAvailable || record.NetFlowV2IPSizeHistogram["<=128"] != 6 || record.NetFlowV2IPSizeHistogram[">1514"] != 2 {
		t.Fatalf("nf histogram wrong: %#v", record.NetFlowV2IPSizeHistogram)
	}
	// bytes/s vs bits/s: 1000 B over 2 s = 500 B/s = 4000 bit/s.
	if record.BytesPerSecondOut == nil || *record.BytesPerSecondOut != 500 {
		t.Fatalf("bytes_per_second_out = %v, want 500", record.BytesPerSecondOut)
	}
	if record.ThroughputBpsOut == nil || *record.ThroughputBpsOut != 4000 {
		t.Fatalf("throughput_bps_out = %v, want 4000", record.ThroughputBpsOut)
	}
	if record.BytesPerSecondIn == nil || *record.BytesPerSecondIn != 250 || record.ThroughputBpsIn == nil || *record.ThroughputBpsIn != 2000 {
		t.Fatalf("in-direction rates wrong: %v %v", record.BytesPerSecondIn, record.ThroughputBpsIn)
	}
}

// duration=0 must yield null rates (no division), and a session without any
// header observations must serialize every P1 field as null/false.
func TestBuildRecordP1NullsWhenUnavailable(t *testing.T) {
	record := BuildRecord(sessionizer.FlowSession{
		RecordType: "session_summary",
		FlowID:     "flow-p1-null",
		Protocol:   "tcp",
		DurationMS: 0,
		BytesOut:   1000,
		FeatureSnapshot: features.Snapshot{
			TrafficAccountingAvailable: true,
		},
	}, identity.ResolvedFlow{}, experiment.Labels{})

	if record.BytesPerSecondOut != nil || record.ThroughputBpsOut != nil || record.BytesPerSecondIn != nil || record.ThroughputBpsIn != nil {
		t.Fatalf("rates computed with zero duration: %#v", record)
	}
	if record.IPTTLAvailable || record.TCPFlagsAvailable || record.TCPWindowAvailable || record.DirectionDurationAvailable || record.IPPktLenAvailable || record.NetFlowV2IPSizeHistogramAvailable {
		t.Fatalf("availability fabricated: %#v", record)
	}
	for name, ptr := range map[string]any{
		"ip_ttl_min":                record.IPTTLMin,
		"ip_ttl_max":                record.IPTTLMax,
		"tcp_flags_all":             record.TCPFlagsAll,
		"tcp_flags_out":             record.TCPFlagsOut,
		"tcp_flags_in":              record.TCPFlagsIn,
		"tcp_window_max_out":        record.TCPWindowMaxOut,
		"tcp_window_max_in":         record.TCPWindowMaxIn,
		"direction_duration_out_ms": record.DirectionDurationOutMS,
		"direction_duration_in_ms":  record.DirectionDurationInMS,
		"ip_pkt_len_min":            record.IPPktLenMin,
		"ip_pkt_len_max":            record.IPPktLenMax,
	} {
		if !reflect.ValueOf(ptr).IsNil() {
			t.Fatalf("%s = %v, want null when unavailable", name, ptr)
		}
	}
	if record.NetFlowV2IPSizeHistogram != nil {
		t.Fatalf("nf histogram fabricated: %#v", record.NetFlowV2IPSizeHistogram)
	}

	b, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	for _, key := range []string{"ip_ttl_min", "tcp_flags_all", "tcp_window_max_out", "direction_duration_out_ms", "ip_pkt_len_min", "netflow_v2_ip_size_histogram", "bytes_per_second_out", "throughput_bps_out"} {
		v, ok := fields[key]
		if !ok {
			t.Fatalf("field %q missing from JSON", key)
		}
		if v != nil {
			t.Fatalf("field %q = %v, want JSON null", key, v)
		}
	}
}

// P2 required: retransmissions ride the pre-DNAT socket flow key. A client
// flow to a Service ClusterIP tuple accumulates local retrans counters on
// exactly that ClusterIP-keyed session — no kube-proxy DNAT reconciliation —
// and the ledger keeps the latest monotonic value across cumulative STATS.
func TestLedgerLocalRetransOnServiceClusterIPKey(t *testing.T) {
	base := time.Unix(1000, 0).UTC()
	s := sessionizer.New("node-a", time.Minute, 30*time.Second)
	mkEv := func(offset time.Duration, eventType string, count, bytes uint64) collector.FlowEvent {
		return collector.FlowEvent{
			TimestampNS:           uint64(base.Add(offset).UnixNano()),
			EventType:             eventType,
			SrcIP:                 "10.244.1.10",
			SrcPort:               40000,
			DstIP:                 "10.96.0.10", // Service ClusterIP (pre-DNAT socket view)
			DstPort:               6379,
			Protocol:              "tcp",
			CounterSemantics:      collector.CounterSemanticsCumulative,
			LocalRetransSKBCount:  count,
			LocalRetransSKBBytes:  bytes,
			LocalRetransAvailable: true,
			LocalRetransSource:    collector.LocalRetransSourceTCPRetransmitSKB,
		}
	}
	s.Process(mkEv(0, "CONNECT", 0, 0))
	s.Process(mkEv(1*time.Second, "STATS", 1, 1400))
	s.Process(mkEv(2*time.Second, "STATS", 3, 4200))
	s.Process(mkEv(3*time.Second, "STATS", 3, 4200)) // re-delivered snapshot: no growth
	out := s.Process(mkEv(4*time.Second, "CLOSE", 3, 4200))
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}

	record := BuildRecord(out[1], identity.ResolvedFlow{}, experiment.Labels{})
	if record.DstIP != "10.96.0.10" {
		t.Fatalf("record not keyed by ClusterIP tuple: %#v", record)
	}
	if record.LocalRetransSKBCount == nil || *record.LocalRetransSKBCount != 3 || record.LocalRetransSKBBytes == nil || *record.LocalRetransSKBBytes != 4200 {
		t.Fatalf("local retrans = %v/%v, want latest 3/4200 (not summed)", record.LocalRetransSKBCount, record.LocalRetransSKBBytes)
	}
	if !record.LocalRetransAvailable || record.LocalRetransSource != "tcp_retransmit_skb" {
		t.Fatalf("availability/source wrong: %#v", record)
	}
	// Peer direction is unobservable: always null/false, never a copy of the
	// local values.
	if record.PeerRetransSKBCount != nil || record.PeerRetransSKBBytes != nil || record.PeerRetransAvailable {
		t.Fatalf("peer retrans fields must stay null/false: %#v", record)
	}
}

// P2 required: an unattached tracepoint yields null counters — 0 must never
// impersonate "confirmed no retransmissions" — while an attached hook with no
// retransmissions is a genuine 0.
func TestLedgerLocalRetransAvailabilitySemantics(t *testing.T) {
	unattached := BuildRecord(sessionizer.FlowSession{
		RecordType: "session_summary",
		FlowID:     "flow-r1",
		Protocol:   "tcp",
	}, identity.ResolvedFlow{}, experiment.Labels{})
	if unattached.LocalRetransAvailable || unattached.LocalRetransSource != "" {
		t.Fatalf("availability fabricated: %#v", unattached)
	}
	if unattached.LocalRetransSKBCount != nil || unattached.LocalRetransSKBBytes != nil {
		t.Fatalf("unattached hook produced non-null counters: %#v", unattached)
	}
	b, err := json.Marshal(unattached)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	for _, key := range []string{"local_retrans_skb_count", "local_retrans_skb_bytes", "peer_retrans_skb_count", "peer_retrans_skb_bytes"} {
		v, ok := fields[key]
		if !ok {
			t.Fatalf("field %q missing from JSON", key)
		}
		if v != nil {
			t.Fatalf("field %q = %v, want JSON null", key, v)
		}
	}

	attached := BuildRecord(sessionizer.FlowSession{
		RecordType:            "session_summary",
		FlowID:                "flow-r2",
		Protocol:              "tcp",
		LocalRetransAvailable: true,
		LocalRetransSource:    "tcp_retransmit_skb",
	}, identity.ResolvedFlow{}, experiment.Labels{})
	if attached.LocalRetransSKBCount == nil || *attached.LocalRetransSKBCount != 0 || attached.LocalRetransSKBBytes == nil || *attached.LocalRetransSKBBytes != 0 {
		t.Fatalf("attached hook with no retransmissions must be genuine 0: %#v", attached)
	}
}

// A kernel-side reset (regression) of the retrans counters keeps the pre-reset
// maximum and records the reset.
func TestLedgerLocalRetransResetRecorded(t *testing.T) {
	base := time.Unix(1100, 0).UTC()
	s := sessionizer.New("node-a", time.Minute, 30*time.Second)
	mkEv := func(offset time.Duration, eventType string, count uint64) collector.FlowEvent {
		return collector.FlowEvent{
			TimestampNS:           uint64(base.Add(offset).UnixNano()),
			EventType:             eventType,
			SrcIP:                 "10.244.1.10",
			SrcPort:               40001,
			DstIP:                 "10.96.0.10",
			DstPort:               6379,
			Protocol:              "tcp",
			CounterSemantics:      collector.CounterSemanticsCumulative,
			LocalRetransSKBCount:  count,
			LocalRetransAvailable: true,
			LocalRetransSource:    collector.LocalRetransSourceTCPRetransmitSKB,
		}
	}
	s.Process(mkEv(0, "CONNECT", 0))
	s.Process(mkEv(1*time.Second, "STATS", 5))
	s.Process(mkEv(2*time.Second, "STATS", 2)) // regression: kernel reset
	out := s.Process(mkEv(3*time.Second, "CLOSE", 0))
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}
	record := BuildRecord(out[1], identity.ResolvedFlow{}, experiment.Labels{})
	if record.LocalRetransSKBCount == nil || *record.LocalRetransSKBCount != 5 {
		t.Fatalf("local retrans = %v, want pre-reset 5 (not 7, not silent 2)", record.LocalRetransSKBCount)
	}
	if !record.CounterResetDetected || record.CounterResetCount == 0 {
		t.Fatalf("reset not recorded: %#v", record)
	}
}

// A TCP NULL scan flow: the out direction was observed but every segment
// carried an all-zero flag byte and a zero advertised window. The ledger must
// emit genuine zeros with available=true — never null — while the unobserved
// in direction stays null. This is the case a value-based availability
// inference (flags != 0) would silently destroy.
func TestBuildRecordTCPNullScanObservedZeros(t *testing.T) {
	now := time.Unix(900, 0).UTC()
	session := sessionizer.FlowSession{
		RecordType: "session_summary",
		FlowID:     "flow-nullscan",
		Protocol:   "tcp",
		StartTime:  now,
		EndTime:    now.Add(time.Second),
		DurationMS: 1000,

		TCPFlagsOut:          0,
		TCPFlagsIn:           0,
		TCPHeaderObservedOut: true,
		TCPHeaderObservedIn:  false,
		TCPWindowMaxOut:      u32p(0), // observed, every segment advertised window 0
		TCPWindowMaxIn:       nil,     // unobserved
	}

	record := BuildRecord(session, identity.ResolvedFlow{}, experiment.Labels{})
	if !record.TCPFlagsAvailable {
		t.Fatalf("tcp_flags_available = false, want true for observed NULL-scan direction")
	}
	if record.TCPFlagsOut == nil || *record.TCPFlagsOut != 0 {
		t.Fatalf("tcp_flags_out = %v, want pointer to genuine 0", record.TCPFlagsOut)
	}
	if record.TCPFlagsIn != nil {
		t.Fatalf("tcp_flags_in = %v, want null for unobserved direction", *record.TCPFlagsIn)
	}
	// tcp_flags_all availability follows the observed witnesses too.
	if record.TCPFlagsAll == nil || *record.TCPFlagsAll != 0 {
		t.Fatalf("tcp_flags_all = %v, want pointer to 0 (>=1 direction observed)", record.TCPFlagsAll)
	}
	if !record.TCPWindowAvailable || record.TCPWindowMaxOut == nil || *record.TCPWindowMaxOut != 0 {
		t.Fatalf("tcp_window_max_out = %v (available=%v), want genuine 0", record.TCPWindowMaxOut, record.TCPWindowAvailable)
	}
	if record.TCPWindowMaxIn != nil {
		t.Fatalf("tcp_window_max_in = %v, want null for unobserved direction", *record.TCPWindowMaxIn)
	}
}

// With no direction observed, every tcp_flags/window field must be null and
// unavailable regardless of stale mask values.
func TestBuildRecordTCPFlagsUnobservedNull(t *testing.T) {
	now := time.Unix(900, 0).UTC()
	session := sessionizer.FlowSession{
		RecordType: "session_summary",
		FlowID:     "flow-unobserved",
		Protocol:   "tcp",
		StartTime:  now,
		EndTime:    now.Add(time.Second),
		DurationMS: 1000,
		// Stale non-zero masks with no observation witness: availability must
		// come from the witness, so these must NOT leak into the ledger.
		TCPFlagsOut: 0x12,
		TCPFlagsIn:  0x10,
	}
	record := BuildRecord(session, identity.ResolvedFlow{}, experiment.Labels{})
	if record.TCPFlagsAvailable || record.TCPFlagsAll != nil || record.TCPFlagsOut != nil || record.TCPFlagsIn != nil {
		t.Fatalf("unobserved flow leaked flag values: %#v %#v %#v available=%v",
			record.TCPFlagsAll, record.TCPFlagsOut, record.TCPFlagsIn, record.TCPFlagsAvailable)
	}
	if record.TCPWindowAvailable || record.TCPWindowMaxOut != nil || record.TCPWindowMaxIn != nil {
		t.Fatalf("unobserved flow fabricated window values: %#v", record)
	}
}
