package ledger

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"FlowLedger/pkg/experiment"
	"FlowLedger/pkg/features"
	"FlowLedger/pkg/identity"
	"FlowLedger/pkg/k8smeta"
	"FlowLedger/pkg/sessionizer"
)

type Record struct {
	SchemaVersion  string `json:"schema_version"`
	RecordType     string `json:"record_type"`
	ClusterID      string `json:"cluster_id"`
	NodeName       string `json:"node_name"`
	AgentID        string `json:"agent_id"`
	CollectionMode string `json:"collection_mode"`
	HookSource     string `json:"hook_source"`
	StartTime      string `json:"start_time"`
	EndTime        string `json:"end_time"`
	ExperimentID   string `json:"experiment_id"`
	ScenarioLabel  string `json:"scenario_label"`

	FlowID   string `json:"flow_id"`
	WindowID uint64 `json:"window_id"`

	// --- v1alpha4 window-delta contract ---
	// CounterSemantics is the machine-readable discriminator of what the
	// additive counters in THIS record mean: "window_delta" on window_summary
	// records (current cumulative minus previous accepted baseline) and
	// "lifetime_cumulative" on session_summary records (whole-connection
	// totals, a diagnostic record that REPEATS everything already emitted in
	// this flow's windows — it must never be counted as another window).
	// A fixed-window dataset is exactly: record_type == "window_summary".
	CounterSemantics string `json:"counter_semantics"`
	// WindowValid: the delta counters of this window record are a
	// trustworthy fixed-window increment. When false every additive counter
	// and histogram is zeroed and WindowInvalidReason explains why
	// ("unknown_baseline": first snapshot of a generation not proven to start
	// from zero; "counter_reset": a cumulative counter/bucket regressed).
	// Always false on session_summary records.
	WindowValid         bool   `json:"window_valid"`
	WindowInvalidReason string `json:"window_invalid_reason"`
	// CounterEpoch groups windows differenced over one continuous kernel
	// counter lineage; it increments after each counter_reset window.
	CounterEpoch uint64 `json:"counter_epoch"`
	// FinalWindow marks the partial window flushed exactly once when the
	// connection ends (CLOSE, inactivity timeout, shutdown, or a new CONNECT
	// generation superseding a lost CLOSE).
	FinalWindow bool `json:"final_window"`
	// WindowStartTime is the start of this window's delta interval (the
	// previous baseline snapshot time); the interval ends at end_time.
	// Empty on session_summary records.
	WindowStartTime string `json:"window_start_time"`
	SrcIP         string `json:"src_ip"`
	SrcPort       uint16 `json:"src_port"`
	DstIP         string `json:"dst_ip"`
	DstPort       uint16 `json:"dst_port"`
	Protocol      string `json:"protocol"`
	Direction     string `json:"direction"`
	IPFamily      string `json:"ip_family"`
	ConnStartTime string `json:"conn_start_time"`
	ConnEndTime   string `json:"conn_end_time"`
	DurationMS    int64  `json:"duration_ms"`
	TCPState      string `json:"tcp_state"`
	CloseReason   string `json:"close_reason"`
	IsLongLived   bool   `json:"is_long_lived"`
	NetnsIno      uint64 `json:"netns_ino"`

	BytesOut                   uint64            `json:"bytes_out"`
	BytesIn                    uint64            `json:"bytes_in"`
	PacketsOut                 uint64            `json:"packets_out"`
	PacketsIn                  uint64            `json:"packets_in"`
	BytesTotal                 uint64            `json:"bytes_total"`
	PacketsTotal               uint64            `json:"packets_total"`
	ByteRatioOutIn             *float64          `json:"byte_ratio_out_in"`
	PacketRatioOutIn           *float64          `json:"packet_ratio_out_in"`
	DirectionChanges           uint64            `json:"direction_changes"`
	PktSizeMin                 *uint64           `json:"pkt_size_min"`
	PktSizeMax                 *uint64           `json:"pkt_size_max"`
	PktSizeMean                *float64          `json:"pkt_size_mean"`
	PktSizeP50                 *float64          `json:"pkt_size_p50"`
	PktSizeP95                 *float64          `json:"pkt_size_p95"`
	PktSizeStd                 *float64          `json:"pkt_size_std"`
	PktSizeHistogram           map[string]uint64 `json:"pkt_size_histogram"`
	IATMean                    *float64          `json:"iat_mean"`
	IATP50                     *float64          `json:"iat_p50"`
	IATP95                     *float64          `json:"iat_p95"`
	IATStd                     *float64          `json:"iat_std"`
	IATHistogram               map[string]uint64 `json:"iat_histogram"`
	IdleGapCount               uint64            `json:"idle_gap_count"`
	BurstCount                 uint64            `json:"burst_count"`
	ByteRate                   *float64          `json:"byte_rate"`
	PacketRate                 *float64          `json:"packet_rate"`
	SYNCount                   uint64            `json:"syn_count"`
	FINCount                   uint64            `json:"fin_count"`
	RSTCount                   uint64            `json:"rst_count"`
	RetransCount               uint64            `json:"retrans_count"`
	RTTEstimateUS              *uint64           `json:"rtt_estimate_us"`
	TrafficAccountingAvailable bool              `json:"traffic_accounting_available"`
	PacketTimingAvailable      bool              `json:"packet_timing_available"`
	TCPMetricsAvailable        bool              `json:"tcp_metrics_available"`

	// v1alpha3: cgroup_skb-observed skb counts. skb granularity — one skb may
	// be a GSO/GRO aggregate of many wire packets — so these are NOT exact
	// wire packet counts and must not be compared 1:1 against PCAP. The
	// legacy packets_out/in above keep their syscall/message semantics.
	ObservedSKBPacketsOut       uint64 `json:"observed_skb_packets_out"`
	ObservedSKBPacketsIn        uint64 `json:"observed_skb_packets_in"`
	ObservedSKBPacketsTotal     uint64 `json:"observed_skb_packets_total"`
	ObservedSKBPacketsAvailable bool   `json:"observed_skb_packets_available"`
	ObservedSKBPacketsSource    string `json:"observed_skb_packets_source"` // "cgroup_skb" | "mock" | ""

	// v1alpha3: a cumulative kernel counter regressed mid-session (map entry
	// evicted/re-created or agent restart). Totals keep the pre-reset maxima
	// and are a lower bound; pre- and post-reset values are never summed.
	CounterResetDetected bool   `json:"counter_reset_detected"`
	CounterResetCount    uint64 `json:"counter_reset_count"`

	// --- v1alpha3 P1: TCP/IP header aggregates from cgroup_skb. "out" =
	// local egress, "in" = local ingress; NOT client/server — only a
	// downstream cohort that has established the local end as the active
	// initiator may map out/in to client/server. Pointer fields are null when
	// the signal was unavailable, never a fabricated 0.
	IPTTLMin       *uint32 `json:"ip_ttl_min"` // both directions combined
	IPTTLMax       *uint32 `json:"ip_ttl_max"`
	IPTTLAvailable bool    `json:"ip_ttl_available"`

	// Availability is driven by the kernel's per-direction header-observed
	// witness (TCP bytes 12-15 read success), NOT by the values: a direction
	// observed with an all-zero flag byte (TCP NULL scan) serializes as a
	// genuine 0 with available=true; an unobserved direction is null.
	// tcp_flags_all is available iff at least one direction was observed.
	TCPFlagsAll       *uint32 `json:"tcp_flags_all"` // OR of out|in
	TCPFlagsOut       *uint32 `json:"tcp_flags_out"`
	TCPFlagsIn        *uint32 `json:"tcp_flags_in"`
	TCPFlagsAvailable bool    `json:"tcp_flags_available"`

	// Raw advertised window (ntohs of the TCP header field), per-direction
	// max. NOT the effective scaled window: window scaling (RFC 7323) is
	// negotiated in SYN options and is not implemented or verified here.
	// Same observed-gating as tcp_flags: an observed direction whose every
	// segment advertised window 0 serializes a genuine 0, not null. The max
	// is a concurrent best-effort extremum (see schema doc), not exact.
	TCPWindowMaxOut    *uint32 `json:"tcp_window_max_out"`
	TCPWindowMaxIn     *uint32 `json:"tcp_window_max_in"`
	TCPWindowAvailable bool    `json:"tcp_window_available"`

	// Active span per direction (first-to-last observed skb). A direction
	// with exactly one packet reports 0; a never-observed direction is null.
	DirectionDurationOutMS     *uint64 `json:"direction_duration_out_ms"`
	DirectionDurationInMS      *uint64 `json:"direction_duration_in_ms"`
	DirectionDurationAvailable bool    `json:"direction_duration_available"`

	// ntohs(ip.tot_len) envelope; pkt_size_min/max above keep their skb->len
	// (flow_pkt_len) semantics. May reflect GSO/GRO aggregates.
	IPPktLenMin       *uint32 `json:"ip_pkt_len_min"`
	IPPktLenMax       *uint32 `json:"ip_pkt_len_max"`
	IPPktLenAvailable bool    `json:"ip_pkt_len_available"`

	// NetFlow-v2 edge histogram over ntohs(ip.tot_len), both directions.
	// ">1514" is overflow (GSO/GRO) and must be reported separately — an
	// Anomal-E adapter selects only the first five buckets.
	NetFlowV2IPSizeHistogram          map[string]uint64 `json:"netflow_v2_ip_size_histogram"`
	NetFlowV2IPSizeHistogramAvailable bool              `json:"netflow_v2_ip_size_histogram_available"`

	// --- v1alpha3 P2: LOCAL egress retransmissions from tracepoint
	// tcp/tcp_retransmit_skb, keyed by the pre-DNAT socket flow key (for a
	// client to a Service this is the ClusterIP tuple — the same key as every
	// other socket hook). skb granularity: one retransmitted skb may be a GSO
	// aggregate of several wire segments, so these are NOT wire-packet
	// counts. Null (not 0) when the tracepoint was unavailable; a present 0
	// means the hook was attached and observed no retransmissions. The peer
	// (dst->src) direction is NOT observable from this hook: peer fields are
	// always null/false, and local values are never copied into them. Only a
	// downstream cohort that knows the local end is the active initiator may
	// read local retrans as an approximation of src->dst retransmissions.
	LocalRetransSKBCount  *uint64 `json:"local_retrans_skb_count"`
	LocalRetransSKBBytes  *uint64 `json:"local_retrans_skb_bytes"`
	LocalRetransAvailable bool    `json:"local_retrans_available"`
	LocalRetransSource    string  `json:"local_retrans_source"`   // "tcp_retransmit_skb" | "mock" | ""
	PeerRetransSKBCount   *uint64 `json:"peer_retrans_skb_count"` // always null
	PeerRetransSKBBytes   *uint64 `json:"peer_retrans_skb_bytes"` // always null
	PeerRetransAvailable  bool    `json:"peer_retrans_available"` // always false

	// Derived rates over the whole session duration from the syscall-level
	// byte counters. bytes_per_second_* is BYTES/s; throughput_bps_* is
	// BITS/s (×8). Null when duration <= 0 or traffic accounting is
	// unavailable; a genuine 0 is possible for a zero-byte direction.
	BytesPerSecondOut *float64 `json:"bytes_per_second_out"`
	BytesPerSecondIn  *float64 `json:"bytes_per_second_in"`
	ThroughputBpsOut  *float64 `json:"throughput_bps_out"`
	ThroughputBpsIn   *float64 `json:"throughput_bps_in"`

	ProtocolGuess            string            `json:"protocol_guess"`
	IsTLSLike                bool              `json:"is_tls_like"`
	TLSVersion               string            `json:"tls_version"`
	SNIHash                  string            `json:"sni_hash"`
	ALPN                     string            `json:"alpn"`
	JA4                      string            `json:"ja4"`
	TLSParseStatus           string            `json:"tls_parse_status"`
	TLSRecordSizeHistogram   map[string]uint64 `json:"tls_record_size_histogram"`
	HandshakeSeen            bool              `json:"handshake_seen"`
	ServerHelloSeen          bool              `json:"server_hello_seen"`
	TLSVersionNegotiated     string            `json:"tls_version_negotiated"`
	ALPNNegotiated           string            `json:"alpn_negotiated"`
	JA4S                     string            `json:"ja4s"`
	TLSServerParseStatus     string            `json:"tls_server_parse_status"`
	SNIVisibility            string            `json:"sni_visibility"`
	VisibilityDegraded       bool              `json:"visibility_degraded"`
	VisibilityDegradedReason string            `json:"visibility_degraded_reason"`

	SamplingApplied    bool    `json:"sampling_applied"`
	SamplingRate       float64 `json:"sampling_rate"`
	SamplingReason     string  `json:"sampling_reason"`
	HistogramTruncated bool    `json:"histogram_truncated"`
	IATOverflow        bool    `json:"iat_overflow"`

	SrcNamespace       string `json:"src_namespace"`
	SrcPodName         string `json:"src_pod_name"`
	SrcPodUID          string `json:"src_pod_uid"`
	SrcNode            string `json:"src_node"`
	SrcContainerName   string `json:"src_container_name"`
	SrcContainerID     string `json:"src_container_id"`
	SrcCgroupID        uint64 `json:"src_cgroup_id"`
	SrcWorkloadKind    string `json:"src_workload_kind"`
	SrcWorkloadName    string `json:"src_workload_name"`
	SrcWorkloadUID     string `json:"src_workload_uid"`
	SrcReplicaSet      string `json:"src_replicaset"`
	SrcPodTemplateHash string `json:"src_pod_template_hash"`
	SrcServiceAccount  string `json:"src_service_account"`
	SrcRevision        string `json:"src_revision"`
	SrcImageDigest     string `json:"src_image_digest"`

	DstNamespace       string `json:"dst_namespace"`
	DstPodName         string `json:"dst_pod_name"`
	DstPodUID          string `json:"dst_pod_uid"`
	DstNode            string `json:"dst_node"`
	DstContainerName   string `json:"dst_container_name"`
	DstContainerID     string `json:"dst_container_id"`
	DstCgroupID        uint64 `json:"dst_cgroup_id"`
	DstWorkloadKind    string `json:"dst_workload_kind"`
	DstWorkloadName    string `json:"dst_workload_name"`
	DstWorkloadUID     string `json:"dst_workload_uid"`
	DstReplicaSet      string `json:"dst_replicaset"`
	DstPodTemplateHash string `json:"dst_pod_template_hash"`
	DstServiceAccount  string `json:"dst_service_account"`
	DstRevision        string `json:"dst_revision"`
	DstImageDigest     string `json:"dst_image_digest"`

	SrcMappingConfidence string `json:"src_mapping_confidence"`
	DstMappingConfidence string `json:"dst_mapping_confidence"`
	MappingMethod        string `json:"mapping_method"`

	// --- v1alpha4 source-identity snapshot contract ---
	// The source identity above is the connection generation's FROZEN
	// snapshot (resolved near establishment), not an emission-time lookup.
	// SrcIdentityFrozen: the snapshot is final for this generation (resolved,
	// terminally missing, or retry budget spent). SrcIdentityObservedTime is
	// when the resolution that produced these fields ran. A missing pod
	// identity keeps an explicit SrcIdentityMissingReason and is NEVER
	// substituted with IP or name. SrcRevisionSource says how src_revision
	// was derived ("replicaset_revision" / "controller_revision_hash" /
	// "pod_template_hash" / "not_applicable" / "unavailable") — src_revision
	// is bound to the POD's own rollout, never the controller's latest.
	// SrcIdentityResolutionMethod is the SOURCE-only resolution path
	// ("cgroup_id" | "pod_ip" | "host_netns" | "external" | "informer_miss" |
	// "unknown"). It must be read for source provenance instead of
	// mapping_method: that field is record-level and reports the
	// DESTINATION's method whenever the source did not resolve via cgroup_id.
	SrcIdentityResolutionMethod string `json:"src_identity_resolution_method"`
	SrcIdentityFrozen           bool   `json:"src_identity_frozen"`
	SrcIdentityObservedTime  string `json:"src_identity_observed_time"`
	SrcIdentityAttempts      uint64 `json:"src_identity_attempts"`
	SrcIdentityMissingReason string `json:"src_identity_missing_reason"`
	SrcRevisionSource        string `json:"src_revision_source"`
	// Constructibility of the history-state keys from THIS record:
	// G1 = src_ip (always present), G2 = pod UID, G3 = namespace + top-level
	// controller kind + controller UID, G4 = G3 + rollout revision
	// (revision_source "not_applicable" still counts as constructible: the
	// workload kind has no rollout dimension and the G4 key degenerates to
	// G3 deterministically).
	SrcKeyG2Available bool `json:"src_key_g2_available"`
	SrcKeyG3Available bool `json:"src_key_g3_available"`
	SrcKeyG4Available bool `json:"src_key_g4_available"`

	// C11: explicit resolution status enums (resolved / service_only /
	// host_network / kube_system / informer_miss / external / unknown) so
	// downstream tooling can distinguish "by-design no pod identity" (etcd
	// loopback, kubelet host-network) from genuine cgroup/informer failures.
	SrcIdentityResolutionStatus string `json:"src_identity_resolution_status"`
	DstIdentityResolutionStatus string `json:"dst_identity_resolution_status"`

	DstServiceName         string `json:"dst_service_name"`
	DstServiceUID          string `json:"dst_service_uid"`
	DstServiceNamespace    string `json:"dst_service_namespace"`
	DstServicePortName     string `json:"dst_service_port_name"`
	DstAppProtocol         string `json:"dst_app_protocol"`
	DstIsServiceBackend    bool   `json:"dst_is_service_backend"`
	DstExternal            bool   `json:"dst_external"`
	SameNamespace          bool   `json:"same_namespace"`
	SameWorkload           bool   `json:"same_workload"`
	CrossNamespace         bool   `json:"cross_namespace"`
	ExpectedEdge           string `json:"expected_edge"`
	NetworkPolicyAllowed   string `json:"network_policy_allowed"`
	PolicyConfidence       string `json:"policy_confidence"`
	RolloutWindow          bool   `json:"rollout_window"`
	HpaScalingWindow       bool   `json:"hpa_scaling_window"`
	NodeVisibilityDegraded bool   `json:"node_visibility_degraded"`

	FeatureSetVersion string   `json:"feature_set_version"`
	FastModelVersion  string   `json:"fast_model_version"`
	FastScore         *float64 `json:"fast_score"`
	FastThreshold     *float64 `json:"fast_threshold"`
	ReasonCodes       []string `json:"reason_codes"`
	ReviewRequired    bool     `json:"review_required"`
	ReviewID          string   `json:"review_id"`
	ReviewScore       *float64 `json:"review_score"`
	ReviewVerdict     string   `json:"review_verdict"`
	ActionSuggestion  string   `json:"action_suggestion"`
	RetentionTier     string   `json:"retention_tier"`
	PayloadCollected  bool     `json:"payload_collected"`

	ScenarioPhase    string `json:"scenario_phase,omitempty"`
	AttackEnabled    string `json:"attack_enabled,omitempty"`
	LoadLevel        string `json:"load_level,omitempty"`
	PodRestartWindow bool   `json:"pod_restart_window"`
}

type Writer struct {
	mu               sync.Mutex
	path             string
	maxBytes         int64
	maxAge           time.Duration
	retentionAge     time.Duration
	retentionBytes   int64
	retentionStop    chan struct{}
	retentionStopped chan struct{}
	openedAt         time.Time
	currentSize      int64
	f                *os.File
	w                *bufio.Writer
}

type WriterOptions struct {
	Path     string
	MaxBytes int64
	MaxAge   time.Duration

	// C14 retention controls. Both bound the *rotated* ledger files; the live
	// `flows.jsonl` is never touched. RetentionInterval is how often the sweep
	// goroutine runs; if zero, defaults to 5 minutes (set to a small value for
	// tests). If RetentionAge and RetentionBytes are both zero, no sweep
	// goroutine is started — preserves the prior unbounded-accumulation
	// behaviour for callers that haven't opted in.
	RetentionAge      time.Duration
	RetentionBytes    int64
	RetentionInterval time.Duration
}

func NewWriter(path string) (*Writer, error) {
	return NewWriterWithOptions(WriterOptions{Path: path})
}

func NewWriterWithOptions(opts WriterOptions) (*Writer, error) {
	w := &Writer{
		path:           opts.Path,
		maxBytes:       opts.MaxBytes,
		maxAge:         opts.MaxAge,
		retentionAge:   opts.RetentionAge,
		retentionBytes: opts.RetentionBytes,
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	if w.retentionAge > 0 || w.retentionBytes > 0 {
		interval := opts.RetentionInterval
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		w.retentionStop = make(chan struct{})
		w.retentionStopped = make(chan struct{})
		go w.retentionLoop(interval)
	}
	return w, nil
}

func (w *Writer) Write(record Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	line := append(b, '\n')
	if err := w.rotateIfNeededLocked(int64(len(line)), time.Now().UTC()); err != nil {
		return err
	}
	if _, err := w.w.Write(line); err != nil {
		return err
	}
	if err := w.w.Flush(); err != nil {
		return err
	}
	w.currentSize += int64(len(line))
	return nil
}

func (w *Writer) Close() error {
	if w.retentionStop != nil {
		close(w.retentionStop)
		// Wait for the sweep goroutine to acknowledge so we don't race the
		// file handle. The goroutine signals retentionStopped on exit.
		<-w.retentionStopped
		w.retentionStop = nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.w.Flush(); err != nil {
		_ = w.f.Close()
		return err
	}
	return w.f.Close()
}

// retentionLoop periodically deletes rotated ledger files that exceed the
// retention bounds. Runs until Close() signals stop. The live `flows.jsonl`
// file is never touched here — that's exclusively managed by rotateIfNeeded.
//
// C14: previously rotated files accumulated indefinitely, filling the host
// disk in ~1 day and indirectly triggering etcd I/O cascades (cluster ENV-2/-3).
func (w *Writer) retentionLoop(interval time.Duration) {
	defer close(w.retentionStopped)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// Run once at startup so an agent that's just been redeployed onto a node
	// with existing accumulated ledger files cleans up immediately.
	w.sweepRetention()
	for {
		select {
		case <-w.retentionStop:
			return
		case <-ticker.C:
			w.sweepRetention()
		}
	}
}

func (w *Writer) sweepRetention() {
	ctx := context.Background()
	deleted, freedBytes, err := sweepLedgerDir(ctx, filepath.Dir(w.path), filepath.Base(w.path), w.retentionAge, w.retentionBytes, time.Now())
	if err != nil {
		log.Printf("ledger retention sweep: %v", err)
		return
	}
	if deleted > 0 {
		log.Printf("ledger retention sweep: deleted %d rotated file(s), freed %d bytes", deleted, freedBytes)
	}
}

// sweepLedgerDir is the pure function backing the sweep so it can be unit-tested
// without touching real time or a real Writer. It scans `dir` for rotated
// ledger siblings of `liveBase` (e.g. liveBase="flows.jsonl" → matches
// "flows-*.jsonl") and deletes the oldest first until both bounds are met.
//
//   - retentionAge   > 0: delete files whose mtime is older than now-retentionAge
//   - retentionBytes > 0: delete oldest files until total rotated bytes ≤ this
//
// Returns the number of files deleted and the bytes freed. The live `liveBase`
// itself is always preserved.
func sweepLedgerDir(_ context.Context, dir, liveBase string, retentionAge time.Duration, retentionBytes int64, now time.Time) (int, int64, error) {
	ext := filepath.Ext(liveBase)
	stem := strings.TrimSuffix(liveBase, ext)
	prefix := stem + "-" // rotated files are stem-<timestamp>.ext

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, err
	}

	type rotated struct {
		path  string
		mtime time.Time
		size  int64
	}
	var files []rotated
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == liveBase {
			continue // never touch the live file
		}
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ext) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, rotated{
			path:  filepath.Join(dir, name),
			mtime: info.ModTime(),
			size:  info.Size(),
		})
	}
	if len(files) == 0 {
		return 0, 0, nil
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mtime.Before(files[j].mtime) })

	deleted := 0
	freed := int64(0)
	remaining := make([]rotated, 0, len(files))

	// Age-based pass first: anything older than retentionAge is unconditionally
	// gone. Files inside the window are candidates for the byte-budget pass.
	if retentionAge > 0 {
		cutoff := now.Add(-retentionAge)
		for _, f := range files {
			if f.mtime.Before(cutoff) {
				if err := os.Remove(f.path); err == nil {
					deleted++
					freed += f.size
				}
				continue
			}
			remaining = append(remaining, f)
		}
	} else {
		remaining = files
	}

	// Byte-budget pass: oldest first until total ≤ retentionBytes.
	if retentionBytes > 0 {
		var total int64
		for _, f := range remaining {
			total += f.size
		}
		i := 0
		for total > retentionBytes && i < len(remaining) {
			if err := os.Remove(remaining[i].path); err == nil {
				deleted++
				freed += remaining[i].size
				total -= remaining[i].size
			}
			i++
		}
	}

	return deleted, freed, nil
}

func (w *Writer) open() error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f = f
	w.w = bufio.NewWriter(f)
	w.openedAt = time.Now().UTC()
	w.currentSize = info.Size()
	return nil
}

func (w *Writer) rotateIfNeededLocked(nextBytes int64, now time.Time) error {
	sizeExceeded := w.maxBytes > 0 && w.currentSize > 0 && w.currentSize+nextBytes > w.maxBytes
	ageExceeded := w.maxAge > 0 && !w.openedAt.IsZero() && now.Sub(w.openedAt) >= w.maxAge
	if !sizeExceeded && !ageExceeded {
		return nil
	}
	if err := w.w.Flush(); err != nil {
		return err
	}
	if err := w.f.Close(); err != nil {
		return err
	}
	if w.currentSize > 0 {
		if err := os.Rename(w.path, rotatedPath(w.path, now)); err != nil {
			return err
		}
	}
	return w.open()
}

func rotatedPath(path string, t time.Time) string {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, name+"-"+t.UTC().Format("20060102-150405.000000000")+ext)
}

type BuildContext struct {
	ClusterID      string
	AgentID        string
	CollectionMode string
	HookSource     string
}

func BuildRecord(session sessionizer.FlowSession, resolved identity.ResolvedFlow, labels experiment.Labels) Record {
	return BuildRecordWithContext(session, resolved, labels, BuildContext{})
}

func BuildRecordWithContext(session sessionizer.FlowSession, resolved identity.ResolvedFlow, labels experiment.Labels, ctx BuildContext) Record {
	recordType := session.RecordType
	if recordType == "" {
		recordType = "session_summary"
	}
	snapshot := session.FeatureSnapshot
	if snapshot.PktSizeHistogram == nil {
		snapshot.PktSizeHistogram = features.EmptyPacketSizeHistogram()
	}
	if snapshot.IATHistogram == nil {
		snapshot.IATHistogram = features.EmptyIATHistogram()
	}
	protocolGuess := features.ProtocolGuess(session.Protocol, session.DstPort)
	isTLSLike := features.IsTLSLike(protocolGuess, session.DstPort)
	sameNamespace := nonEmptyEqual(resolved.Src.Namespace, resolved.Dst.Namespace)
	sameWorkload := nonEmptyEqual(resolved.Src.WorkloadUID, resolved.Dst.WorkloadUID)
	crossNamespace := resolved.Src.Namespace != "" && resolved.Dst.Namespace != "" && resolved.Src.Namespace != resolved.Dst.Namespace
	tlsMetadataUnavailable := isTLSLike && !session.HandshakeSeen
	visibilityDegraded := !snapshot.TrafficAccountingAvailable || tlsMetadataUnavailable
	visibilityReason := visibilityDegradedReason(snapshot, tlsMetadataUnavailable)
	reasonCodes := features.ReasonCodes(features.ReasonContext{
		CrossNamespace:      crossNamespace,
		ExternalDestination: resolved.Dst.External,
		LongLived:           snapshot.IsLongLived,
		UnknownIdentity:     resolved.Src.Confidence == features.Unknown || resolved.Dst.Confidence == features.Unknown,
		RolloutWindow:       false,
		VisibilityDegraded:  visibilityDegraded,
	})
	direction := deriveDirection(session.Direction, resolved)
	srcCgroupID := resolved.Src.CgroupID
	if srcCgroupID == 0 {
		srcCgroupID = session.CgroupID
	}
	isWindow := recordType == "window_summary"
	srcKeyG2 := resolved.Src.PodUID != ""
	srcKeyG3 := resolved.Src.Namespace != "" && resolved.Src.WorkloadKind != "" && resolved.Src.WorkloadUID != ""
	srcKeyG4 := srcKeyG3 && (resolved.Src.Revision != "" ||
		session.SourceIdentity.RevisionSource == k8smeta.RevisionSourceNotApplicable)
	counterSemantics := "lifetime_cumulative"
	if isWindow {
		counterSemantics = "window_delta"
	}
	// Rates on a window record cover the window's data span, not the whole
	// connection; on lifetime records they keep the whole-session duration.
	rateDurationMS := session.DurationMS
	if isWindow && !session.WindowStartTime.IsZero() {
		rateDurationMS = session.EndTime.Sub(session.WindowStartTime).Milliseconds()
	}

	return Record{
		SchemaVersion:  features.SchemaVersion,
		RecordType:     recordType,
		ClusterID:      ctx.ClusterID,
		NodeName:       session.NodeName,
		AgentID:        ctx.AgentID,
		CollectionMode: firstNonEmpty(ctx.CollectionMode, features.Unknown),
		HookSource:     firstNonEmpty(ctx.HookSource, features.Unknown),
		StartTime:      formatTime(session.StartTime),
		EndTime:        formatTime(session.EndTime),
		ExperimentID:   labels.ExperimentID,
		ScenarioLabel:  labels.ScenarioLabel,

		FlowID:   session.FlowID,
		WindowID: session.WindowID,

		CounterSemantics:    counterSemantics,
		WindowValid:         isWindow && session.WindowValid,
		WindowInvalidReason: session.WindowInvalidReason,
		CounterEpoch:        session.CounterEpoch,
		FinalWindow:         isWindow && session.FinalWindow,
		WindowStartTime:     formatTime(session.WindowStartTime),
		SrcIP:         session.SrcIP,
		SrcPort:       session.SrcPort,
		DstIP:         session.DstIP,
		DstPort:       session.DstPort,
		Protocol:      session.Protocol,
		Direction:     direction,
		IPFamily:      firstNonEmpty(session.IPFamily, features.Unknown),
		ConnStartTime: formatTime(session.StartTime),
		ConnEndTime:   formatTime(session.EndTime),
		DurationMS:    session.DurationMS,
		TCPState:      firstNonEmpty(session.TCPState, features.Unknown),
		CloseReason:   firstNonEmpty(session.CloseReason, features.Unknown),
		IsLongLived:   snapshot.IsLongLived,
		NetnsIno:      session.NetnsIno,

		BytesOut:                   session.BytesOut,
		BytesIn:                    session.BytesIn,
		PacketsOut:                 session.PacketsOut,
		PacketsIn:                  session.PacketsIn,
		BytesTotal:                 snapshot.BytesTotal,
		PacketsTotal:               snapshot.PacketsTotal,
		ByteRatioOutIn:             snapshot.ByteRatioOutIn,
		PacketRatioOutIn:           snapshot.PacketRatioOutIn,
		DirectionChanges:           snapshot.DirectionChanges,
		PktSizeMin:                 snapshot.PktSizeMin,
		PktSizeMax:                 snapshot.PktSizeMax,
		PktSizeMean:                snapshot.PktSizeMean,
		PktSizeP50:                 snapshot.PktSizeP50,
		PktSizeP95:                 snapshot.PktSizeP95,
		PktSizeStd:                 snapshot.PktSizeStd,
		PktSizeHistogram:           snapshot.PktSizeHistogram,
		IATMean:                    snapshot.IATMean,
		IATP50:                     snapshot.IATP50,
		IATP95:                     snapshot.IATP95,
		IATStd:                     snapshot.IATStd,
		IATHistogram:               snapshot.IATHistogram,
		IdleGapCount:               snapshot.IdleGapCount,
		BurstCount:                 snapshot.BurstCount,
		ByteRate:                   snapshot.ByteRate,
		PacketRate:                 snapshot.PacketRate,
		SYNCount:                   snapshot.SYNCount,
		FINCount:                   snapshot.FINCount,
		RSTCount:                   snapshot.RSTCount,
		RetransCount:               snapshot.RetransCount,
		RTTEstimateUS:              snapshot.RTTEstimateUS,
		TrafficAccountingAvailable: snapshot.TrafficAccountingAvailable,
		PacketTimingAvailable:      snapshot.PacketTimingAvailable,
		TCPMetricsAvailable:        snapshot.TCPMetricsAvailable,

		ObservedSKBPacketsOut:       session.ObservedSKBPacketsOut,
		ObservedSKBPacketsIn:        session.ObservedSKBPacketsIn,
		ObservedSKBPacketsTotal:     session.ObservedSKBPacketsOut + session.ObservedSKBPacketsIn,
		ObservedSKBPacketsAvailable: session.ObservedSKBPacketsAvailable,
		ObservedSKBPacketsSource:    session.ObservedSKBPacketsSource,

		CounterResetDetected: session.CounterResetDetected || snapshot.CounterResetDetected,
		CounterResetCount:    session.CounterResetCount + snapshot.CounterResetCount,

		IPTTLMin:       session.IPTTLMin,
		IPTTLMax:       session.IPTTLMax,
		IPTTLAvailable: session.IPTTLMin != nil,

		// Availability comes from the per-direction header-observed witness,
		// never from the flag/window VALUES: an observed direction with
		// flags==0 (TCP NULL scan) or window==0 serializes a genuine 0, an
		// unobserved direction serializes null.
		TCPFlagsAll:       flagsIfObserved(session.TCPFlagsOut|session.TCPFlagsIn, session.TCPHeaderObservedOut || session.TCPHeaderObservedIn),
		TCPFlagsOut:       flagsIfObserved(session.TCPFlagsOut, session.TCPHeaderObservedOut),
		TCPFlagsIn:        flagsIfObserved(session.TCPFlagsIn, session.TCPHeaderObservedIn),
		TCPFlagsAvailable: session.TCPHeaderObservedOut || session.TCPHeaderObservedIn,

		TCPWindowMaxOut:    session.TCPWindowMaxOut,
		TCPWindowMaxIn:     session.TCPWindowMaxIn,
		TCPWindowAvailable: session.TCPWindowMaxOut != nil || session.TCPWindowMaxIn != nil,

		DirectionDurationOutMS:     durationMSIfObserved(session.DirectionDurationOutNS, session.DirectionDurationOutObserved),
		DirectionDurationInMS:      durationMSIfObserved(session.DirectionDurationInNS, session.DirectionDurationInObserved),
		DirectionDurationAvailable: session.DirectionDurationOutObserved || session.DirectionDurationInObserved,

		IPPktLenMin:       session.IPPktLenMin,
		IPPktLenMax:       session.IPPktLenMax,
		IPPktLenAvailable: session.IPPktLenMin != nil,

		NetFlowV2IPSizeHistogram:          snapshot.NetFlowV2IPSizeHistogram,
		NetFlowV2IPSizeHistogramAvailable: snapshot.NetFlowV2IPSizeHistogramAvailable,

		LocalRetransSKBCount:  counterIfAvailable(session.LocalRetransSKBCount, session.LocalRetransAvailable),
		LocalRetransSKBBytes:  counterIfAvailable(session.LocalRetransSKBBytes, session.LocalRetransAvailable),
		LocalRetransAvailable: session.LocalRetransAvailable,
		LocalRetransSource:    session.LocalRetransSource,
		// PeerRetrans* deliberately stay zero-valued (null/false): remote-side
		// retransmissions are unobservable from local hooks.

		BytesPerSecondOut: rateBytesPerSecond(session.BytesOut, rateDurationMS, snapshot.TrafficAccountingAvailable),
		BytesPerSecondIn:  rateBytesPerSecond(session.BytesIn, rateDurationMS, snapshot.TrafficAccountingAvailable),
		ThroughputBpsOut:  rateBitsPerSecond(session.BytesOut, rateDurationMS, snapshot.TrafficAccountingAvailable),
		ThroughputBpsIn:   rateBitsPerSecond(session.BytesIn, rateDurationMS, snapshot.TrafficAccountingAvailable),

		ProtocolGuess:            protocolGuess,
		IsTLSLike:                isTLSLike,
		TLSVersion:               session.TLSVersion,
		SNIHash:                  session.SNIHash,
		ALPN:                     session.ALPN,
		JA4:                      session.JA4,
		TLSParseStatus:           firstNonEmpty(session.TLSParseStatus, "not_inspected"),
		TLSRecordSizeHistogram:   features.EmptyPacketSizeHistogram(),
		HandshakeSeen:            session.HandshakeSeen,
		ServerHelloSeen:          session.ServerHelloSeen,
		TLSVersionNegotiated:     session.TLSVersionNegotiated,
		ALPNNegotiated:           session.ALPNNegotiated,
		JA4S:                     session.JA4S,
		TLSServerParseStatus:     firstNonEmpty(session.TLSServerParseStatus, "not_inspected"),
		SNIVisibility:            features.Unknown,
		VisibilityDegraded:       visibilityDegraded,
		VisibilityDegradedReason: visibilityReason,

		SamplingApplied:    session.SamplingApplied,
		SamplingRate:       samplingRate(session.SamplingRate),
		SamplingReason:     firstNonEmpty(session.SamplingReason, "none"),
		HistogramTruncated: session.HistogramTruncated,
		IATOverflow:        session.IATOverflow,

		SrcNamespace:       resolved.Src.Namespace,
		SrcPodName:         resolved.Src.PodName,
		SrcPodUID:          resolved.Src.PodUID,
		SrcNode:            resolved.Src.NodeName,
		SrcContainerName:   resolved.Src.ContainerName,
		SrcContainerID:     resolved.Src.ContainerID,
		SrcCgroupID:        srcCgroupID,
		SrcWorkloadKind:    resolved.Src.WorkloadKind,
		SrcWorkloadName:    resolved.Src.WorkloadName,
		SrcWorkloadUID:     resolved.Src.WorkloadUID,
		SrcReplicaSet:      resolved.Src.ReplicaSet,
		SrcPodTemplateHash: resolved.Src.PodTemplateHash,
		SrcServiceAccount:  resolved.Src.ServiceAccount,
		SrcRevision:        resolved.Src.Revision,
		SrcImageDigest:     resolved.Src.ImageDigest,

		DstNamespace:       resolved.Dst.Namespace,
		DstPodName:         resolved.Dst.PodName,
		DstPodUID:          resolved.Dst.PodUID,
		DstNode:            resolved.Dst.NodeName,
		DstContainerName:   resolved.Dst.ContainerName,
		DstContainerID:     resolved.Dst.ContainerID,
		DstCgroupID:        resolved.Dst.CgroupID,
		DstWorkloadKind:    resolved.Dst.WorkloadKind,
		DstWorkloadName:    resolved.Dst.WorkloadName,
		DstWorkloadUID:     resolved.Dst.WorkloadUID,
		DstReplicaSet:      resolved.Dst.ReplicaSet,
		DstPodTemplateHash: resolved.Dst.PodTemplateHash,
		DstServiceAccount:  resolved.Dst.ServiceAccount,
		DstRevision:        resolved.Dst.Revision,
		DstImageDigest:     resolved.Dst.ImageDigest,

		SrcMappingConfidence: resolved.Src.Confidence,
		DstMappingConfidence: resolved.Dst.Confidence,
		MappingMethod:        resolved.MappingMethod,

		SrcIdentityResolutionMethod: resolved.Src.Method,
		SrcIdentityFrozen:           session.SourceIdentity.Frozen,
		SrcIdentityObservedTime:  formatTime(session.SourceIdentity.ObservedAt),
		SrcIdentityAttempts:      session.SourceIdentity.Attempts,
		SrcIdentityMissingReason: session.SourceIdentity.MissingReason,
		SrcRevisionSource:        session.SourceIdentity.RevisionSource,
		SrcKeyG2Available:        srcKeyG2,
		SrcKeyG3Available:        srcKeyG3,
		SrcKeyG4Available:        srcKeyG4,

		SrcIdentityResolutionStatus: firstNonEmpty(resolved.Src.ResolutionStatus, identity.ResolutionStatusUnknown),
		DstIdentityResolutionStatus: firstNonEmpty(resolved.Dst.ResolutionStatus, identity.ResolutionStatusUnknown),

		DstServiceName:         resolved.Dst.ServiceName,
		DstServiceUID:          resolved.Dst.ServiceUID,
		DstServiceNamespace:    resolved.Dst.ServiceNamespace,
		DstServicePortName:     resolved.Dst.ServicePortName,
		DstAppProtocol:         resolved.Dst.AppProtocol,
		DstIsServiceBackend:    resolved.Dst.ServiceName != "" && resolved.Dst.PodName != "",
		DstExternal:            resolved.Dst.External,
		SameNamespace:          sameNamespace,
		SameWorkload:           sameWorkload,
		CrossNamespace:         crossNamespace,
		ExpectedEdge:           features.Unknown,
		NetworkPolicyAllowed:   features.Unknown,
		PolicyConfidence:       features.Unknown,
		RolloutWindow:          false,
		HpaScalingWindow:       false,
		NodeVisibilityDegraded: session.NodeName == "",

		FeatureSetVersion: features.FeatureSetVersion,
		FastModelVersion:  "none",
		FastScore:         nil,
		FastThreshold:     nil,
		ReasonCodes:       reasonCodes,
		ReviewRequired:    len(reasonCodes) > 0,
		ReviewID:          "",
		ReviewScore:       nil,
		ReviewVerdict:     features.Unknown,
		ActionSuggestion:  "observe",
		RetentionTier:     "standard",
		PayloadCollected:  false,

		ScenarioPhase:    labels.ScenarioPhase,
		AttackEnabled:    labels.AttackEnabled,
		LoadLevel:        labels.LoadLevel,
		PodRestartWindow: resolved.PodRestartWindow,
	}
}

// counterIfAvailable serializes a cumulative counter whose validity depends on
// a hook having been attached: null when unavailable (0 must never impersonate
// "confirmed none"), a genuine value — possibly 0 — when available.
func counterIfAvailable(v uint64, available bool) *uint64 {
	if !available {
		return nil
	}
	return &v
}

// flagsIfObserved serializes a TCP flag OR-mask gated on the header-observed
// witness: null when no TCP header was ever read (observed=false), otherwise
// the mask — including a genuine 0 for flows whose every observed segment
// carried an all-zero flag byte (TCP NULL scan). Availability must never be
// inferred from the mask value itself.
func flagsIfObserved(flags uint32, observed bool) *uint32 {
	if !observed {
		return nil
	}
	return &flags
}

// durationMSIfObserved converts a per-direction active span to milliseconds.
// One observed packet is a genuine 0 ms; a never-observed direction is null.
func durationMSIfObserved(durationNS uint64, observed bool) *uint64 {
	if !observed {
		return nil
	}
	v := durationNS / 1_000_000
	return &v
}

// rateBytesPerSecond is BYTES per second over the whole session duration;
// rateBitsPerSecond is the same quantity in BITS per second (×8). Both are
// null when the duration is not positive or traffic accounting is
// unavailable — division by a zero duration is never performed.
func rateBytesPerSecond(bytes uint64, durationMS int64, accountingAvailable bool) *float64 {
	if durationMS <= 0 || !accountingAvailable {
		return nil
	}
	v := float64(bytes) / (float64(durationMS) / 1000.0)
	return &v
}

func rateBitsPerSecond(bytes uint64, durationMS int64, accountingAvailable bool) *float64 {
	perSecond := rateBytesPerSecond(bytes, durationMS, accountingAvailable)
	if perSecond == nil {
		return nil
	}
	v := *perSecond * 8
	return &v
}

func samplingRate(v float64) float64 {
	if v <= 0 {
		return 1.0
	}
	return v
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func deriveDirection(current string, resolved identity.ResolvedFlow) string {
	if current == "local" {
		return "local"
	}
	if resolved.Src.External && !resolved.Dst.External {
		return "ingress"
	}
	if resolved.Dst.External && !resolved.Src.External {
		return "egress"
	}
	if current != "" && current != features.Unknown {
		return current
	}
	return features.Unknown
}

func nonEmptyEqual(a, b string) bool {
	return a != "" && b != "" && a == b
}

func visibilityDegradedReason(snapshot features.Snapshot, isTLSLike bool) string {
	reasons := []string{}
	if !snapshot.TrafficAccountingAvailable {
		reasons = append(reasons, "traffic_accounting_unavailable")
	}
	if isTLSLike {
		reasons = append(reasons, "tls_metadata_unavailable")
	}
	if len(reasons) == 0 {
		return ""
	}
	return strings.Join(reasons, ",")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
