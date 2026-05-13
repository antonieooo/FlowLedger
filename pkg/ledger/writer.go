package ledger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"FlowLedger/pkg/experiment"
	"FlowLedger/pkg/features"
	"FlowLedger/pkg/identity"
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

	FlowID        string `json:"flow_id"`
	WindowID      uint64 `json:"window_id"`
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
	PktSizeHistogram           map[string]uint64 `json:"pkt_size_histogram"`
	IATP50                     *float64          `json:"iat_p50"`
	IATP95                     *float64          `json:"iat_p95"`
	IATStd                     *float64          `json:"iat_std"`
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
	mu          sync.Mutex
	path        string
	maxBytes    int64
	maxAge      time.Duration
	openedAt    time.Time
	currentSize int64
	f           *os.File
	w           *bufio.Writer
}

type WriterOptions struct {
	Path     string
	MaxBytes int64
	MaxAge   time.Duration
}

func NewWriter(path string) (*Writer, error) {
	return NewWriterWithOptions(WriterOptions{Path: path})
}

func NewWriterWithOptions(opts WriterOptions) (*Writer, error) {
	w := &Writer{
		path:     opts.Path,
		maxBytes: opts.MaxBytes,
		maxAge:   opts.MaxAge,
	}
	if err := w.open(); err != nil {
		return nil, err
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
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.w.Flush(); err != nil {
		_ = w.f.Close()
		return err
	}
	return w.f.Close()
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

		FlowID:        session.FlowID,
		WindowID:      session.WindowID,
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
		PktSizeHistogram:           snapshot.PktSizeHistogram,
		IATP50:                     snapshot.IATP50,
		IATP95:                     snapshot.IATP95,
		IATStd:                     snapshot.IATStd,
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
