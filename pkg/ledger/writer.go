package ledger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"FlowLedger/pkg/experiment"
	"FlowLedger/pkg/identity"
	"FlowLedger/pkg/sessionizer"
)

type Record struct {
	RecordType string `json:"record_type"`
	FlowID     string `json:"flow_id"`
	NodeName   string `json:"node_name"`
	StartTime  string `json:"start_time"`
	EndTime    string `json:"end_time"`
	DurationMS int64  `json:"duration_ms"`

	SrcIP    string `json:"src_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`

	BytesOut   uint64 `json:"bytes_out"`
	BytesIn    uint64 `json:"bytes_in"`
	PacketsOut uint64 `json:"packets_out"`
	PacketsIn  uint64 `json:"packets_in"`

	SrcNamespace      string `json:"src_namespace"`
	SrcPodName        string `json:"src_pod_name"`
	SrcPodUID         string `json:"src_pod_uid"`
	SrcWorkloadKind   string `json:"src_workload_kind"`
	SrcWorkloadName   string `json:"src_workload_name"`
	SrcWorkloadUID    string `json:"src_workload_uid"`
	SrcServiceAccount string `json:"src_service_account"`
	SrcRevision       string `json:"src_revision"`

	DstNamespace      string `json:"dst_namespace"`
	DstPodName        string `json:"dst_pod_name"`
	DstPodUID         string `json:"dst_pod_uid"`
	DstWorkloadKind   string `json:"dst_workload_kind"`
	DstWorkloadName   string `json:"dst_workload_name"`
	DstWorkloadUID    string `json:"dst_workload_uid"`
	DstServiceAccount string `json:"dst_service_account"`
	DstServiceName    string `json:"dst_service_name"`
	DstExternal       bool   `json:"dst_external"`

	SrcMappingConfidence string `json:"src_mapping_confidence"`
	DstMappingConfidence string `json:"dst_mapping_confidence"`
	MappingMethod        string `json:"mapping_method"`

	ExperimentID     string `json:"experiment_id"`
	ScenarioLabel    string `json:"scenario_label"`
	ScenarioPhase    string `json:"scenario_phase,omitempty"`
	AttackEnabled    string `json:"attack_enabled,omitempty"`
	LoadLevel        string `json:"load_level,omitempty"`
	RolloutWindow    bool   `json:"rollout_window"`
	PodRestartWindow bool   `json:"pod_restart_window"`
}

type Writer struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
}

func NewWriter(path string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &Writer{f: f, w: bufio.NewWriter(f)}, nil
}

func (w *Writer) Write(record Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if _, err := w.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return w.w.Flush()
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

func BuildRecord(session sessionizer.FlowSession, resolved identity.ResolvedFlow, labels experiment.Labels) Record {
	recordType := session.RecordType
	if recordType == "" {
		recordType = "session_summary"
	}
	return Record{
		RecordType: recordType,
		FlowID:     session.FlowID,
		NodeName:   session.NodeName,
		StartTime:  formatTime(session.StartTime),
		EndTime:    formatTime(session.EndTime),
		DurationMS: session.DurationMS,
		SrcIP:      session.SrcIP,
		SrcPort:    session.SrcPort,
		DstIP:      session.DstIP,
		DstPort:    session.DstPort,
		Protocol:   session.Protocol,
		BytesOut:   session.BytesOut,
		BytesIn:    session.BytesIn,
		PacketsOut: session.PacketsOut,
		PacketsIn:  session.PacketsIn,

		SrcNamespace:      resolved.Src.Namespace,
		SrcPodName:        resolved.Src.PodName,
		SrcPodUID:         resolved.Src.PodUID,
		SrcWorkloadKind:   resolved.Src.WorkloadKind,
		SrcWorkloadName:   resolved.Src.WorkloadName,
		SrcWorkloadUID:    resolved.Src.WorkloadUID,
		SrcServiceAccount: resolved.Src.ServiceAccount,
		SrcRevision:       resolved.Src.Revision,

		DstNamespace:      resolved.Dst.Namespace,
		DstPodName:        resolved.Dst.PodName,
		DstPodUID:         resolved.Dst.PodUID,
		DstWorkloadKind:   resolved.Dst.WorkloadKind,
		DstWorkloadName:   resolved.Dst.WorkloadName,
		DstWorkloadUID:    resolved.Dst.WorkloadUID,
		DstServiceAccount: resolved.Dst.ServiceAccount,
		DstServiceName:    resolved.Dst.ServiceName,
		DstExternal:       resolved.Dst.External,

		SrcMappingConfidence: resolved.Src.Confidence,
		DstMappingConfidence: resolved.Dst.Confidence,
		MappingMethod:        resolved.MappingMethod,

		ExperimentID:     labels.ExperimentID,
		ScenarioLabel:    labels.ScenarioLabel,
		ScenarioPhase:    labels.ScenarioPhase,
		AttackEnabled:    labels.AttackEnabled,
		LoadLevel:        labels.LoadLevel,
		RolloutWindow:    false,
		PodRestartWindow: resolved.PodRestartWindow,
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
