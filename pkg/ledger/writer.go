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
