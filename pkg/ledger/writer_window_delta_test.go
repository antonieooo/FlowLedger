package ledger

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"FlowLedger/pkg/collector"
	"FlowLedger/pkg/experiment"
	"FlowLedger/pkg/identity"
	"FlowLedger/pkg/sessionizer"
)

func windowTestEvent(ts time.Time, evType string, bytesOut uint64) collector.FlowEvent {
	return collector.FlowEvent{
		TimestampNS:                uint64(ts.UnixNano()),
		EventType:                  evType,
		SrcIP:                      "10.1.1.10",
		SrcPort:                    40000,
		DstIP:                      "10.1.1.20",
		DstPort:                    443,
		Protocol:                   "tcp",
		CounterSemantics:           collector.CounterSemanticsCumulative,
		TrafficAccountingAvailable: true,
		BytesSent:                  bytesOut,
	}
}

// v1alpha4 contract: window_summary records self-describe as window deltas
// (counter_semantics/window_valid/final_window/window_start_time), while the
// session_summary stays a lifetime_cumulative diagnostic that a window
// dataset (record_type == "window_summary") can never double-count.
func TestRecordWindowDeltaContractFields(t *testing.T) {
	base := time.Unix(2100, 0).UTC()
	s := sessionizer.New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(windowTestEvent(base, "CONNECT", 0))

	out := s.Process(windowTestEvent(base.Add(10*time.Second), "STATS", 150))
	if len(out) != 1 {
		t.Fatalf("window: got %d records, want 1", len(out))
	}
	windowRecord := BuildRecord(out[0], identity.ResolvedFlow{}, experiment.Labels{})
	if windowRecord.CounterSemantics != "window_delta" {
		t.Fatalf("window counter_semantics = %q, want window_delta", windowRecord.CounterSemantics)
	}
	if !windowRecord.WindowValid || windowRecord.WindowInvalidReason != "" || windowRecord.FinalWindow {
		t.Fatalf("window flags wrong: %#v", windowRecord)
	}
	if windowRecord.BytesOut != 150 || windowRecord.CounterEpoch != 0 {
		t.Fatalf("window counters wrong: bytes=%d epoch=%d", windowRecord.BytesOut, windowRecord.CounterEpoch)
	}
	if windowRecord.WindowStartTime == "" {
		t.Fatalf("window_start_time missing on window record")
	}
	raw, err := json.Marshal(windowRecord)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"counter_semantics":"window_delta"`, `"window_valid":true`, `"final_window":false`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("serialized window record missing %s", want)
		}
	}

	out = s.Process(windowTestEvent(base.Add(12*time.Second), "CLOSE", 200))
	if len(out) != 2 {
		t.Fatalf("close: got %d records, want final window + summary", len(out))
	}
	finalRecord := BuildRecord(out[0], identity.ResolvedFlow{}, experiment.Labels{})
	if finalRecord.CounterSemantics != "window_delta" || !finalRecord.FinalWindow || !finalRecord.WindowValid {
		t.Fatalf("final window flags wrong: %#v", finalRecord)
	}
	if finalRecord.BytesOut != 50 {
		t.Fatalf("final window bytes = %d, want 50 (200-150)", finalRecord.BytesOut)
	}

	summaryRecord := BuildRecord(out[1], identity.ResolvedFlow{}, experiment.Labels{})
	if summaryRecord.CounterSemantics != "lifetime_cumulative" {
		t.Fatalf("summary counter_semantics = %q, want lifetime_cumulative", summaryRecord.CounterSemantics)
	}
	if summaryRecord.WindowValid || summaryRecord.FinalWindow || summaryRecord.WindowStartTime != "" {
		t.Fatalf("summary must not look like a window: %#v", summaryRecord)
	}
	if summaryRecord.RecordType != "session_summary" || summaryRecord.BytesOut != 200 {
		t.Fatalf("summary lifetime totals wrong: type=%q bytes=%d", summaryRecord.RecordType, summaryRecord.BytesOut)
	}
	// The window dataset predicate excludes the summary by record_type alone.
	if summaryRecord.RecordType == windowRecord.RecordType {
		t.Fatalf("summary and window share a record_type; dataset split impossible")
	}
}

// An unknown-baseline window serializes as an explicitly invalid window
// sample with zeroed counters, never as a plausible delta.
func TestRecordUnknownBaselineWindowInvalid(t *testing.T) {
	base := time.Unix(2200, 0).UTC()
	s := sessionizer.New("node-a", 5*time.Minute, 10*time.Second)
	// Mid-flight first sighting: no CONNECT, 500 cumulative bytes.
	s.Process(windowTestEvent(base, "STATS", 500))
	out := s.Process(windowTestEvent(base.Add(10*time.Second), "STATS", 800))
	if len(out) != 1 {
		t.Fatalf("window: got %d records, want 1", len(out))
	}
	record := BuildRecord(out[0], identity.ResolvedFlow{}, experiment.Labels{})
	if record.CounterSemantics != "window_delta" || record.WindowValid {
		t.Fatalf("unknown-baseline record flags wrong: %#v", record)
	}
	if record.WindowInvalidReason != sessionizer.WindowInvalidUnknownBaseline {
		t.Fatalf("invalid reason = %q, want %q", record.WindowInvalidReason, sessionizer.WindowInvalidUnknownBaseline)
	}
	if record.BytesOut != 0 || record.BytesTotal != 0 {
		t.Fatalf("invalid window leaked counters: %#v", record)
	}
}
