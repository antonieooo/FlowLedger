package sessionizer

import (
	"testing"
	"time"

	"FlowLedger/pkg/collector"
)

// Helpers for the v1alpha4 window-delta tests. All events use cumulative
// (eBPF) counter semantics: every event carries totals since flow start.

func cumEvent(ts time.Time, evType string, bytesOut, bytesIn uint64) collector.FlowEvent {
	ev := collector.FlowEvent{
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
		BytesRecv:                  bytesIn,
	}
	if evType == "CONNECT" {
		ev.SYNCount = 1
	}
	return ev
}

func requireWindow(t *testing.T, got FlowSession, wantValid bool, wantReason string, wantBytesOut uint64) {
	t.Helper()
	if got.RecordType != "window_summary" {
		t.Fatalf("record_type = %q, want window_summary: %#v", got.RecordType, got)
	}
	if got.WindowValid != wantValid || got.WindowInvalidReason != wantReason {
		t.Fatalf("window validity = (%v, %q), want (%v, %q)", got.WindowValid, got.WindowInvalidReason, wantValid, wantReason)
	}
	if got.BytesOut != wantBytesOut {
		t.Fatalf("window bytes_out = %d, want %d", got.BytesOut, wantBytesOut)
	}
}

// Case A: cumulative scalar 10 -> 25 -> 40 must yield window deltas
// 10 -> 15 -> 15 across three consecutive windows.
func TestWindowDeltaScalarSequence(t *testing.T) {
	base := time.Unix(1000, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))

	out := s.Process(cumEvent(base.Add(10*time.Second), "STATS", 10, 4))
	if len(out) != 1 {
		t.Fatalf("window 1: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], true, "", 10)
	if out[0].BytesIn != 4 || out[0].WindowID != 1 || out[0].FinalWindow {
		t.Fatalf("window 1 wrong: %#v", out[0])
	}
	if !out[0].WindowStartTime.Equal(base) {
		t.Fatalf("window 1 start = %v, want %v", out[0].WindowStartTime, base)
	}
	if out[0].FeatureSnapshot.BytesTotal != 14 {
		t.Fatalf("window 1 snapshot bytes_total = %d, want 14", out[0].FeatureSnapshot.BytesTotal)
	}
	// First window of a CONNECT-born generation carries its SYN.
	if out[0].FeatureSnapshot.SYNCount != 1 {
		t.Fatalf("window 1 syn = %d, want 1", out[0].FeatureSnapshot.SYNCount)
	}

	out = s.Process(cumEvent(base.Add(20*time.Second), "STATS", 25, 9))
	if len(out) != 1 {
		t.Fatalf("window 2: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], true, "", 15)
	if out[0].BytesIn != 5 || out[0].WindowID != 2 {
		t.Fatalf("window 2 wrong: %#v", out[0])
	}
	if !out[0].WindowStartTime.Equal(base.Add(10 * time.Second)) {
		t.Fatalf("window 2 start = %v, want %v", out[0].WindowStartTime, base.Add(10*time.Second))
	}
	if out[0].FeatureSnapshot.SYNCount != 0 {
		t.Fatalf("window 2 syn = %d, want 0 (SYN belongs to window 1)", out[0].FeatureSnapshot.SYNCount)
	}

	out = s.Process(cumEvent(base.Add(30*time.Second), "STATS", 40, 9))
	if len(out) != 1 {
		t.Fatalf("window 3: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], true, "", 15)
	if out[0].BytesIn != 0 || out[0].WindowID != 3 {
		t.Fatalf("window 3 wrong: %#v", out[0])
	}
}

// Case B (+ scalars and histograms differenced together): cumulative
// histogram [1,2] -> [3,5] must yield window histograms [1,2] -> [2,3].
func TestWindowDeltaHistogramAndScalars(t *testing.T) {
	base := time.Unix(1100, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))

	ev := cumEvent(base.Add(10*time.Second), "STATS", 100, 0)
	ev.PacketSizeHistogram = map[string]uint64{"0-63": 1, "64-127": 2}
	ev.IATHistogram = map[string]uint64{"<100": 4}
	ev.PacketTimingAvailable = true
	out := s.Process(ev)
	if len(out) != 1 {
		t.Fatalf("window 1: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], true, "", 100)
	h := out[0].FeatureSnapshot.PktSizeHistogram
	if h["0-63"] != 1 || h["64-127"] != 2 {
		t.Fatalf("window 1 pkt histogram = %v, want 0-63:1 64-127:2", h)
	}
	if out[0].FeatureSnapshot.IATHistogram["<100"] != 4 {
		t.Fatalf("window 1 iat histogram = %v, want <100:4", out[0].FeatureSnapshot.IATHistogram)
	}

	ev = cumEvent(base.Add(20*time.Second), "STATS", 260, 0)
	ev.PacketSizeHistogram = map[string]uint64{"0-63": 3, "64-127": 5}
	ev.IATHistogram = map[string]uint64{"<100": 6}
	ev.PacketTimingAvailable = true
	out = s.Process(ev)
	if len(out) != 1 {
		t.Fatalf("window 2: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], true, "", 160)
	h = out[0].FeatureSnapshot.PktSizeHistogram
	if h["0-63"] != 2 || h["64-127"] != 3 {
		t.Fatalf("window 2 pkt histogram = %v, want 0-63:2 64-127:3 (delta, not cumulative)", h)
	}
	if out[0].FeatureSnapshot.IATHistogram["<100"] != 2 {
		t.Fatalf("window 2 iat histogram = %v, want <100:2", out[0].FeatureSnapshot.IATHistogram)
	}
}

// Case C: a normal Sweep-driven window emission advances the baseline without
// clearing it; the connection continues and the next window carries only the
// new increment, never re-counting already-emitted history.
func TestWindowCarryoverAcrossSweep(t *testing.T) {
	base := time.Unix(1200, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))
	s.Process(cumEvent(base.Add(1*time.Second), "STATS", 100, 0))

	out := s.Sweep(base.Add(10 * time.Second))
	if len(out) != 1 {
		t.Fatalf("sweep window: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], true, "", 100)
	if out[0].FinalWindow {
		t.Fatalf("sweep window must not be final: %#v", out[0])
	}

	s.Process(cumEvent(base.Add(12*time.Second), "STATS", 250, 0))
	out = s.Process(cumEvent(base.Add(20*time.Second), "STATS", 250, 0))
	if len(out) != 1 {
		t.Fatalf("window 2: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], true, "", 150)
	if s.ActiveCount() != 1 {
		t.Fatalf("session dropped by sweep window emission")
	}
}

// Case D: after an inactivity-timeout close, a new EVENT_CONNECT on the same
// 5-tuple is a NEW connection generation with a fresh zero baseline and a new
// flow_id — it must not difference against the dead generation.
func TestNewConnectAfterTimeoutIsNewGeneration(t *testing.T) {
	base := time.Unix(1300, 0).UTC()
	s := New("node-a", 5*time.Second, 30*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))
	s.Process(cumEvent(base.Add(1*time.Second), "STATS", 100, 0))

	out := s.Sweep(base.Add(7 * time.Second))
	if len(out) != 2 {
		t.Fatalf("timeout: got %d records, want final window + summary", len(out))
	}
	requireWindow(t, out[0], true, "", 100)
	if !out[0].FinalWindow {
		t.Fatalf("timeout flush must be final: %#v", out[0])
	}
	if out[1].RecordType != "session_summary" || out[1].CloseReason != "timeout" {
		t.Fatalf("unexpected timeout summary: %#v", out[1])
	}
	oldFlowID := out[1].FlowID

	if got := s.Process(cumEvent(base.Add(8*time.Second), "CONNECT", 0, 0)); len(got) != 0 {
		t.Fatalf("new CONNECT after timeout emitted %d records, want 0", len(got))
	}
	s.Process(cumEvent(base.Add(9*time.Second), "STATS", 20, 0))
	out = s.Process(cumEvent(base.Add(10*time.Second), "CLOSE", 20, 0))
	if len(out) != 2 {
		t.Fatalf("close: got %d records, want final window + summary", len(out))
	}
	requireWindow(t, out[0], true, "", 20)
	if out[1].BytesOut != 20 {
		t.Fatalf("new generation lifetime bytes = %d, want 20", out[1].BytesOut)
	}
	if out[1].FlowID == oldFlowID {
		t.Fatalf("new generation reused old flow_id %s", oldFlowID)
	}
}

// Case E: a cumulative counter regression invalidates exactly one window
// (zeroed deltas, reason counter_reset), the current snapshot becomes the new
// baseline, the epoch increments, and the next window recovers.
func TestCounterResetInvalidWindowThenRecovers(t *testing.T) {
	base := time.Unix(1400, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))

	out := s.Process(cumEvent(base.Add(10*time.Second), "STATS", 100, 0))
	requireWindow(t, out[0], true, "", 100)
	if out[0].CounterEpoch != 0 {
		t.Fatalf("window 1 epoch = %d, want 0", out[0].CounterEpoch)
	}

	// Kernel accumulator reset: cumulative drops 100 -> 40, then grows.
	s.Process(cumEvent(base.Add(12*time.Second), "STATS", 40, 0))
	out = s.Process(cumEvent(base.Add(20*time.Second), "STATS", 60, 0))
	if len(out) != 1 {
		t.Fatalf("reset window: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], false, WindowInvalidCounterReset, 0)
	if out[0].FeatureSnapshot.BytesTotal != 0 {
		t.Fatalf("invalid window must carry zero deltas: %#v", out[0].FeatureSnapshot)
	}
	if out[0].CounterEpoch != 0 {
		t.Fatalf("invalid window epoch = %d, want 0 (old lineage)", out[0].CounterEpoch)
	}

	out = s.Process(cumEvent(base.Add(30*time.Second), "STATS", 90, 0))
	if len(out) != 1 {
		t.Fatalf("recovery window: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], true, "", 30)
	if out[0].CounterEpoch != 1 {
		t.Fatalf("recovery window epoch = %d, want 1 (new lineage)", out[0].CounterEpoch)
	}
}

// Case E, histogram variant: a single decreasing bucket invalidates the
// window; the next window differences from the post-reset snapshot.
func TestHistogramBucketRegressionInvalidWindow(t *testing.T) {
	base := time.Unix(1500, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))

	ev := cumEvent(base.Add(10*time.Second), "STATS", 10, 0)
	ev.PacketSizeHistogram = map[string]uint64{"0-63": 3}
	out := s.Process(ev)
	requireWindow(t, out[0], true, "", 10)
	if out[0].FeatureSnapshot.PktSizeHistogram["0-63"] != 3 {
		t.Fatalf("window 1 histogram = %v", out[0].FeatureSnapshot.PktSizeHistogram)
	}

	ev = cumEvent(base.Add(20*time.Second), "STATS", 20, 0)
	ev.PacketSizeHistogram = map[string]uint64{"0-63": 2} // bucket went backwards
	out = s.Process(ev)
	requireWindow(t, out[0], false, WindowInvalidCounterReset, 0)
	if out[0].FeatureSnapshot.PktSizeHistogram["0-63"] != 0 {
		t.Fatalf("invalid window histogram must be zeroed: %v", out[0].FeatureSnapshot.PktSizeHistogram)
	}

	ev = cumEvent(base.Add(30*time.Second), "STATS", 25, 0)
	ev.PacketSizeHistogram = map[string]uint64{"0-63": 5}
	out = s.Process(ev)
	requireWindow(t, out[0], true, "", 5)
	if out[0].FeatureSnapshot.PktSizeHistogram["0-63"] != 3 {
		t.Fatalf("recovery window histogram = %v, want 0-63:3 (5-2)", out[0].FeatureSnapshot.PktSizeHistogram)
	}
}

// Case F: CLOSE in the middle of a window flushes the final partial window
// exactly once; the session_summary that follows is a lifetime diagnostic
// record, not a second window; nothing remains to flush afterwards.
func TestCloseMidWindowFlushesFinalPartialWindowOnce(t *testing.T) {
	base := time.Unix(1600, 0).UTC()
	s := New("node-a", 5*time.Minute, 30*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))
	s.Process(cumEvent(base.Add(5*time.Second), "STATS", 100, 40))

	out := s.Process(cumEvent(base.Add(10*time.Second), "CLOSE", 100, 40))
	if len(out) != 2 {
		t.Fatalf("close: got %d records, want final window + summary", len(out))
	}
	requireWindow(t, out[0], true, "", 100)
	if !out[0].FinalWindow || out[0].WindowID != 1 || out[0].BytesIn != 40 {
		t.Fatalf("unexpected final window: %#v", out[0])
	}
	summary := out[1]
	if summary.RecordType != "session_summary" || summary.WindowID != 0 || summary.FinalWindow || summary.WindowValid {
		t.Fatalf("summary must not look like a window: %#v", summary)
	}
	if summary.BytesOut != 100 || summary.BytesIn != 40 {
		t.Fatalf("summary lifetime totals wrong: %#v", summary)
	}
	if got := s.Sweep(base.Add(120 * time.Second)); len(got) != 0 {
		t.Fatalf("closed session flushed again: %#v", got)
	}
}

// Case F, boundary variant: when CLOSE arrives right after a boundary window
// already flushed everything, the final window is a zero-delta record — the
// same increment is never emitted twice.
func TestCloseAtWindowBoundaryZeroDeltaFinalWindow(t *testing.T) {
	base := time.Unix(1700, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))
	out := s.Process(cumEvent(base.Add(10*time.Second), "STATS", 100, 0))
	requireWindow(t, out[0], true, "", 100)

	out = s.Process(cumEvent(base.Add(11*time.Second), "CLOSE", 100, 0))
	if len(out) != 2 {
		t.Fatalf("close: got %d records, want final window + summary", len(out))
	}
	requireWindow(t, out[0], true, "", 0)
	if !out[0].FinalWindow {
		t.Fatalf("boundary close must still flush a final window: %#v", out[0])
	}
	// Across all windows the connection contributed exactly its 100 bytes.
	if out[1].BytesOut != 100 {
		t.Fatalf("summary bytes = %d, want 100", out[1].BytesOut)
	}
}

// Case G: a session first seen mid-flight (no EVENT_CONNECT, e.g. after an
// agent restart) has no trustworthy baseline: the first window is invalid
// (unknown_baseline, zero deltas), the observed snapshot becomes the
// baseline, and subsequent windows difference normally.
func TestUnknownBaselineFirstWindowInvalid(t *testing.T) {
	base := time.Unix(1800, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	// First sighting: 500 cumulative bytes of unknown origin.
	s.Process(cumEvent(base, "STATS", 500, 0))

	out := s.Process(cumEvent(base.Add(10*time.Second), "STATS", 800, 0))
	if len(out) != 1 {
		t.Fatalf("window 1: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], false, WindowInvalidUnknownBaseline, 0)
	if out[0].FeatureSnapshot.BytesTotal != 0 {
		t.Fatalf("unknown-baseline window must not pass cumulative mass as a delta: %#v", out[0].FeatureSnapshot)
	}

	out = s.Process(cumEvent(base.Add(20*time.Second), "STATS", 900, 0))
	if len(out) != 1 {
		t.Fatalf("window 2: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], true, "", 100)
}

// 5-tuple reuse without an observed CLOSE: the CONNECT of the next real
// connection finalizes the previous generation and starts from a zero
// baseline — deltas never mix the two connections.
func TestTupleReuseConnectDoesNotInheritBaseline(t *testing.T) {
	base := time.Unix(1900, 0).UTC()
	s := New("node-a", 5*time.Minute, 30*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))
	s.Process(cumEvent(base.Add(1*time.Second), "STATS", 40, 0))

	out := s.Process(cumEvent(base.Add(5*time.Second), "CONNECT", 0, 0))
	if len(out) != 2 {
		t.Fatalf("superseding CONNECT: got %d records, want final window + summary", len(out))
	}
	requireWindow(t, out[0], true, "", 40)
	if !out[0].FinalWindow {
		t.Fatalf("superseded generation must flush a final window: %#v", out[0])
	}
	if out[1].RecordType != "session_summary" || out[1].BytesOut != 40 {
		t.Fatalf("unexpected superseded summary: %#v", out[1])
	}
	oldFlowID := out[1].FlowID

	s.Process(cumEvent(base.Add(6*time.Second), "STATS", 10, 0))
	out = s.Process(cumEvent(base.Add(7*time.Second), "CLOSE", 10, 0))
	if len(out) != 2 {
		t.Fatalf("close: got %d records, want final window + summary", len(out))
	}
	requireWindow(t, out[0], true, "", 10)
	if out[1].FlowID == oldFlowID {
		t.Fatalf("reused tuple inherited old flow_id %s", oldFlowID)
	}
}

// A window in which nothing happened is a legitimate zero-delta sample:
// valid, all counters zero, no invalid reason.
func TestZeroDeltaWindowValid(t *testing.T) {
	base := time.Unix(2000, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(cumEvent(base, "CONNECT", 0, 0))
	s.Process(cumEvent(base.Add(2*time.Second), "STATS", 100, 0))

	out := s.Sweep(base.Add(10 * time.Second))
	requireWindow(t, out[0], true, "", 100)

	out = s.Sweep(base.Add(20 * time.Second))
	if len(out) != 1 {
		t.Fatalf("idle window: got %d records, want 1", len(out))
	}
	requireWindow(t, out[0], true, "", 0)
	snap := out[0].FeatureSnapshot
	if snap.BytesTotal != 0 || snap.PacketsTotal != 0 || snap.SYNCount != 0 {
		t.Fatalf("zero-delta window carries data: %#v", snap)
	}
	for bucket, count := range snap.PktSizeHistogram {
		if count != 0 {
			t.Fatalf("zero-delta window histogram bucket %s = %d, want 0", bucket, count)
		}
	}
}
