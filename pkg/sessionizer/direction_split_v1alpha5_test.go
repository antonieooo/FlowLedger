package sessionizer

import (
	"testing"
	"time"

	"FlowLedger/pkg/collector"
)

// pktLabels/iatLabels mirror the collector's bucket label tables. The
// collector-side test TestDirectionalHistogramsShareBucketLabels pins those
// tables to the mixed histograms; here they are only convenient names.
var pktLabels = []string{"0-63", "64-127", "128-255", "256-511", "512-1023", "1024-1500", ">1500"}
var iatLabels = []string{"<100", "100-1000", "1000-10000", "10000-100000", "100000-1000000", ">1000000"}

func hist(labels []string, values ...uint64) map[string]uint64 {
	out := make(map[string]uint64, len(labels))
	for i, l := range labels {
		if i < len(values) {
			out[l] = values[i]
		} else {
			out[l] = 0
		}
	}
	return out
}

func sumHist(h map[string]uint64) uint64 {
	var total uint64
	for _, v := range h {
		total += v
	}
	return total
}

// dirEvent builds a cumulative event whose mixed histograms are exactly the
// sum of the two direction histograms — i.e. the invariant the kernel
// guarantees. Tests that want to violate it do so explicitly.
func dirEvent(ts time.Time, evType string, outPkts, inPkts []uint64, synOut, rstIn uint64) collector.FlowEvent {
	mixedPkt := make([]uint64, len(pktLabels))
	for i := range mixedPkt {
		mixedPkt[i] = outPkts[i] + inPkts[i]
	}
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

		PacketSizeHistogram:    hist(pktLabels, mixedPkt...),
		PacketSizeHistogramOut: hist(pktLabels, outPkts...),
		PacketSizeHistogramIn:  hist(pktLabels, inPkts...),
		RealPacketsSent:        sumHist(hist(pktLabels, outPkts...)),
		RealPacketsRecv:        sumHist(hist(pktLabels, inPkts...)),

		SYNCountOut: synOut,
		RSTCountIn:  rstIn,
	}
	if evType == "CONNECT" {
		ev.SYNCount = 1
	}
	return ev
}

// The identity out+in == mixed must survive WINDOWING, not just conversion:
// three independent cumulative series are differenced against three
// independently snapshotted baselines, so a baseline taken at the wrong
// moment would break the identity even though every single subtraction is
// individually correct.
func TestWindowDeltaPreservesDirectionalIdentity(t *testing.T) {
	base := time.Unix(2000, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(dirEvent(base, "CONNECT", make([]uint64, 7), make([]uint64, 7), 0, 0))

	steps := []struct {
		out, in []uint64
	}{
		{[]uint64{3, 1, 0, 0, 0, 0, 0}, []uint64{0, 2, 5, 0, 0, 0, 0}},
		{[]uint64{9, 4, 0, 1, 0, 0, 0}, []uint64{0, 7, 11, 2, 0, 0, 0}},
		{[]uint64{9, 40, 3, 1, 6, 0, 0}, []uint64{5, 7, 11, 2, 0, 9, 0}},
	}
	for i, step := range steps {
		ts := base.Add(time.Duration(i+1) * 10 * time.Second)
		out := s.Process(dirEvent(ts, "STATS", step.out, step.in, 0, 0))
		if len(out) != 1 {
			t.Fatalf("window %d: got %d records, want 1", i+1, len(out))
		}
		w := out[0]
		if !w.WindowValid {
			t.Fatalf("window %d invalid: %q", i+1, w.WindowInvalidReason)
		}
		for _, label := range pktLabels {
			got := w.PktSizeHistogramOut[label] + w.PktSizeHistogramIn[label]
			want := w.FeatureSnapshot.PktSizeHistogram[label]
			if got != want {
				t.Errorf("window %d bucket %s: out+in = %d, mixed delta = %d", i+1, label, got, want)
			}
		}
		// And each direction's delta must still reconcile with that
		// direction's skb packet delta.
		if got, want := sumHist(w.PktSizeHistogramOut), w.ObservedSKBPacketsOut; got != want {
			t.Errorf("window %d: Σ out histogram = %d, observed_skb_packets_out = %d", i+1, got, want)
		}
		if got, want := sumHist(w.PktSizeHistogramIn), w.ObservedSKBPacketsIn; got != want {
			t.Errorf("window %d: Σ in histogram = %d, observed_skb_packets_in = %d", i+1, got, want)
		}
	}
}

// Concrete arithmetic: cumulative 3 -> 9 -> 9 in one bucket must window as
// 3 -> 6 -> 0. The last window is the "observed but quiet" case and must be a
// present zero, not a null.
func TestWindowDeltaDirectionalArithmetic(t *testing.T) {
	base := time.Unix(3000, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(dirEvent(base, "CONNECT", make([]uint64, 7), make([]uint64, 7), 0, 0))

	want := []uint64{3, 6, 0}
	for i, cum := range []uint64{3, 9, 9} {
		outPkts := []uint64{cum, 0, 0, 0, 0, 0, 0}
		ts := base.Add(time.Duration(i+1) * 10 * time.Second)
		got := s.Process(dirEvent(ts, "STATS", outPkts, make([]uint64, 7), 0, 0))
		if len(got) != 1 {
			t.Fatalf("window %d: got %d records", i+1, len(got))
		}
		w := got[0]
		if w.PktSizeHistogramOut == nil {
			t.Fatalf("window %d: out histogram is nil, want an observed delta", i+1)
		}
		if w.PktSizeHistogramOut["0-63"] != want[i] {
			t.Errorf("window %d: out[0-63] = %d, want %d", i+1, w.PktSizeHistogramOut["0-63"], want[i])
		}
	}
}

// Per-direction flag counts are windowed like every other additive counter.
func TestWindowDeltaDirectionalFlagCounts(t *testing.T) {
	base := time.Unix(4000, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(dirEvent(base, "CONNECT", make([]uint64, 7), make([]uint64, 7), 0, 0))

	zero := make([]uint64, 7)
	// cumulative syn_out 1 -> 3 -> 3, rst_in 0 -> 0 -> 1
	cases := []struct {
		synOut, rstIn         uint64
		wantSynOut, wantRstIn uint64
	}{
		{1, 0, 1, 0},
		{3, 0, 2, 0},
		{3, 1, 0, 1},
	}
	for i, c := range cases {
		ts := base.Add(time.Duration(i+1) * 10 * time.Second)
		got := s.Process(dirEvent(ts, "STATS", zero, zero, c.synOut, c.rstIn))
		if len(got) != 1 {
			t.Fatalf("window %d: got %d records", i+1, len(got))
		}
		w := got[0]
		if w.SYNCountOut != c.wantSynOut {
			t.Errorf("window %d: syn_count_out = %d, want %d", i+1, w.SYNCountOut, c.wantSynOut)
		}
		if w.RSTCountIn != c.wantRstIn {
			t.Errorf("window %d: rst_count_in = %d, want %d", i+1, w.RSTCountIn, c.wantRstIn)
		}
		// The legacy per-connection rst_count must stay 0 throughout: it is a
		// different field and v1alpha5 does not fire it.
		if w.FeatureSnapshot.RSTCount != 0 {
			t.Errorf("window %d: legacy rst_count = %d, want 0", i+1, w.FeatureSnapshot.RSTCount)
		}
	}
}

// A direction the kernel never reported must stay nil all the way to the
// window record — never a fabricated all-zero histogram. This is what lets a
// consumer tell "no inbound packets ever" from "inbound observed, idle
// window", which is the whole point of the split.
func TestUnobservedDirectionStaysNilThroughWindowing(t *testing.T) {
	base := time.Unix(5000, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)

	connect := dirEvent(base, "CONNECT", make([]uint64, 7), make([]uint64, 7), 0, 0)
	connect.PacketSizeHistogramIn = nil
	connect.IATHistogramIn = nil
	s.Process(connect)

	ev := dirEvent(base.Add(10*time.Second), "STATS", []uint64{4, 0, 0, 0, 0, 0, 0}, make([]uint64, 7), 1, 0)
	ev.PacketSizeHistogramIn = nil // kernel: in direction never observed
	ev.IATHistogramIn = nil
	ev.PacketSizeHistogram = hist(pktLabels, 4, 0, 0, 0, 0, 0, 0)
	ev.RealPacketsRecv = 0

	out := s.Process(ev)
	if len(out) != 1 {
		t.Fatalf("got %d records, want 1", len(out))
	}
	w := out[0]
	if !w.WindowValid {
		t.Fatalf("window invalid: %q", w.WindowInvalidReason)
	}
	if w.PktSizeHistogramIn != nil {
		t.Errorf("pkt_size_histogram_in = %v, want nil for a never-observed direction", w.PktSizeHistogramIn)
	}
	if w.PktSizeHistogramOut == nil || w.PktSizeHistogramOut["0-63"] != 4 {
		t.Errorf("pkt_size_histogram_out = %v, want an observed delta of 4 in 0-63", w.PktSizeHistogramOut)
	}
	// The shape the split exists to expose: outbound SYN with no inbound
	// packet at all in this window.
	if w.SYNCountOut != 1 || w.ObservedSKBPacketsIn != 0 {
		t.Errorf("syn_count_out/observed_skb_packets_in = %d/%d, want 1/0", w.SYNCountOut, w.ObservedSKBPacketsIn)
	}
}

// An invalid window must not carry directional deltas either: the histograms
// go to nil (no trustworthy reading) and the counts to zero, matching how the
// mixed counters are already zeroed. The TTL envelopes are NOT deltas and are
// deliberately preserved.
func TestInvalidWindowClearsDirectionalDeltas(t *testing.T) {
	base := time.Unix(6000, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)

	// First event is a STATS, not a CONNECT: the baseline is unknown, so the
	// first window is invalid by construction.
	ev := dirEvent(base, "STATS", []uint64{7, 0, 0, 0, 0, 0, 0}, []uint64{2, 0, 0, 0, 0, 0, 0}, 4, 3)
	ttl := uint32(64)
	ttlIn := uint32(62)
	ev.IPTTLMinOut, ev.IPTTLMaxOut = &ttl, &ttl
	ev.IPTTLMinIn, ev.IPTTLMaxIn = &ttlIn, &ttlIn
	s.Process(ev)

	out := s.Process(dirEvent(base.Add(10*time.Second), "STATS", []uint64{9, 0, 0, 0, 0, 0, 0}, []uint64{3, 0, 0, 0, 0, 0, 0}, 5, 3))
	if len(out) != 1 {
		t.Fatalf("got %d records, want 1", len(out))
	}
	w := out[0]
	if w.WindowValid || w.WindowInvalidReason != WindowInvalidUnknownBaseline {
		t.Fatalf("window validity = (%v, %q), want (false, %q)", w.WindowValid, w.WindowInvalidReason, WindowInvalidUnknownBaseline)
	}
	if w.PktSizeHistogramOut != nil || w.PktSizeHistogramIn != nil ||
		w.IATHistogramOut != nil || w.IATHistogramIn != nil {
		t.Errorf("invalid window kept directional histograms: out=%v in=%v iatOut=%v iatIn=%v",
			w.PktSizeHistogramOut, w.PktSizeHistogramIn, w.IATHistogramOut, w.IATHistogramIn)
	}
	if w.SYNCountOut != 0 || w.SYNCountIn != 0 || w.FINCountOut != 0 ||
		w.FINCountIn != 0 || w.RSTCountOut != 0 || w.RSTCountIn != 0 {
		t.Errorf("invalid window kept directional flag counts: %#v", w)
	}
	// Envelopes survive: they are lifetime extrema, exactly like ip_ttl_min/max.
	if w.IPTTLMinOut == nil || *w.IPTTLMinOut != 64 || w.IPTTLMinIn == nil || *w.IPTTLMinIn != 62 {
		t.Errorf("invalid window dropped the TTL envelopes: out=%v in=%v", w.IPTTLMinOut, w.IPTTLMinIn)
	}
}

// A regression in ANY per-direction histogram must invalidate the window,
// exactly as a regression in the mixed one does. Without this a kernel map
// eviction could leak a bogus delta through the new fields while the mixed
// fields correctly reported a reset.
func TestDirectionalHistogramRegressionInvalidatesWindow(t *testing.T) {
	base := time.Unix(7000, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(dirEvent(base, "CONNECT", make([]uint64, 7), make([]uint64, 7), 0, 0))

	out := s.Process(dirEvent(base.Add(10*time.Second), "STATS", []uint64{10, 0, 0, 0, 0, 0, 0}, make([]uint64, 7), 0, 0))
	if len(out) != 1 || !out[0].WindowValid {
		t.Fatalf("setup window not valid: %#v", out)
	}

	// The direction histogram regresses while the mixed one is held steady,
	// so only the new gate can catch it.
	ev := dirEvent(base.Add(20*time.Second), "STATS", []uint64{4, 0, 0, 0, 0, 0, 0}, make([]uint64, 7), 0, 0)
	ev.PacketSizeHistogram = hist(pktLabels, 10, 0, 0, 0, 0, 0, 0)
	ev.RealPacketsSent = 10

	out = s.Process(ev)
	if len(out) != 1 {
		t.Fatalf("got %d records, want 1", len(out))
	}
	if out[0].WindowValid || out[0].WindowInvalidReason != WindowInvalidCounterReset {
		t.Fatalf("window validity = (%v, %q), want (false, %q)",
			out[0].WindowValid, out[0].WindowInvalidReason, WindowInvalidCounterReset)
	}
}

// session_summary records are lifetime_cumulative and must carry lifetime
// directional totals, not the last window's delta.
func TestSessionSummaryCarriesLifetimeDirectionalTotals(t *testing.T) {
	base := time.Unix(8000, 0).UTC()
	s := New("node-a", 5*time.Minute, 10*time.Second)
	s.Process(dirEvent(base, "CONNECT", make([]uint64, 7), make([]uint64, 7), 0, 0))
	s.Process(dirEvent(base.Add(10*time.Second), "STATS", []uint64{5, 0, 0, 0, 0, 0, 0}, make([]uint64, 7), 1, 0))

	out := s.Process(dirEvent(base.Add(15*time.Second), "CLOSE", []uint64{12, 0, 0, 0, 0, 0, 0}, make([]uint64, 7), 1, 2))
	var summary *FlowSession
	for i := range out {
		if out[i].RecordType == "session_summary" {
			summary = &out[i]
		}
	}
	if summary == nil {
		t.Fatalf("no session_summary emitted: %#v", out)
	}
	if summary.PktSizeHistogramOut["0-63"] != 12 {
		t.Errorf("session_summary out[0-63] = %d, want the lifetime 12", summary.PktSizeHistogramOut["0-63"])
	}
	if summary.SYNCountOut != 1 || summary.RSTCountIn != 2 {
		t.Errorf("session_summary syn_out/rst_in = %d/%d, want lifetime 1/2", summary.SYNCountOut, summary.RSTCountIn)
	}
}
