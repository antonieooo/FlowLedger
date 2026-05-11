package sessionizer

import (
	"testing"
	"time"

	"FlowLedger/pkg/collector"
)

func TestSessionizerClose(t *testing.T) {
	base := time.Unix(100, 0).UTC()
	s := New("node-a", 60*time.Second, 30*time.Second)
	common := collector.FlowEvent{
		SrcIP: "10.1.1.10", SrcPort: 40000,
		DstIP: "10.1.1.20", DstPort: 443,
		Protocol: "tcp",
	}
	common.TimestampNS = uint64(base.UnixNano())
	common.EventType = "CONNECT"
	if out := s.Process(common); len(out) != 0 {
		t.Fatalf("CONNECT emitted %d sessions", len(out))
	}
	common.TimestampNS = uint64(base.Add(time.Second).UnixNano())
	common.EventType = "STATS"
	common.BytesSent = 100
	common.BytesRecv = 250
	if out := s.Process(common); len(out) != 0 {
		t.Fatalf("STATS emitted %d sessions", len(out))
	}
	common.TimestampNS = uint64(base.Add(2 * time.Second).UnixNano())
	common.EventType = "CLOSE"
	out := s.Process(common)
	if len(out) != 1 {
		t.Fatalf("CLOSE emitted %d sessions, want 1", len(out))
	}
	got := out[0]
	if got.RecordType != "session_summary" || got.CloseReason != "unknown" || got.BytesOut != 100 || got.BytesIn != 250 || got.EventCount != 3 {
		t.Fatalf("unexpected session: %#v", got)
	}
	if got.FeatureSnapshot.BytesTotal != 350 || got.FeatureSnapshot.TrafficAccountingAvailable != true {
		t.Fatalf("unexpected feature snapshot: %#v", got.FeatureSnapshot)
	}
}

func TestSessionizerTimeout(t *testing.T) {
	base := time.Unix(100, 0).UTC()
	s := New("node-a", 60*time.Second, 30*time.Second)
	ev := collector.FlowEvent{
		TimestampNS: uint64(base.UnixNano()),
		EventType:   "CONNECT",
		SrcIP:       "10.1.1.10",
		SrcPort:     40000,
		DstIP:       "10.1.1.20",
		DstPort:     443,
		Protocol:    "tcp",
	}
	s.Process(ev)
	out := s.Sweep(base.Add(61 * time.Second))
	if len(out) != 1 {
		t.Fatalf("Sweep emitted %d sessions, want 1", len(out))
	}
	if out[0].CloseReason != "timeout" || out[0].RecordType != "session_summary" {
		t.Fatalf("unexpected timeout session: %#v", out[0])
	}
}

func TestSessionizerWindowIDAndLongLived(t *testing.T) {
	base := time.Unix(100, 0).UTC()
	s := NewWithLongLivedThreshold("node-a", time.Minute, time.Second, 2*time.Second)
	ev := collector.FlowEvent{
		TimestampNS: uint64(base.UnixNano()),
		EventType:   "CONNECT",
		SrcIP:       "10.1.1.10",
		SrcPort:     40000,
		DstIP:       "10.1.1.20",
		DstPort:     443,
		Protocol:    "tcp",
	}
	s.Process(ev)
	ev.TimestampNS = uint64(base.Add(1500 * time.Millisecond).UnixNano())
	ev.EventType = "STATS"
	ev.BytesSent = 100
	ev.BytesRecv = 50
	ev.PacketsSent = 2
	ev.PacketsRecv = 1
	ev.PacketSizes = []uint64{60, 100, 1400}
	ev.IATMicros = []uint64{100, 2_000_000}
	out := s.Process(ev)
	if len(out) != 1 || out[0].RecordType != "window_summary" || out[0].WindowID != 1 {
		t.Fatalf("unexpected window output: %#v", out)
	}
	if out[0].FeatureSnapshot.BytesTotal != 150 || out[0].FeatureSnapshot.PacketTimingAvailable != true {
		t.Fatalf("unexpected window features: %#v", out[0].FeatureSnapshot)
	}

	ev.TimestampNS = uint64(base.Add(3 * time.Second).UnixNano())
	ev.EventType = "CLOSE"
	ev.CloseReason = "fin"
	out = s.Process(ev)
	if len(out) != 1 || out[0].WindowID != 0 || out[0].CloseReason != "fin" || !out[0].FeatureSnapshot.IsLongLived {
		t.Fatalf("unexpected final session: %#v", out)
	}
}
