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
	if got.RecordType != "session_summary" || got.CloseReason != "closed" || got.BytesOut != 100 || got.BytesIn != 250 || got.EventCount != 3 {
		t.Fatalf("unexpected session: %#v", got)
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
	if out[0].CloseReason != "expired" || out[0].RecordType != "session_summary" {
		t.Fatalf("unexpected timeout session: %#v", out[0])
	}
}
