package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func collectMockEvents(t *testing.T, jsonl string) []FlowEvent {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte(jsonl), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, errs := NewMockCollector(path).Run(ctx)
	var out []FlowEvent
	for events != nil || errs != nil {
		select {
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			out = append(out, ev)
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if err != nil {
				t.Fatalf("mock collector error: %v", err)
			}
		}
	}
	return out
}

// Mock fixtures keep the legacy per-event delta semantics: an event without an
// explicit marking is stamped "delta" so aggregators keep summing it.
func TestMockCollectorDefaultsToDeltaSemantics(t *testing.T) {
	events := collectMockEvents(t, `{"event_type":"STATS","src_ip":"10.1.1.10","src_port":40000,"dst_ip":"10.1.1.20","dst_port":443,"packet_sizes":[60,100]}
`)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].CounterSemantics != CounterSemanticsDelta {
		t.Fatalf("CounterSemantics = %q, want delta default", events[0].CounterSemantics)
	}
}

// A fixture may opt into cumulative semantics explicitly (to exercise the eBPF
// aggregation path); the collector must not overwrite it.
func TestMockCollectorHonorsExplicitCumulativeSemantics(t *testing.T) {
	events := collectMockEvents(t, `{"event_type":"STATS","src_ip":"10.1.1.10","src_port":40000,"dst_ip":"10.1.1.20","dst_port":443,"counter_semantics":"cumulative","real_packets_sent":10,"real_packets_recv":8}
`)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.CounterSemantics != CounterSemanticsCumulative {
		t.Fatalf("CounterSemantics = %q, want cumulative preserved", ev.CounterSemantics)
	}
	if ev.ObservedSKBPacketsSource != "mock" {
		t.Fatalf("ObservedSKBPacketsSource = %q, want mock provenance for fixture counts", ev.ObservedSKBPacketsSource)
	}
}

// A fixture without skb-level counts must not gain a fabricated provenance.
func TestMockCollectorNoFabricatedSKBSource(t *testing.T) {
	events := collectMockEvents(t, `{"event_type":"CONNECT","src_ip":"10.1.1.10","src_port":40000,"dst_ip":"10.1.1.20","dst_port":443}
`)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].ObservedSKBPacketsSource != "" {
		t.Fatalf("ObservedSKBPacketsSource = %q, want empty", events[0].ObservedSKBPacketsSource)
	}
}

// Mock fixtures can exercise the P1 header-aggregate fields end to end; the
// collector passes them through untouched.
func TestMockCollectorP1HeaderFixture(t *testing.T) {
	events := collectMockEvents(t, `{"event_type":"STATS","src_ip":"10.1.1.10","src_port":40000,"dst_ip":"10.1.1.20","dst_port":443,"counter_semantics":"cumulative","ip_ttl_min":58,"ip_ttl_max":64,"tcp_flags_out":26,"tcp_flags_in":18,"tcp_window_max_out":64240,"tcp_window_max_in":65535,"direction_duration_out_ns":900000000,"direction_duration_out_observed":true,"ip_pkt_len_min":52,"ip_pkt_len_max":1500,"netflow_v2_ip_size_histogram":{"<=128":6,">1514":2}}
`)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.IPTTLMin == nil || *ev.IPTTLMin != 58 || ev.IPTTLMax == nil || *ev.IPTTLMax != 64 {
		t.Fatalf("ttl fixture wrong: %#v", ev)
	}
	if ev.TCPFlagsOut != 26 || ev.TCPFlagsIn != 18 {
		t.Fatalf("flags fixture wrong: %#v", ev)
	}
	if ev.TCPWindowMaxOut == nil || *ev.TCPWindowMaxOut != 64240 || ev.TCPWindowMaxIn == nil || *ev.TCPWindowMaxIn != 65535 {
		t.Fatalf("window fixture wrong: %#v", ev)
	}
	if ev.DirectionDurationOutNS != 900000000 || !ev.DirectionDurationOutObserved || ev.DirectionDurationInObserved {
		t.Fatalf("duration fixture wrong: %#v", ev)
	}
	if ev.IPPktLenMin == nil || *ev.IPPktLenMin != 52 || ev.NetFlowV2IPSizeHistogram["<=128"] != 6 {
		t.Fatalf("ip length fixture wrong: %#v", ev)
	}
}

// P2 mock fixtures: non-zero retrans counters imply an attached hook; an
// explicit local_retrans_available=true with zero counters models "attached,
// no retransmissions"; a fixture with neither stays unavailable.
func TestMockCollectorLocalRetransFixtures(t *testing.T) {
	events := collectMockEvents(t, `{"event_type":"STATS","src_ip":"10.1.1.10","src_port":40000,"dst_ip":"10.96.0.10","dst_port":443,"counter_semantics":"cumulative","local_retrans_skb_count":2,"local_retrans_skb_bytes":2800}
{"event_type":"STATS","src_ip":"10.1.1.11","src_port":40001,"dst_ip":"10.96.0.10","dst_port":443,"local_retrans_available":true}
{"event_type":"STATS","src_ip":"10.1.1.12","src_port":40002,"dst_ip":"10.96.0.10","dst_port":443}
`)
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	if !events[0].LocalRetransAvailable || events[0].LocalRetransSource != "mock" || events[0].LocalRetransSKBCount != 2 {
		t.Fatalf("counted fixture wrong: %#v", events[0])
	}
	if !events[1].LocalRetransAvailable || events[1].LocalRetransSource != "mock" || events[1].LocalRetransSKBCount != 0 {
		t.Fatalf("attached-no-retrans fixture wrong: %#v", events[1])
	}
	if events[2].LocalRetransAvailable || events[2].LocalRetransSource != "" {
		t.Fatalf("availability fabricated for empty fixture: %#v", events[2])
	}
}
