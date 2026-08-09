//go:build 386 || amd64 || arm64

package collector

import (
	"testing"
	"unsafe"
)

// The static audit must reflect the compiled object's real bounds: it feeds
// capacity planning (is 65536 flow entries enough?) so wrong numbers here are
// worse than none.
func TestAuditEBPFResources(t *testing.T) {
	report, err := AuditEBPFResources()
	if err != nil {
		t.Fatalf("AuditEBPFResources: %v", err)
	}

	structs := map[string]uint32{}
	for _, s := range report.Structs {
		structs[s.Name] = s.SizeBytes
	}
	if got, want := structs["flow_event"], uint32(unsafe.Sizeof(rawEBPFEvent{})); got != want {
		t.Errorf("audited flow_event size = %d, want %d (rawEBPFEvent)", got, want)
	}
	if structs["flow_stats"] == 0 || structs["flow_stats"] > 384 {
		t.Errorf("audited flow_stats size = %d, want (0, 384]", structs["flow_stats"])
	}
	if structs["flow_config"] == 0 || structs["flow_key"] == 0 || structs["local_ep"] == 0 {
		t.Errorf("missing audited structs: %v", structs)
	}

	maps := map[string]EBPFMapAudit{}
	for _, m := range report.Maps {
		maps[m.Name] = m
	}
	for name, wantMax := range map[string]uint32{
		"flow_stats_map":            65536,
		"local_ep_to_key":           65536,
		"tls_server_hello_seen_map": 65536,
		"recv_args_map":             16384,
	} {
		audit, ok := maps[name]
		if !ok {
			t.Errorf("map %s missing from audit", name)
			continue
		}
		if audit.MaxEntries != wantMax {
			t.Errorf("map %s max_entries = %d, want %d", name, audit.MaxEntries, wantMax)
		}
		if audit.RawPayloadUpperBoundBytes != uint64(audit.MaxEntries)*uint64(audit.KeySizeBytes+audit.ValueSizeBytes) {
			t.Errorf("map %s payload bound inconsistent: %+v", name, audit)
		}
	}
	if maps["flow_stats_map"].ValueSizeBytes != structs["flow_stats"] {
		t.Errorf("flow_stats_map value size %d != flow_stats struct size %d",
			maps["flow_stats_map"].ValueSizeBytes, structs["flow_stats"])
	}

	ringbufs := map[string]EBPFRingbufAudit{}
	for _, r := range report.Ringbufs {
		ringbufs[r.Name] = r
	}
	events, ok := ringbufs["events"]
	if !ok {
		t.Fatal("events ringbuf missing from audit")
	}
	if events.SizeBytes != 1<<24 {
		t.Errorf("events ringbuf size = %d, want %d", events.SizeBytes, 1<<24)
	}
	if events.EventStruct != "flow_event" || events.EventSizeBytes != structs["flow_event"] {
		t.Errorf("events ringbuf event struct wrong: %+v", events)
	}
	wantRecord := (8 + events.EventSizeBytes + 7) &^ 7
	if events.NominalEventCapacity != events.SizeBytes/wantRecord {
		t.Errorf("events nominal capacity = %d, want %d", events.NominalEventCapacity, events.SizeBytes/wantRecord)
	}
	tls, ok := ringbufs["tls_handshake_events"]
	if !ok {
		t.Fatal("tls_handshake_events ringbuf missing from audit")
	}
	if tls.SizeBytes != 1<<22 || tls.EventStruct != "tls_handshake_event" || tls.NominalEventCapacity == 0 {
		t.Errorf("tls ringbuf audit wrong: %+v", tls)
	}
}
