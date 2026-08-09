package sessionizer

import (
	"testing"
	"time"

	"FlowLedger/pkg/collector"
)

type fakeK8sResolver struct {
	clusterIP   string
	servicePort int
	ok          bool
}

func (r fakeK8sResolver) ResolveServiceForEndpoint(endpointIP string, endpointPort int, protocol string) (string, int, bool) {
	if !r.ok || endpointIP != "10.1.1.20" || endpointPort != 443 || protocol != "tcp" {
		return "", 0, false
	}
	return r.clusterIP, r.servicePort, true
}

type fakeNATAliasMetrics struct {
	hits   int
	misses int
}

func (m *fakeNATAliasMetrics) IncTLSServerHelloNATAliasHit() {
	m.hits++
}

func (m *fakeNATAliasMetrics) IncTLSServerHelloNATAliasMiss() {
	m.misses++
}

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
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}
	if out[0].RecordType != "window_summary" || !out[0].FinalWindow || !out[0].WindowValid {
		t.Fatalf("unexpected final window: %#v", out[0])
	}
	got := out[1]
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
	if len(out) != 2 {
		t.Fatalf("Sweep emitted %d records, want final window + session summary", len(out))
	}
	if out[0].RecordType != "window_summary" || !out[0].FinalWindow {
		t.Fatalf("unexpected final window: %#v", out[0])
	}
	if out[1].CloseReason != "timeout" || out[1].RecordType != "session_summary" {
		t.Fatalf("unexpected timeout session: %#v", out[1])
	}
}

func TestSessionizerTLSHandshakeUpdatesExistingSessionOnly(t *testing.T) {
	base := time.Unix(100, 0).UTC()
	s := New("node-a", 60*time.Second, 30*time.Second)
	common := collector.FlowEvent{
		SrcIP: "10.1.1.10", SrcPort: 40000,
		DstIP: "10.1.1.20", DstPort: 443,
		Protocol: "tcp",
	}
	tlsEvent := common
	tlsEvent.TimestampNS = uint64(base.UnixNano())
	tlsEvent.EventType = "TLS_HANDSHAKE"
	tlsEvent.HandshakeSeen = true
	tlsEvent.TLSVersion = "1.3"
	tlsEvent.SNIHash = "a379a6f6eeafb9a5"
	tlsEvent.ALPN = "h2"
	tlsEvent.JA4 = "t13d0000h2_000000000000_000000000000"
	tlsEvent.TLSParseStatus = "parsed"
	if s.ProcessTLSHandshake(tlsEvent) {
		t.Fatal("TLS handshake matched before CONNECT")
	}

	common.TimestampNS = uint64(base.UnixNano())
	common.EventType = "CONNECT"
	s.Process(common)
	if !s.ProcessTLSHandshake(tlsEvent) {
		t.Fatal("TLS handshake did not match active session")
	}
	common.TimestampNS = uint64(base.Add(time.Second).UnixNano())
	common.EventType = "CLOSE"
	out := s.Process(common)
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}
	got := out[1]
	if !got.HandshakeSeen || got.JA4 != tlsEvent.JA4 || got.SNIHash != tlsEvent.SNIHash || got.TLSParseStatus != "parsed" {
		t.Fatalf("TLS fields were not retained: %#v", got)
	}
}

func TestSessionizerTLSClientAndServerHandshakeAnyOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first collector.FlowEvent
		next  collector.FlowEvent
	}{
		{
			name:  "client_then_server",
			first: clientTLSFlowEvent(),
			next:  serverTLSFlowEvent(),
		},
		{
			name:  "server_then_client",
			first: serverTLSFlowEvent(),
			next:  clientTLSFlowEvent(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := time.Unix(100, 0).UTC()
			s := New("node-a", 60*time.Second, 30*time.Second)
			common := collector.FlowEvent{
				TimestampNS: uint64(base.UnixNano()),
				EventType:   "CONNECT",
				SrcIP:       "10.1.1.10",
				SrcPort:     40000,
				DstIP:       "10.1.1.20",
				DstPort:     443,
				Protocol:    "tcp",
			}
			s.Process(common)
			if !s.ProcessTLSHandshake(tc.first) || !s.ProcessTLSHandshake(tc.next) {
				t.Fatal("TLS handshake did not match active session")
			}
			common.TimestampNS = uint64(base.Add(time.Second).UnixNano())
			common.EventType = "CLOSE"
			out := s.Process(common)
			if len(out) != 2 {
				t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
			}
			got := out[1]
			if !got.HandshakeSeen || got.JA4 != clientTLSFlowEvent().JA4 || !got.ServerHelloSeen || got.JA4S != serverTLSFlowEvent().JA4S {
				t.Fatalf("TLS client/server fields were not retained: %#v", got)
			}
		})
	}
}

func TestSessionizerServerHelloNATAliasMatchesServiceSession(t *testing.T) {
	base := time.Unix(100, 0).UTC()
	s := New("node-a", 60*time.Second, 30*time.Second)
	aliasMetrics := &fakeNATAliasMetrics{}
	s.SetK8sMeta(fakeK8sResolver{clusterIP: "10.96.0.10", servicePort: 443, ok: true})
	s.SetNATAliasMetrics(aliasMetrics)

	connect := collector.FlowEvent{
		TimestampNS: uint64(base.UnixNano()),
		EventType:   "CONNECT",
		SrcIP:       "10.1.1.10",
		SrcPort:     40000,
		DstIP:       "10.96.0.10",
		DstPort:     443,
		Protocol:    "tcp",
	}
	s.Process(connect)

	clientHello := clientTLSFlowEvent()
	clientHello.DstIP = "10.1.1.20"
	if s.ProcessTLSHandshake(clientHello) {
		t.Fatal("ClientHello unexpectedly used NAT alias fallback")
	}
	if aliasMetrics.hits != 0 || aliasMetrics.misses != 0 {
		t.Fatalf("ClientHello changed NAT alias metrics: %#v", aliasMetrics)
	}

	serverHello := serverTLSFlowEvent()
	serverHello.DstIP = "10.1.1.20"
	if !s.ProcessTLSHandshake(serverHello) {
		t.Fatal("ServerHello did not match through NAT alias")
	}
	if aliasMetrics.hits != 1 || aliasMetrics.misses != 0 {
		t.Fatalf("unexpected NAT alias metrics: %#v", aliasMetrics)
	}

	connect.TimestampNS = uint64(base.Add(time.Second).UnixNano())
	connect.EventType = "CLOSE"
	out := s.Process(connect)
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}
	if !out[1].ServerHelloSeen || out[1].JA4S != serverHello.JA4S {
		t.Fatalf("ServerHello fields were not retained after alias join: %#v", out[1])
	}
}

func TestSessionizerServerHelloNATAliasMiss(t *testing.T) {
	s := New("node-a", 60*time.Second, 30*time.Second)
	aliasMetrics := &fakeNATAliasMetrics{}
	s.SetK8sMeta(fakeK8sResolver{})
	s.SetNATAliasMetrics(aliasMetrics)

	serverHello := serverTLSFlowEvent()
	serverHello.DstIP = "10.1.1.20"
	if s.ProcessTLSHandshake(serverHello) {
		t.Fatal("ServerHello unexpectedly matched without alias")
	}
	if aliasMetrics.hits != 0 || aliasMetrics.misses != 1 {
		t.Fatalf("unexpected NAT alias metrics: %#v", aliasMetrics)
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
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}
	if out[0].RecordType != "window_summary" || out[0].WindowID != 2 || !out[0].FinalWindow {
		t.Fatalf("unexpected final window: %#v", out[0])
	}
	if out[1].WindowID != 0 || out[1].CloseReason != "fin" || !out[1].FeatureSnapshot.IsLongLived {
		t.Fatalf("unexpected final session: %#v", out[1])
	}
}

func clientTLSFlowEvent() collector.FlowEvent {
	return collector.FlowEvent{
		TimestampNS:    uint64(time.Unix(100, 100).UTC().UnixNano()),
		EventType:      "TLS_HANDSHAKE",
		SrcIP:          "10.1.1.10",
		SrcPort:        40000,
		DstIP:          "10.1.1.20",
		DstPort:        443,
		Protocol:       "tcp",
		HandshakeSeen:  true,
		TLSVersion:     "1.3",
		SNIHash:        "a379a6f6eeafb9a5",
		ALPN:           "h2",
		JA4:            "t13d0000h2_000000000000_000000000000",
		TLSParseStatus: "parsed",
	}
}

func serverTLSFlowEvent() collector.FlowEvent {
	return collector.FlowEvent{
		TimestampNS:          uint64(time.Unix(100, 200).UTC().UnixNano()),
		EventType:            "TLS_HANDSHAKE",
		SrcIP:                "10.1.1.10",
		SrcPort:              40000,
		DstIP:                "10.1.1.20",
		DstPort:              443,
		Protocol:             "tcp",
		ServerHelloSeen:      true,
		TLSVersionNegotiated: "1.2",
		ALPNNegotiated:       "h2",
		JA4S:                 "t1201h2_c02f_0b08e3dcc50f",
		TLSServerParseStatus: "parsed",
	}
}

func TestSessionizerCumulativeStats(t *testing.T) {
	base := time.Unix(200, 0).UTC()
	s := New("node-a", time.Minute, 30*time.Second)
	common := collector.FlowEvent{
		SrcIP: "10.1.1.10", SrcPort: 40000,
		DstIP: "10.1.1.20", DstPort: 443,
		Protocol:                   "tcp",
		TrafficAccountingAvailable: true,
	}
	common.TimestampNS = uint64(base.UnixNano())
	common.EventType = "CONNECT"
	s.Process(common)
	common.TimestampNS = uint64(base.Add(time.Second).UnixNano())
	common.EventType = "STATS"
	common.BytesSent = 100
	common.BytesRecv = 200
	common.PacketsSent = 1
	common.PacketsRecv = 2
	s.Process(common)
	common.TimestampNS = uint64(base.Add(2 * time.Second).UnixNano())
	common.BytesSent = 300
	common.BytesRecv = 500
	common.PacketsSent = 3
	common.PacketsRecv = 4
	s.Process(common)
	common.TimestampNS = uint64(base.Add(3 * time.Second).UnixNano())
	common.EventType = "CLOSE"
	out := s.Process(common)
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}
	got := out[1]
	if got.RecordType != "session_summary" || got.BytesOut != 300 || got.BytesIn != 500 || got.PacketsOut != 3 || got.PacketsIn != 4 {
		t.Fatalf("unexpected cumulative counters: %#v", got)
	}
	if got.FeatureSnapshot.BytesTotal != 800 || got.FeatureSnapshot.PacketsTotal != 7 {
		t.Fatalf("unexpected feature totals: %#v", got.FeatureSnapshot)
	}
}

func TestSessionizerWindowSummaryWithStats(t *testing.T) {
	base := time.Unix(300, 0).UTC()
	s := New("node-a", time.Minute, time.Second)
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
	ev.TimestampNS = uint64(base.Add(2 * time.Second).UnixNano())
	ev.EventType = "STATS"
	ev.BytesSent = 100
	ev.BytesRecv = 200
	ev.PacketsSent = 2
	ev.PacketsRecv = 3
	out := s.Process(ev)
	if len(out) != 1 || out[0].RecordType != "window_summary" {
		t.Fatalf("unexpected window output: %#v", out)
	}
	if out[0].BytesOut != 100 || out[0].BytesIn != 200 || out[0].PacketsOut != 2 || out[0].PacketsIn != 3 {
		t.Fatalf("unexpected window counters: %#v", out[0])
	}
}

func u32ptr(v uint32) *uint32 { return &v }

// P1: TTL envelopes, TCP flag OR-masks, directional window maxima, direction
// durations and IP length envelopes must merge idempotently across multiple
// cumulative snapshots — identical re-delivered snapshots change nothing, and
// values never re-accumulate.
func TestSessionizerMergesHeaderAggregates(t *testing.T) {
	base := time.Unix(800, 0).UTC()
	s := New("node-a", time.Minute, 30*time.Second)
	common := collector.FlowEvent{
		SrcIP: "10.1.1.10", SrcPort: 40000,
		DstIP: "10.1.1.20", DstPort: 443,
		Protocol:         "tcp",
		CounterSemantics: collector.CounterSemanticsCumulative,
	}

	connect := common
	connect.TimestampNS = uint64(base.UnixNano())
	connect.EventType = "CONNECT"
	connect.SYNCount = 1
	s.Process(connect)

	stats1 := common
	stats1.TimestampNS = uint64(base.Add(time.Second).UnixNano())
	stats1.EventType = "STATS"
	stats1.IPTTLMin = u32ptr(62)
	stats1.IPTTLMax = u32ptr(64)
	stats1.TCPFlagsOut = 0x02 // SYN
	stats1.TCPFlagsIn = 0x12  // SYN|ACK
	stats1.TCPHeaderObservedOut = true
	stats1.TCPHeaderObservedIn = true
	stats1.TCPWindowMaxOut = u32ptr(64240)
	stats1.TCPWindowMaxIn = u32ptr(65160)
	stats1.DirectionDurationOutNS = 0 // single packet so far
	stats1.DirectionDurationOutObserved = true
	stats1.DirectionDurationInNS = 0
	stats1.DirectionDurationInObserved = true
	stats1.IPPktLenMin = u32ptr(60)
	stats1.IPPktLenMax = u32ptr(60)
	s.Process(stats1)

	stats2 := stats1
	stats2.TimestampNS = uint64(base.Add(2 * time.Second).UnixNano())
	stats2.IPTTLMin = u32ptr(58) // lower TTL seen later
	stats2.IPTTLMax = u32ptr(64)
	stats2.TCPFlagsOut = 0x18 // PSH|ACK
	stats2.TCPFlagsIn = 0x10  // ACK
	stats2.TCPWindowMaxOut = u32ptr(64240)
	stats2.TCPWindowMaxIn = u32ptr(65535)
	stats2.DirectionDurationOutNS = 900_000_000
	stats2.DirectionDurationInNS = 1_500_000_000
	stats2.IPPktLenMin = u32ptr(52)
	stats2.IPPktLenMax = u32ptr(1500)
	s.Process(stats2)
	// Re-delivered identical snapshot: merges are idempotent, nothing grows.
	stats3 := stats2
	stats3.TimestampNS = uint64(base.Add(3 * time.Second).UnixNano())
	s.Process(stats3)

	closeEv := common
	closeEv.TimestampNS = uint64(base.Add(4 * time.Second).UnixNano())
	closeEv.EventType = "CLOSE"
	closeEv.FINCount = 1
	out := s.Process(closeEv)
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}
	got := out[1]
	if got.IPTTLMin == nil || *got.IPTTLMin != 58 || got.IPTTLMax == nil || *got.IPTTLMax != 64 {
		t.Fatalf("ttl envelope wrong: %#v %#v", got.IPTTLMin, got.IPTTLMax)
	}
	// OR of SYN|PSH|ACK, not a count and not tripled by the re-delivery.
	if got.TCPFlagsOut != 0x1a {
		t.Fatalf("tcp_flags_out = %#x, want OR 0x1a", got.TCPFlagsOut)
	}
	if got.TCPFlagsIn != 0x12 {
		t.Fatalf("tcp_flags_in = %#x, want OR 0x12", got.TCPFlagsIn)
	}
	if got.TCPWindowMaxOut == nil || *got.TCPWindowMaxOut != 64240 || got.TCPWindowMaxIn == nil || *got.TCPWindowMaxIn != 65535 {
		t.Fatalf("directional window max wrong: %#v %#v", got.TCPWindowMaxOut, got.TCPWindowMaxIn)
	}
	if got.DirectionDurationOutNS != 900_000_000 || got.DirectionDurationInNS != 1_500_000_000 {
		t.Fatalf("direction durations wrong: %#v", got)
	}
	if !got.DirectionDurationOutObserved || !got.DirectionDurationInObserved {
		t.Fatalf("direction observation lost: %#v", got)
	}
	if got.IPPktLenMin == nil || *got.IPPktLenMin != 52 || got.IPPktLenMax == nil || *got.IPPktLenMax != 1500 {
		t.Fatalf("ip pkt len envelope wrong: %#v %#v", got.IPPktLenMin, got.IPPktLenMax)
	}
	if got.FeatureSnapshot.SYNCount != 1 {
		t.Fatalf("SYN inflated by repeated snapshots: %#v", got.FeatureSnapshot)
	}
	if !got.TCPHeaderObservedOut || !got.TCPHeaderObservedIn {
		t.Fatalf("header observed witnesses lost across merges: %#v", got)
	}
}

// One direction observed with an all-zero flag byte (TCP NULL scan), the
// other never observed: the witness flags must survive the session merge
// as-is — observed stays true with flags 0 and a genuine zero window, the
// unobserved direction stays false/nil even across repeated cumulative
// snapshots (idempotency).
func TestSessionizerHeaderObservedOneDirectionNullScan(t *testing.T) {
	base := time.Unix(820, 0).UTC()
	s := New("node-a", time.Minute, 30*time.Second)
	common := collector.FlowEvent{
		SrcIP: "10.1.1.10", SrcPort: 40001,
		DstIP: "10.1.1.20", DstPort: 443,
		Protocol:         "tcp",
		CounterSemantics: collector.CounterSemanticsCumulative,
	}

	connect := common
	connect.TimestampNS = uint64(base.UnixNano())
	connect.EventType = "CONNECT"
	s.Process(connect)

	stats := common
	stats.TimestampNS = uint64(base.Add(time.Second).UnixNano())
	stats.EventType = "STATS"
	stats.TCPFlagsOut = 0 // NULL scan: header observed, zero flag byte
	stats.TCPHeaderObservedOut = true
	stats.TCPWindowMaxOut = u32ptr(0) // observed zero window
	s.Process(stats)
	// Identical cumulative snapshot re-delivered: nothing may change.
	stats2 := stats
	stats2.TimestampNS = uint64(base.Add(2 * time.Second).UnixNano())
	s.Process(stats2)

	closeEv := common
	closeEv.TimestampNS = uint64(base.Add(3 * time.Second).UnixNano())
	closeEv.EventType = "CLOSE"
	out := s.Process(closeEv)
	if len(out) != 2 {
		t.Fatalf("CLOSE emitted %d records, want final window + session summary", len(out))
	}
	got := out[1]
	if !got.TCPHeaderObservedOut || got.TCPFlagsOut != 0 {
		t.Fatalf("observed NULL-scan direction wrong: observed=%v flags=%#x", got.TCPHeaderObservedOut, got.TCPFlagsOut)
	}
	if got.TCPWindowMaxOut == nil || *got.TCPWindowMaxOut != 0 {
		t.Fatalf("observed zero window lost: %#v", got.TCPWindowMaxOut)
	}
	if got.TCPHeaderObservedIn || got.TCPFlagsIn != 0 || got.TCPWindowMaxIn != nil {
		t.Fatalf("unobserved direction fabricated: observed=%v flags=%#x win=%#v",
			got.TCPHeaderObservedIn, got.TCPFlagsIn, got.TCPWindowMaxIn)
	}
}
