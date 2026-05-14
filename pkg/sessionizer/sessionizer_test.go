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
	if len(out) != 1 {
		t.Fatalf("CLOSE emitted %d sessions, want 1", len(out))
	}
	if !out[0].HandshakeSeen || out[0].JA4 != tlsEvent.JA4 || out[0].SNIHash != tlsEvent.SNIHash || out[0].TLSParseStatus != "parsed" {
		t.Fatalf("TLS fields were not retained: %#v", out[0])
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
			if len(out) != 1 {
				t.Fatalf("CLOSE emitted %d sessions, want 1", len(out))
			}
			got := out[0]
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
	if len(out) != 1 {
		t.Fatalf("CLOSE emitted %d sessions, want 1", len(out))
	}
	if !out[0].ServerHelloSeen || out[0].JA4S != serverHello.JA4S {
		t.Fatalf("ServerHello fields were not retained after alias join: %#v", out[0])
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
	if len(out) != 1 || out[0].WindowID != 0 || out[0].CloseReason != "fin" || !out[0].FeatureSnapshot.IsLongLived {
		t.Fatalf("unexpected final session: %#v", out)
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
	if len(out) != 1 {
		t.Fatalf("CLOSE emitted %d sessions, want 1", len(out))
	}
	got := out[0]
	if got.BytesOut != 300 || got.BytesIn != 500 || got.PacketsOut != 3 || got.PacketsIn != 4 {
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
