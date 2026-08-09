//go:build linux

package collector

import "testing"

func u32p(v uint32) *uint32 { return &v }

// Required: with the packet feature hooks disabled the new header fields must
// be null / zero / unobserved — availability never fabricated.
func TestApplyPacketFeatureOptionsDisabledClearsP1Fields(t *testing.T) {
	c := NewEBPFCollectorWithOptions(EBPFOptions{
		EnableTrafficAccounting:   true,
		EnableTCPBasicMetrics:     true,
		EnablePacketTiming:        false,
		EnablePacketHistogram:     false,
		EnableTLSHandshakeInspect: false,
		EnableHeaderAggregates:    false,
		EnableNetFlowV2Histogram:  false,
	})
	ev := FlowEvent{
		RealPacketsSent:              5,
		RealPacketsRecv:              4,
		ObservedSKBPacketsSource:     ObservedSKBPacketsSourceCgroupSKB,
		IPTTLMin:                     u32p(61),
		IPTTLMax:                     u32p(64),
		TCPFlagsOut:                  0x1a,
		TCPFlagsIn:                   0x12,
		TCPWindowMaxOut:              u32p(64240),
		TCPWindowMaxIn:               u32p(65160),
		DirectionDurationOutNS:       100,
		DirectionDurationInNS:        200,
		DirectionDurationOutObserved: true,
		DirectionDurationInObserved:  true,
		IPPktLenMin:                  u32p(52),
		IPPktLenMax:                  u32p(1500),
		NetFlowV2IPSizeHistogram:     map[string]uint64{"<=128": 1},
	}
	c.applyPacketFeatureOptions(&ev)

	if ev.IPTTLMin != nil || ev.IPTTLMax != nil || ev.TCPFlagsOut != 0 || ev.TCPFlagsIn != 0 {
		t.Fatalf("ttl/flags not cleared: %#v", ev)
	}
	if ev.TCPWindowMaxOut != nil || ev.TCPWindowMaxIn != nil || ev.IPPktLenMin != nil || ev.IPPktLenMax != nil {
		t.Fatalf("window/ip-len not cleared: %#v", ev)
	}
	if ev.NetFlowV2IPSizeHistogram != nil {
		t.Fatalf("nf histogram not cleared: %#v", ev)
	}
	if ev.DirectionDurationOutNS != 0 || ev.DirectionDurationInNS != 0 || ev.DirectionDurationOutObserved || ev.DirectionDurationInObserved {
		t.Fatalf("direction durations not cleared: %#v", ev)
	}
	if ev.RealPacketsSent != 0 || ev.RealPacketsRecv != 0 || ev.ObservedSKBPacketsSource != "" {
		t.Fatalf("skb packet counters not cleared: %#v", ev)
	}
}

// The header-aggregate gate is independent of the packet histogram: with
// aggregates disabled but the histogram enabled, header fields (including the
// observed witnesses) clear while histogram/timing fields survive.
func TestApplyPacketFeatureOptionsHeaderAggregatesGateIsIndependent(t *testing.T) {
	c := NewEBPFCollectorWithOptions(EBPFOptions{
		EnablePacketTiming:       true,
		EnablePacketHistogram:    true,
		EnableHeaderAggregates:   false,
		EnableNetFlowV2Histogram: true,
	})
	ev := FlowEvent{
		PacketSizeHistogram:      map[string]uint64{"0-63": 3},
		RealPacketsSent:          5,
		IPTTLMin:                 u32p(61),
		IPTTLMax:                 u32p(64),
		TCPFlagsOut:              0x1a,
		TCPHeaderObservedOut:     true,
		TCPHeaderObservedIn:      true,
		TCPWindowMaxOut:          u32p(64240),
		IPPktLenMin:              u32p(52),
		IPPktLenMax:              u32p(1500),
		NetFlowV2IPSizeHistogram: map[string]uint64{"<=128": 1},
	}
	c.applyPacketFeatureOptions(&ev)

	if ev.IPTTLMin != nil || ev.IPTTLMax != nil || ev.TCPFlagsOut != 0 ||
		ev.TCPHeaderObservedOut || ev.TCPHeaderObservedIn ||
		ev.TCPWindowMaxOut != nil || ev.IPPktLenMin != nil || ev.IPPktLenMax != nil {
		t.Fatalf("header aggregates not cleared with dedicated gate off: %#v", ev)
	}
	if ev.PacketSizeHistogram == nil || ev.RealPacketsSent != 5 {
		t.Fatalf("histogram-gated fields wrongly cleared: %#v", ev)
	}
	if ev.NetFlowV2IPSizeHistogram == nil {
		t.Fatalf("nf histogram wrongly cleared while its gate is on: %#v", ev)
	}
}

// The NetFlow-v2 histogram gate clears only the histogram; header aggregates
// with their own gate on survive untouched.
func TestApplyPacketFeatureOptionsNetFlowGateIsIndependent(t *testing.T) {
	c := NewEBPFCollectorWithOptions(EBPFOptions{
		EnablePacketTiming:       true,
		EnablePacketHistogram:    true,
		EnableHeaderAggregates:   true,
		EnableNetFlowV2Histogram: false,
	})
	ev := FlowEvent{
		IPTTLMin:                 u32p(61),
		TCPFlagsOut:              0x1a,
		TCPHeaderObservedOut:     true,
		TCPWindowMaxOut:          u32p(64240),
		NetFlowV2IPSizeHistogram: map[string]uint64{"<=128": 1},
	}
	c.applyPacketFeatureOptions(&ev)

	if ev.NetFlowV2IPSizeHistogram != nil {
		t.Fatalf("nf histogram not cleared: %#v", ev)
	}
	if ev.IPTTLMin == nil || ev.TCPFlagsOut != 0x1a || !ev.TCPHeaderObservedOut || ev.TCPWindowMaxOut == nil {
		t.Fatalf("header aggregates wrongly cleared by the nf gate: %#v", ev)
	}
}

// The kernel-side gate bits written to config_map must mirror the collector
// options exactly — each bit independently.
func TestBuildBPFFlowConfigBits(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts EBPFOptions
		want bpfFlowConfig
	}{
		{"all off", EBPFOptions{}, bpfFlowConfig{}},
		{"tls only", EBPFOptions{EnableTLSHandshakeInspect: true},
			bpfFlowConfig{TLSHandshakeInspectEnabled: 1}},
		{"header aggregates only", EBPFOptions{EnableHeaderAggregates: true},
			bpfFlowConfig{CollectHeaderAggregates: 1}},
		{"netflow histogram only", EBPFOptions{EnableNetFlowV2Histogram: true},
			bpfFlowConfig{CollectNetFlowV2Histogram: 1}},
		{"all on", EBPFOptions{
			EnableTLSHandshakeInspect: true,
			EnableHeaderAggregates:    true,
			EnableNetFlowV2Histogram:  true,
		}, bpfFlowConfig{
			TLSHandshakeInspectEnabled: 1,
			CollectHeaderAggregates:    1,
			CollectNetFlowV2Histogram:  1,
		}},
	} {
		if got := buildBPFFlowConfig(tc.opts); got != tc.want {
			t.Errorf("%s: buildBPFFlowConfig = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
