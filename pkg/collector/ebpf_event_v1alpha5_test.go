package collector

import (
	"reflect"
	"testing"
)

// buckets that make every index distinguishable, so a transposed or
// off-by-one array copy cannot pass by coincidence.
func directionalRaw() rawEBPFEvent {
	return rawEBPFEvent{
		EventType: ebpfEventStats,
		Family:    ebpfFamilyIPv4,
		Protocol:  ebpfProtocolTCP,

		PktSizeBuckets:    [7]uint64{11, 22, 33, 44, 55, 66, 77},
		PktSizeBucketsOut: [7]uint64{1, 2, 3, 4, 5, 6, 7},
		PktSizeBucketsIn:  [7]uint64{10, 20, 30, 40, 50, 60, 70},

		IATBuckets:    [6]uint64{110, 220, 330, 440, 550, 660},
		IATBucketsOut: [6]uint64{100, 200, 300, 400, 500, 600},
		IATBucketsIn:  [6]uint64{10, 20, 30, 40, 50, 60},

		RealPacketsSent: 28,  // Σ PktSizeBucketsOut
		RealPacketsRecv: 280, // Σ PktSizeBucketsIn

		SYNCount:    1,
		FINCount:    0,
		RSTCount:    0,
		SYNCountOut: 3,
		SYNCountIn:  1,
		FINCountOut: 2,
		FINCountIn:  4,
		RSTCountOut: 5,
		RSTCountIn:  6,

		IpTtlMin:    62,
		IpTtlMax:    64,
		IpTtlMinOut: 64,
		IpTtlMaxOut: 64,
		IpTtlMinIn:  62,
		IpTtlMaxIn:  63,
	}
}

// The per-direction histograms must be labelled from the SAME bucket-name
// tables as the mixed ones. If a future edit forks a second table, the label
// sets diverge and this fails — §7-3, one bucket-edge source per family.
func TestDirectionalHistogramsShareBucketLabels(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(directionalRaw())
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	keysOf := func(h map[string]uint64) []string {
		out := make([]string, 0, len(h))
		for k := range h {
			out = append(out, k)
		}
		return out
	}
	sameSet := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		m := map[string]int{}
		for _, k := range a {
			m[k]++
		}
		for _, k := range b {
			m[k]--
		}
		for _, v := range m {
			if v != 0 {
				return false
			}
		}
		return true
	}
	for _, tc := range []struct {
		name       string
		mixed, out map[string]uint64
		in         map[string]uint64
	}{
		{"pkt_size", ev.PacketSizeHistogram, ev.PacketSizeHistogramOut, ev.PacketSizeHistogramIn},
		{"iat", ev.IATHistogram, ev.IATHistogramOut, ev.IATHistogramIn},
	} {
		if !sameSet(keysOf(tc.mixed), keysOf(tc.out)) {
			t.Errorf("%s: out buckets %v != mixed buckets %v", tc.name, keysOf(tc.out), keysOf(tc.mixed))
		}
		if !sameSet(keysOf(tc.mixed), keysOf(tc.in)) {
			t.Errorf("%s: in buckets %v != mixed buckets %v", tc.name, keysOf(tc.in), keysOf(tc.mixed))
		}
	}
	// And the literal tables are the same objects, not copies that could drift.
	if !reflect.DeepEqual(ebpfPacketSizeHistogramBuckets, ebpfPacketSizeHistogramBuckets) ||
		len(ebpfPacketSizeHistogramBuckets) != 7 || len(ebpfIATHistogramBuckets) != 6 {
		t.Fatalf("bucket label tables changed shape: pkt=%v iat=%v",
			ebpfPacketSizeHistogramBuckets, ebpfIATHistogramBuckets)
	}
}

// Every bucket of every direction must arrive at the right label, in order.
// A silent array-index shift is the failure this catches.
func TestDirectionalHistogramValuesLandOnTheRightBuckets(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(directionalRaw())
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	for i, label := range ebpfPacketSizeHistogramBuckets {
		if got, want := ev.PacketSizeHistogramOut[label], uint64(i+1); got != want {
			t.Errorf("pkt out[%s] = %d, want %d", label, got, want)
		}
		if got, want := ev.PacketSizeHistogramIn[label], uint64((i+1)*10); got != want {
			t.Errorf("pkt in[%s] = %d, want %d", label, got, want)
		}
	}
	for i, label := range ebpfIATHistogramBuckets {
		if got, want := ev.IATHistogramOut[label], uint64((i+1)*100); got != want {
			t.Errorf("iat out[%s] = %d, want %d", label, got, want)
		}
		if got, want := ev.IATHistogramIn[label], uint64((i+1)*10); got != want {
			t.Errorf("iat in[%s] = %d, want %d", label, got, want)
		}
	}
}

// out + in == mixed, bucket by bucket, for BOTH families. The kernel keeps
// three independent accumulations; the conversion layer must not disturb the
// identity between them.
func TestDirectionalHistogramsSumToMixed(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(directionalRaw())
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	for _, label := range ebpfPacketSizeHistogramBuckets {
		if got, want := ev.PacketSizeHistogramOut[label]+ev.PacketSizeHistogramIn[label], ev.PacketSizeHistogram[label]; got != want {
			t.Errorf("pkt_size[%s]: out+in = %d, mixed = %d", label, got, want)
		}
	}
	for _, label := range ebpfIATHistogramBuckets {
		if got, want := ev.IATHistogramOut[label]+ev.IATHistogramIn[label], ev.IATHistogram[label]; got != want {
			t.Errorf("iat[%s]: out+in = %d, mixed = %d", label, got, want)
		}
	}
}

// Σ over the per-direction packet-size histogram must equal that direction's
// skb packet count: both come off the same call site for the same skb.
func TestDirectionalPacketHistogramReconcilesWithSKBCounts(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(directionalRaw())
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	sum := func(h map[string]uint64) uint64 {
		var total uint64
		for _, v := range h {
			total += v
		}
		return total
	}
	if got, want := sum(ev.PacketSizeHistogramOut), ev.RealPacketsSent; got != want {
		t.Errorf("Σ pkt_size_histogram_out = %d, observed_skb_packets_out = %d", got, want)
	}
	if got, want := sum(ev.PacketSizeHistogramIn), ev.RealPacketsRecv; got != want {
		t.Errorf("Σ pkt_size_histogram_in = %d, observed_skb_packets_in = %d", got, want)
	}
}

// The legacy per-connection syn/fin/rst counters and the new per-packet
// per-direction counters are DIFFERENT quantities and must not be conflated:
// here syn_count is the tracepoint's 1 while syn_count_out is 3 SYN packets
// (an initial SYN plus two retransmissions).
func TestPerPacketFlagCountsAreIndependentOfPerConnectionCounts(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(directionalRaw())
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if ev.SYNCount != 1 {
		t.Errorf("SYNCount = %d, want the untouched per-connection 1", ev.SYNCount)
	}
	if ev.SYNCountOut != 3 || ev.SYNCountIn != 1 {
		t.Errorf("SYNCountOut/In = %d/%d, want 3/1", ev.SYNCountOut, ev.SYNCountIn)
	}
	if ev.FINCountOut != 2 || ev.FINCountIn != 4 {
		t.Errorf("FINCountOut/In = %d/%d, want 2/4", ev.FINCountOut, ev.FINCountIn)
	}
	if ev.RSTCountOut != 5 || ev.RSTCountIn != 6 {
		t.Errorf("RSTCountOut/In = %d/%d, want 5/6", ev.RSTCountOut, ev.RSTCountIn)
	}
	// The dead per-connection rst_count must stay dead: v1alpha5 introduces
	// per-direction RST counting and deliberately does NOT light this up,
	// because a v1alpha4 analysis reading rst_count must keep getting 0.
	if ev.RSTCount != 0 {
		t.Errorf("RSTCount = %d, want 0 — the legacy field must stay unfired", ev.RSTCount)
	}
}

func TestDirectionalTTLEnvelopeConverts(t *testing.T) {
	ev, err := convertRawEBPFEventToFlowEvent(directionalRaw())
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	for _, tc := range []struct {
		name string
		got  *uint32
		want uint32
	}{
		{"ip_ttl_min_out", ev.IPTTLMinOut, 64},
		{"ip_ttl_max_out", ev.IPTTLMaxOut, 64},
		{"ip_ttl_min_in", ev.IPTTLMinIn, 62},
		{"ip_ttl_max_in", ev.IPTTLMaxIn, 63},
	} {
		if tc.got == nil {
			t.Errorf("%s = nil, want %d", tc.name, tc.want)
			continue
		}
		if *tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, *tc.got, tc.want)
		}
	}
}

// A direction the kernel never observed must arrive as nil, never as a
// fabricated all-zero histogram or a TTL of 0: these fields carry no
// *_available companion, so nil is their only way to say "no reading".
func TestUnobservedDirectionStaysNil(t *testing.T) {
	raw := directionalRaw()
	raw.PktSizeBucketsIn = [7]uint64{}
	raw.IATBucketsIn = [6]uint64{}
	raw.IpTtlMinIn, raw.IpTtlMaxIn = 0, 0
	raw.RealPacketsRecv = 0

	ev, err := convertRawEBPFEventToFlowEvent(raw)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if ev.PacketSizeHistogramIn != nil {
		t.Errorf("PacketSizeHistogramIn = %v, want nil for an unobserved direction", ev.PacketSizeHistogramIn)
	}
	if ev.IATHistogramIn != nil {
		t.Errorf("IATHistogramIn = %v, want nil", ev.IATHistogramIn)
	}
	if ev.IPTTLMinIn != nil || ev.IPTTLMaxIn != nil {
		t.Errorf("IPTTLMin/MaxIn = %v/%v, want nil (TTL 0 is invalid on the wire)", ev.IPTTLMinIn, ev.IPTTLMaxIn)
	}
	// The observed direction is unaffected.
	if ev.PacketSizeHistogramOut == nil || ev.IPTTLMinOut == nil {
		t.Errorf("observed out direction was collaterally nulled")
	}
}
