package features

import (
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

	"FlowLedger/pkg/collector"
)

const (
	// v1alpha4: window_summary records carry PER-WINDOW DELTAS (current
	// cumulative snapshot minus the previous accepted baseline) instead of
	// lifetime cumulative copies; session_summary stays lifetime-cumulative as
	// a diagnostic record. Records self-describe via counter_semantics /
	// window_valid / window_invalid_reason / counter_epoch / final_window (see
	// docs/schema-v1alpha4.md). v1alpha3 fixed the cumulative-snapshot
	// double-counting present in v1alpha2 and exported cgroup_skb-observed skb
	// packet counts (docs/schema-v1alpha3.md, "Migration from v1alpha2").
	SchemaVersion = "v1alpha4"
	// Bumped alongside the schema: window records' histogram/idle/burst/
	// SYN/FIN/RST/byte features are now fixed-window increments, not
	// lifetime-cumulative values, so their distributions are not comparable
	// with v1 windows.
	FeatureSetVersion = "flowledger-fast-features-v2"

	Unknown = "unknown"

	DefaultLongLivedThreshold = 5 * time.Minute
)

var PacketSizeHistogramBuckets = []string{
	"0-63",
	"64-127",
	"128-255",
	"256-511",
	"512-1023",
	"1024-1500",
	">1500",
}

var IATHistogramBuckets = []string{
	"<100",
	"100-1000",
	"1000-10000",
	"10000-100000",
	"100000-1000000",
	">1000000",
}

// NetFlowV2IPSizeBuckets are the NetFlow-v2 edge labels for the
// ntohs(ip.tot_len) histogram counted at cgroup_skb over both directions.
// ">1514" is the overflow bucket (mostly GSO/GRO aggregates); an Anomal-E
// adapter selects only the first five buckets and must report overflow
// separately, never folded into "1025-1514". Kept separate from
// PacketSizeHistogramBuckets, whose 63/127/... edges do not line up.
var NetFlowV2IPSizeBuckets = []string{
	"<=128",
	"129-256",
	"257-512",
	"513-1024",
	"1025-1514",
	">1514",
}

// NetFlowV2IPSizeBucket is the unit-tested Go mirror of the BPF
// nf_ip_size_bucket() function (bpf/flow_events.bpf.c); the edges MUST stay
// identical. Used by mock/delta paths and by the boundary tests.
func NetFlowV2IPSizeBucket(totLen uint64) string {
	switch {
	case totLen <= 128:
		return "<=128"
	case totLen <= 256:
		return "129-256"
	case totLen <= 512:
		return "257-512"
	case totLen <= 1024:
		return "513-1024"
	case totLen <= 1514:
		return "1025-1514"
	default:
		return ">1514"
	}
}

// EmptyNetFlowV2IPSizeHistogram returns an all-zero histogram with every
// NetFlow-v2 bucket present.
func EmptyNetFlowV2IPSizeHistogram() map[string]uint64 {
	out := make(map[string]uint64, len(NetFlowV2IPSizeBuckets))
	for _, bucket := range NetFlowV2IPSizeBuckets {
		out[bucket] = 0
	}
	return out
}

type Snapshot struct {
	BytesTotal   uint64
	PacketsTotal uint64

	ByteRatioOutIn   *float64
	PacketRatioOutIn *float64
	DirectionChanges uint64

	PktSizeMin       *uint64
	PktSizeMax       *uint64
	PktSizeMean      *float64
	PktSizeP50       *float64
	PktSizeP95       *float64
	PktSizeStd       *float64 // L18/B: histogram-derived population stddev approximation
	PktSizeHistogram map[string]uint64

	IATMean      *float64 // L18/B: histogram-derived population mean approximation
	IATP50       *float64
	IATP95       *float64
	IATStd       *float64          // exact for raw samples; histogram-approximation when only histogram has data
	IATHistogram map[string]uint64 // Node-model Phase0: raw IAT bucket counts so consumers can compute KL divergence / Wasserstein vs a baseline distribution
	IdleGapCount uint64
	BurstCount   uint64

	ByteRate   *float64
	PacketRate *float64

	SYNCount      uint64
	FINCount      uint64
	RSTCount      uint64
	RetransCount  uint64
	RTTEstimateUS *uint64

	TrafficAccountingAvailable bool
	PacketTimingAvailable      bool
	TCPMetricsAvailable        bool
	IsLongLived                bool

	// True when a cumulative counter regressed (kernel map entry evicted and
	// re-created mid-flow, or agent restart). The pre-reset maxima are kept;
	// pre- and post-reset values are never summed.
	CounterResetDetected bool
	CounterResetCount    uint64

	// v1alpha3 P1: NetFlow-v2 edge histogram over ntohs(ip.tot_len). Nil (and
	// Available=false) when no IP length was ever observed.
	NetFlowV2IPSizeHistogram          map[string]uint64
	NetFlowV2IPSizeHistogramAvailable bool
}

type Accumulator struct {
	packetSizes []uint64
	iatMicros   []uint64

	packetSizeHistogram map[string]uint64
	iatHistogram        map[string]uint64
	pktSizeMin          *uint64
	pktSizeMax          *uint64
	idleGapCount        uint64
	burstCount          uint64

	directionChanges uint64
	synCount         uint64
	finCount         uint64
	rstCount         uint64
	retransCount     uint64
	rttEstimateUS    *uint64

	// Cumulative-snapshot state (events with CounterSemantics=="cumulative",
	// i.e. eBPF mode). Each event carries the flow's counters since flow
	// start: histograms are REPLACED by the latest complete snapshot and
	// scalar counters keep the latest monotonic value. Summing repeated
	// snapshots — the v1alpha2 behaviour — inflated histogram/idle/burst/SYN
	// counts roughly quadratically with flow age.
	cumPacketSizeHistogram map[string]uint64
	cumIATHistogram        map[string]uint64
	cumIdleGapCount        uint64
	cumBurstCount          uint64
	cumSYNCount            uint64
	cumFINCount            uint64
	cumRSTCount            uint64
	counterResetCount      uint64

	// NetFlow-v2 IP size histogram: delta events sum per bucket; cumulative
	// events replace with the latest complete snapshot (same rules as the
	// packet-size/IAT histograms).
	netflowIPSizeHistogram    map[string]uint64
	cumNetflowIPSizeHistogram map[string]uint64

	trafficAccountingAvailable bool
	packetTimingAvailable      bool
	tcpMetricsAvailable        bool
}

func (a *Accumulator) AddEvent(ev collector.FlowEvent) {
	if ev.TrafficAccountingAvailable || ev.BytesSent > 0 || ev.BytesRecv > 0 || ev.PacketsSent > 0 || ev.PacketsRecv > 0 {
		a.trafficAccountingAvailable = true
	}
	if ev.PacketTimingAvailable || len(ev.PacketSizes) > 0 || len(ev.IATMicros) > 0 {
		a.packetTimingAvailable = true
	}
	if len(ev.PacketSizeHistogram) > 0 || len(ev.IATHistogram) > 0 || ev.PktSizeMin != nil || ev.PktSizeMax != nil {
		a.packetTimingAvailable = true
	}
	if ev.TCPMetricsAvailable || ev.SYNCount > 0 || ev.FINCount > 0 || ev.RSTCount > 0 || ev.RetransCount > 0 || ev.RTTEstimateUS > 0 {
		a.tcpMetricsAvailable = true
	}

	a.packetSizes = append(a.packetSizes, ev.PacketSizes...)
	a.iatMicros = append(a.iatMicros, ev.IATMicros...)
	// min/max are global envelopes; correct for both semantics.
	a.updatePacketSizeMinMax(ev.PktSizeMin, ev.PktSizeMax)
	if ev.RTTEstimateUS > 0 {
		v := ev.RTTEstimateUS
		a.rttEstimateUS = &v
	}

	if ev.CounterSemantics == collector.CounterSemanticsCumulative {
		a.addCumulativeEvent(ev)
		return
	}

	// Delta (mock) semantics: per-event increments are summed, exactly as in
	// v1alpha2.
	a.mergePacketSizeHistogram(ev.PacketSizeHistogram)
	a.mergeIATHistogram(ev.IATHistogram)
	if len(ev.NetFlowV2IPSizeHistogram) > 0 {
		if a.netflowIPSizeHistogram == nil {
			a.netflowIPSizeHistogram = EmptyNetFlowV2IPSizeHistogram()
		}
		mergeHistogram(a.netflowIPSizeHistogram, ev.NetFlowV2IPSizeHistogram)
	}
	a.idleGapCount += ev.IdleGapCount
	a.burstCount += ev.BurstCount
	a.directionChanges += ev.DirectionChanges
	a.synCount += ev.SYNCount
	a.finCount += ev.FINCount
	a.rstCount += ev.RSTCount
	a.retransCount += ev.RetransCount

	// Legacy mock semantics: lifecycle events imply one SYN / one FIN.
	// Cumulative (eBPF) events never reach this: the BPF program already
	// counts these transitions, and adding them again here was the v1alpha2
	// SYN/FIN double count.
	switch strings.ToUpper(ev.EventType) {
	case "CONNECT", "ACCEPT":
		a.synCount++
	case "CLOSE":
		a.finCount++
	}
}

// addCumulativeEvent merges one cumulative snapshot: histograms are replaced
// by the latest complete snapshot (never bucket-summed) and scalar counters
// keep the latest monotonic value. A regression (new value below the stored
// one) means the kernel-side accumulator was reset (LRU eviction + re-create,
// agent restart); it is recorded in counterResetCount and the pre-reset value
// is kept — pre- and post-reset values are never summed. A zero counter is
// "not provided" (e.g. a CLOSE emitted after the map entry vanished), not a
// reset.
func (a *Accumulator) addCumulativeEvent(ev collector.FlowEvent) {
	if len(ev.PacketSizeHistogram) > 0 {
		a.cumPacketSizeHistogram = copyHistogram(ev.PacketSizeHistogram)
	}
	if len(ev.IATHistogram) > 0 {
		a.cumIATHistogram = copyHistogram(ev.IATHistogram)
	}
	if len(ev.NetFlowV2IPSizeHistogram) > 0 {
		a.cumNetflowIPSizeHistogram = copyHistogram(ev.NetFlowV2IPSizeHistogram)
	}
	reset := false
	a.cumIdleGapCount = latestMonotonic(a.cumIdleGapCount, ev.IdleGapCount, &reset)
	a.cumBurstCount = latestMonotonic(a.cumBurstCount, ev.BurstCount, &reset)
	a.cumSYNCount = latestMonotonic(a.cumSYNCount, ev.SYNCount, &reset)
	a.cumFINCount = latestMonotonic(a.cumFINCount, ev.FINCount, &reset)
	a.cumRSTCount = latestMonotonic(a.cumRSTCount, ev.RSTCount, &reset)
	a.directionChanges = latestMonotonic(a.directionChanges, ev.DirectionChanges, &reset)
	a.retransCount = latestMonotonic(a.retransCount, ev.RetransCount, &reset)
	if reset {
		a.counterResetCount++
	}
}

// latestMonotonic returns the latest cumulative value under the monotonicity
// constraint: increases are taken, a regression keeps the previous value and
// flags *reset, and zero means "not provided" and is ignored.
func latestMonotonic(prev, next uint64, reset *bool) uint64 {
	if next == 0 {
		return prev
	}
	if next < prev {
		*reset = true
		return prev
	}
	return next
}

func copyHistogram(src map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(src))
	for bucket, count := range src {
		out[bucket] = count
	}
	return out
}

func (a *Accumulator) Snapshot(bytesOut, bytesIn, packetsOut, packetsIn uint64, duration time.Duration, longLivedThreshold time.Duration) Snapshot {
	if longLivedThreshold <= 0 {
		longLivedThreshold = DefaultLongLivedThreshold
	}
	histogram := EmptyPacketSizeHistogram()
	for _, size := range a.packetSizes {
		histogram[PacketSizeBucket(size)]++
	}
	mergeHistogram(histogram, a.packetSizeHistogram)
	// The cumulative state already holds the latest complete snapshot, so it
	// contributes its totals exactly once.
	mergeHistogram(histogram, a.cumPacketSizeHistogram)

	iatHistogram := EmptyIATHistogram()
	for _, iat := range a.iatMicros {
		iatHistogram[IATBucket(iat)]++
	}
	mergeHistogram(iatHistogram, a.iatHistogram)
	mergeHistogram(iatHistogram, a.cumIATHistogram)

	var netflowHistogram map[string]uint64
	if histogramHasData(a.netflowIPSizeHistogram) || histogramHasData(a.cumNetflowIPSizeHistogram) {
		netflowHistogram = EmptyNetFlowV2IPSizeHistogram()
		mergeHistogram(netflowHistogram, a.netflowIPSizeHistogram)
		mergeHistogram(netflowHistogram, a.cumNetflowIPSizeHistogram)
	}

	bytesTotal := bytesOut + bytesIn
	packetsTotal := packetsOut + packetsIn
	packetSizes := append([]uint64{}, a.packetSizes...)
	iatMicros := append([]uint64{}, a.iatMicros...)
	pktSizeMin := minUint64(packetSizes)
	if a.pktSizeMin != nil && (pktSizeMin == nil || *a.pktSizeMin < *pktSizeMin) {
		v := *a.pktSizeMin
		pktSizeMin = &v
	}
	pktSizeMax := maxUint64(packetSizes)
	if a.pktSizeMax != nil && (pktSizeMax == nil || *a.pktSizeMax > *pktSizeMax) {
		v := *a.pktSizeMax
		pktSizeMax = &v
	}

	pktSizeP50 := percentileUint64(packetSizes, 50)
	pktSizeP95 := percentileUint64(packetSizes, 95)
	pktSizeMean := meanUint64(packetSizes)
	pktSizeStd := stddevUint64(packetSizes)
	if histogramHasData(a.packetSizeHistogram) || histogramHasData(a.cumPacketSizeHistogram) {
		// Percentiles from eBPF histograms are estimates; exact raw packet
		// length sequences are deliberately not retained in eBPF mode.
		pktSizeP50 = estimateHistogramPercentile(histogram, packetSizeBucketBounds(), 50)
		pktSizeP95 = estimateHistogramPercentile(histogram, packetSizeBucketBounds(), 95)
		clampFloatPtr(pktSizeP50, pktSizeMin, pktSizeMax)
		clampFloatPtr(pktSizeP95, pktSizeMin, pktSizeMax)
		pktSizeMean = estimateHistogramMean(histogram, packetSizeBucketBounds())
		clampFloatPtr(pktSizeMean, pktSizeMin, pktSizeMax)
		// L18/B: previously pktSizeStd was left as the raw-sample value or nil
		// when only histogram data existed, causing 100% missingness downstream.
		// Use a midpoint-based approximation; bounded error, but enables jitter
		// / beacon variance features in the model.
		pktSizeStd = estimateHistogramStddev(histogram, packetSizeBucketBounds())
	}

	iatP50 := percentileUint64(iatMicros, 50)
	iatP95 := percentileUint64(iatMicros, 95)
	iatStd := stddevUint64(iatMicros)
	iatMean := meanUint64(iatMicros)
	if histogramHasData(a.iatHistogram) || histogramHasData(a.cumIATHistogram) {
		// IAT percentiles from cgroup_skb are histogram estimates. Standard
		// deviation can be approximated from bucket midpoints; the error is
		// bounded by ~half the widest bucket width and is acceptable for the
		// jitter/beacon-period signals the central layer consumes (see
		// estimateHistogramStddev docstring).
		iatP50 = estimateHistogramPercentile(iatHistogram, iatBucketBounds(), 50)
		iatP95 = estimateHistogramPercentile(iatHistogram, iatBucketBounds(), 95)
		iatStd = estimateHistogramStddev(iatHistogram, iatBucketBounds())
		iatMean = estimateHistogramMean(iatHistogram, iatBucketBounds())
	}

	return Snapshot{
		BytesTotal:   bytesTotal,
		PacketsTotal: packetsTotal,

		ByteRatioOutIn:   SafeRatio(bytesOut, bytesIn),
		PacketRatioOutIn: SafeRatio(packetsOut, packetsIn),
		DirectionChanges: a.directionChanges,

		PktSizeMin:       pktSizeMin,
		PktSizeMax:       pktSizeMax,
		PktSizeMean:      pktSizeMean,
		PktSizeP50:       pktSizeP50,
		PktSizeP95:       pktSizeP95,
		PktSizeStd:       pktSizeStd,
		PktSizeHistogram: histogram,

		IATMean:      iatMean,
		IATP50:       iatP50,
		IATP95:       iatP95,
		IATStd:       iatStd,
		IATHistogram: iatHistogram,
		IdleGapCount: countAbove(iatMicros, 1_000_000) + a.idleGapCount + a.cumIdleGapCount,
		BurstCount:   countBelow(iatMicros, 10_000) + a.burstCount + a.cumBurstCount,

		ByteRate:   Rate(bytesTotal, duration),
		PacketRate: Rate(packetsTotal, duration),

		SYNCount:      a.synCount + a.cumSYNCount,
		FINCount:      a.finCount + a.cumFINCount,
		RSTCount:      a.rstCount + a.cumRSTCount,
		RetransCount:  a.retransCount,
		RTTEstimateUS: a.rttEstimateUS,

		TrafficAccountingAvailable: a.trafficAccountingAvailable,
		PacketTimingAvailable:      a.packetTimingAvailable,
		TCPMetricsAvailable:        a.tcpMetricsAvailable,
		IsLongLived:                duration >= longLivedThreshold,

		CounterResetDetected: a.counterResetCount > 0,
		CounterResetCount:    a.counterResetCount,

		NetFlowV2IPSizeHistogram:          netflowHistogram,
		NetFlowV2IPSizeHistogramAvailable: netflowHistogram != nil,
	}
}

// SubtractHistogram returns the per-bucket difference cur-base of two
// cumulative histograms. regressed reports whether any bucket went backwards
// (cur below base, or a base bucket missing from cur) — the signature of a
// kernel-side counter reset. Regressed buckets are clamped to 0, never
// underflowed; callers must treat the whole window as invalid when regressed.
func SubtractHistogram(cur, base map[string]uint64) (map[string]uint64, bool) {
	out := make(map[string]uint64, len(cur))
	regressed := false
	for bucket, v := range cur {
		b := base[bucket]
		if v < b {
			regressed = true
			out[bucket] = 0
			continue
		}
		out[bucket] = v - b
	}
	for bucket, b := range base {
		if _, ok := cur[bucket]; !ok && b > 0 {
			regressed = true
			out[bucket] = 0
		}
	}
	return out, regressed
}

// WindowCounterDeltas are the additive counters of one fixed window: every
// field is a current-minus-baseline difference computed by the sessionizer.
// Histogram maps are already differenced per bucket; NetFlowV2IPSizeHistogram
// is nil when the signal was never observed.
type WindowCounterDeltas struct {
	BytesOut, BytesIn        uint64
	PacketsOut, PacketsIn    uint64
	IdleGapCount, BurstCount uint64
	SYNCount                 uint64
	FINCount                 uint64
	RSTCount                 uint64
	RetransCount             uint64
	DirectionChanges         uint64
	PktSizeHistogram         map[string]uint64
	IATHistogram             map[string]uint64
	NetFlowV2IPSizeHistogram map[string]uint64
}

// WindowSnapshot builds the feature snapshot of one window-delta record.
// Additive counters and histograms come from the differenced deltas and the
// distribution stats are recomputed from the DELTA histograms; rates use the
// window duration. Non-additive context is carried from the lifetime
// snapshot unchanged: availability flags, IsLongLived, the RTT gauge, reset
// diagnostics, and the pkt_size_min/max envelope — the kernel only keeps a
// lifetime envelope, so window records must not present it as per-window.
func WindowSnapshot(lifetime Snapshot, d WindowCounterDeltas, windowDuration time.Duration) Snapshot {
	pktHist := d.PktSizeHistogram
	if pktHist == nil {
		pktHist = EmptyPacketSizeHistogram()
	}
	iatHist := d.IATHistogram
	if iatHist == nil {
		iatHist = EmptyIATHistogram()
	}

	var pktMean, pktP50, pktP95, pktStd *float64
	if histogramHasData(pktHist) {
		pktP50 = estimateHistogramPercentile(pktHist, packetSizeBucketBounds(), 50)
		pktP95 = estimateHistogramPercentile(pktHist, packetSizeBucketBounds(), 95)
		pktMean = estimateHistogramMean(pktHist, packetSizeBucketBounds())
		pktStd = estimateHistogramStddev(pktHist, packetSizeBucketBounds())
		// Estimates stay inside the lifetime envelope; the true window
		// envelope is unknown (kernel keeps only lifetime min/max).
		clampFloatPtr(pktP50, lifetime.PktSizeMin, lifetime.PktSizeMax)
		clampFloatPtr(pktP95, lifetime.PktSizeMin, lifetime.PktSizeMax)
		clampFloatPtr(pktMean, lifetime.PktSizeMin, lifetime.PktSizeMax)
	}
	var iatMean, iatP50, iatP95, iatStd *float64
	if histogramHasData(iatHist) {
		iatP50 = estimateHistogramPercentile(iatHist, iatBucketBounds(), 50)
		iatP95 = estimateHistogramPercentile(iatHist, iatBucketBounds(), 95)
		iatMean = estimateHistogramMean(iatHist, iatBucketBounds())
		iatStd = estimateHistogramStddev(iatHist, iatBucketBounds())
	}

	bytesTotal := d.BytesOut + d.BytesIn
	packetsTotal := d.PacketsOut + d.PacketsIn
	return Snapshot{
		BytesTotal:   bytesTotal,
		PacketsTotal: packetsTotal,

		ByteRatioOutIn:   SafeRatio(d.BytesOut, d.BytesIn),
		PacketRatioOutIn: SafeRatio(d.PacketsOut, d.PacketsIn),
		DirectionChanges: d.DirectionChanges,

		PktSizeMin:       lifetime.PktSizeMin,
		PktSizeMax:       lifetime.PktSizeMax,
		PktSizeMean:      pktMean,
		PktSizeP50:       pktP50,
		PktSizeP95:       pktP95,
		PktSizeStd:       pktStd,
		PktSizeHistogram: pktHist,

		IATMean:      iatMean,
		IATP50:       iatP50,
		IATP95:       iatP95,
		IATStd:       iatStd,
		IATHistogram: iatHist,
		IdleGapCount: d.IdleGapCount,
		BurstCount:   d.BurstCount,

		ByteRate:   Rate(bytesTotal, windowDuration),
		PacketRate: Rate(packetsTotal, windowDuration),

		SYNCount:      d.SYNCount,
		FINCount:      d.FINCount,
		RSTCount:      d.RSTCount,
		RetransCount:  d.RetransCount,
		RTTEstimateUS: lifetime.RTTEstimateUS,

		TrafficAccountingAvailable: lifetime.TrafficAccountingAvailable,
		PacketTimingAvailable:      lifetime.PacketTimingAvailable,
		TCPMetricsAvailable:        lifetime.TCPMetricsAvailable,
		IsLongLived:                lifetime.IsLongLived,

		CounterResetDetected: lifetime.CounterResetDetected,
		CounterResetCount:    lifetime.CounterResetCount,

		NetFlowV2IPSizeHistogram:          d.NetFlowV2IPSizeHistogram,
		NetFlowV2IPSizeHistogramAvailable: d.NetFlowV2IPSizeHistogram != nil,
	}
}

func (a *Accumulator) mergePacketSizeHistogram(histogram map[string]uint64) {
	if len(histogram) == 0 {
		return
	}
	if a.packetSizeHistogram == nil {
		a.packetSizeHistogram = EmptyPacketSizeHistogram()
	}
	mergeHistogram(a.packetSizeHistogram, histogram)
}

func (a *Accumulator) mergeIATHistogram(histogram map[string]uint64) {
	if len(histogram) == 0 {
		return
	}
	if a.iatHistogram == nil {
		a.iatHistogram = EmptyIATHistogram()
	}
	mergeHistogram(a.iatHistogram, histogram)
}

func (a *Accumulator) updatePacketSizeMinMax(minValue, maxValue *uint64) {
	if minValue != nil && (a.pktSizeMin == nil || *minValue < *a.pktSizeMin) {
		v := *minValue
		a.pktSizeMin = &v
	}
	if maxValue != nil && (a.pktSizeMax == nil || *maxValue > *a.pktSizeMax) {
		v := *maxValue
		a.pktSizeMax = &v
	}
}

func EmptyPacketSizeHistogram() map[string]uint64 {
	out := make(map[string]uint64, len(PacketSizeHistogramBuckets))
	for _, bucket := range PacketSizeHistogramBuckets {
		out[bucket] = 0
	}
	return out
}

func EmptyIATHistogram() map[string]uint64 {
	out := make(map[string]uint64, len(IATHistogramBuckets))
	for _, bucket := range IATHistogramBuckets {
		out[bucket] = 0
	}
	return out
}

func PacketSizeBucket(size uint64) string {
	switch {
	case size <= 63:
		return "0-63"
	case size <= 127:
		return "64-127"
	case size <= 255:
		return "128-255"
	case size <= 511:
		return "256-511"
	case size <= 1023:
		return "512-1023"
	case size <= 1500:
		return "1024-1500"
	default:
		return ">1500"
	}
}

func IATBucket(iatMicros uint64) string {
	switch {
	case iatMicros < 100:
		return "<100"
	case iatMicros <= 1000:
		return "100-1000"
	case iatMicros <= 10000:
		return "1000-10000"
	case iatMicros <= 100000:
		return "10000-100000"
	case iatMicros <= 1000000:
		return "100000-1000000"
	default:
		return ">1000000"
	}
}

func SafeRatio(out, in uint64) *float64 {
	if in == 0 {
		return nil
	}
	v := float64(out) / float64(in)
	return &v
}

func Rate(total uint64, duration time.Duration) *float64 {
	if duration <= 0 {
		return nil
	}
	v := float64(total) / duration.Seconds()
	return &v
}

func IPFamily(src, dst string) string {
	for _, raw := range []string{src, dst} {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if addr.Is4() {
			return "ipv4"
		}
		if addr.Is6() {
			return "ipv6"
		}
	}
	return Unknown
}

func BaseDirection(srcIP, dstIP string) string {
	src, srcErr := netip.ParseAddr(srcIP)
	dst, dstErr := netip.ParseAddr(dstIP)
	if srcErr != nil || dstErr != nil {
		return Unknown
	}
	if src.IsLoopback() && dst.IsLoopback() {
		return "local"
	}
	if src == dst {
		return "local"
	}
	return Unknown
}

func ProtocolGuess(protocol string, dstPort uint16) string {
	if strings.EqualFold(protocol, "tcp") {
		switch dstPort {
		case 443, 8443:
			return "tls"
		case 80, 8080:
			return "http"
		}
	}
	return Unknown
}

func IsTLSLike(protocolGuess string, dstPort uint16) bool {
	return protocolGuess == "tls" || dstPort == 443 || dstPort == 8443
}

func ReasonCodes(c ReasonContext) []string {
	reasons := []string{}
	if c.CrossNamespace {
		reasons = append(reasons, "CROSS_NAMESPACE")
	}
	if c.ExternalDestination {
		reasons = append(reasons, "EXTERNAL_DESTINATION")
	}
	if c.LongLived {
		reasons = append(reasons, "LONG_LIVED")
	}
	if c.UnknownIdentity {
		reasons = append(reasons, "UNKNOWN_IDENTITY")
	}
	if c.RolloutWindow {
		reasons = append(reasons, "ROLLOUT_WINDOW")
	}
	if c.VisibilityDegraded {
		reasons = append(reasons, "VISIBILITY_DEGRADED")
	}
	return reasons
}

type ReasonContext struct {
	CrossNamespace      bool
	ExternalDestination bool
	LongLived           bool
	UnknownIdentity     bool
	RolloutWindow       bool
	VisibilityDegraded  bool
}

func minUint64(values []uint64) *uint64 {
	if len(values) == 0 {
		return nil
	}
	min := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
	}
	return &min
}

func maxUint64(values []uint64) *uint64 {
	if len(values) == 0 {
		return nil
	}
	max := values[0]
	for _, v := range values[1:] {
		if v > max {
			max = v
		}
	}
	return &max
}

func meanUint64(values []uint64) *float64 {
	if len(values) == 0 {
		return nil
	}
	var sum uint64
	for _, v := range values {
		sum += v
	}
	mean := float64(sum) / float64(len(values))
	return &mean
}

func percentileUint64(values []uint64, pct float64) *float64 {
	if len(values) == 0 {
		return nil
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	if len(values) == 1 {
		v := float64(values[0])
		return &v
	}
	rank := (pct / 100) * float64(len(values)-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))
	if lower == upper {
		v := float64(values[lower])
		return &v
	}
	weight := rank - float64(lower)
	v := float64(values[lower])*(1-weight) + float64(values[upper])*weight
	return &v
}

func stddevUint64(values []uint64) *float64 {
	if len(values) == 0 {
		return nil
	}
	mean := meanUint64(values)
	if mean == nil {
		return nil
	}
	var sum float64
	for _, v := range values {
		d := float64(v) - *mean
		sum += d * d
	}
	std := math.Sqrt(sum / float64(len(values)))
	return &std
}

func countAbove(values []uint64, threshold uint64) uint64 {
	var count uint64
	for _, v := range values {
		if v > threshold {
			count++
		}
	}
	return count
}

func countBelow(values []uint64, threshold uint64) uint64 {
	var count uint64
	for _, v := range values {
		if v > 0 && v < threshold {
			count++
		}
	}
	return count
}

func mergeHistogram(dst, src map[string]uint64) {
	for bucket, count := range src {
		dst[bucket] += count
	}
}

func histogramHasData(histogram map[string]uint64) bool {
	for _, count := range histogram {
		if count > 0 {
			return true
		}
	}
	return false
}

type histogramBucketBound struct {
	label string
	min   float64
	max   float64
}

func packetSizeBucketBounds() []histogramBucketBound {
	return []histogramBucketBound{
		{label: "0-63", min: 0, max: 63},
		{label: "64-127", min: 64, max: 127},
		{label: "128-255", min: 128, max: 255},
		{label: "256-511", min: 256, max: 511},
		{label: "512-1023", min: 512, max: 1023},
		{label: "1024-1500", min: 1024, max: 1500},
		{label: ">1500", min: 1501, max: 1501},
	}
}

func iatBucketBounds() []histogramBucketBound {
	return []histogramBucketBound{
		{label: "<100", min: 0, max: 99},
		{label: "100-1000", min: 100, max: 1000},
		{label: "1000-10000", min: 1000, max: 10000},
		{label: "10000-100000", min: 10000, max: 100000},
		{label: "100000-1000000", min: 100000, max: 1000000},
		{label: ">1000000", min: 1000001, max: 1000001},
	}
}

func estimateHistogramPercentile(histogram map[string]uint64, bounds []histogramBucketBound, pct float64) *float64 {
	var total uint64
	for _, bucket := range bounds {
		total += histogram[bucket.label]
	}
	if total == 0 {
		return nil
	}

	target := (pct / 100) * float64(total)
	if target <= 0 {
		target = 1
	}
	var seen uint64
	for _, bucket := range bounds {
		count := histogram[bucket.label]
		if count == 0 {
			continue
		}
		next := seen + count
		if float64(next) >= target {
			within := (target - float64(seen)) / float64(count)
			if within < 0 {
				within = 0
			}
			if within > 1 {
				within = 1
			}
			v := bucket.min + within*(bucket.max-bucket.min)
			return &v
		}
		seen = next
	}

	last := bounds[len(bounds)-1].max
	return &last
}

func estimateHistogramMean(histogram map[string]uint64, bounds []histogramBucketBound) *float64 {
	var total uint64
	var weighted float64
	for _, bucket := range bounds {
		count := histogram[bucket.label]
		if count == 0 {
			continue
		}
		midpoint := bucket.min + (bucket.max-bucket.min)/2
		weighted += midpoint * float64(count)
		total += count
	}
	if total == 0 {
		return nil
	}
	mean := weighted / float64(total)
	return &mean
}

// estimateHistogramStddev computes an approximate population standard deviation
// from a bucket histogram by assigning the bucket midpoint to every sample in
// the bucket and applying the standard E[X²] − E[X]² formula. The error is
// bounded by roughly half the widest bucket width — for our packet-size buckets
// (max width 487 at 512-1023) and IAT buckets (max width 900_000 at the
// 100k-1M bucket) the result is good enough for "is this flow's IAT
// dispersion roughly constant or highly variable" questions, which is what
// jitter/beacon detection needs. It is NOT exact and should not be relied on
// for tail analysis. Returns math.NaN-free non-negative *float64, or nil if
// the histogram is empty.
func estimateHistogramStddev(histogram map[string]uint64, bounds []histogramBucketBound) *float64 {
	var total uint64
	var sumW float64
	var sumW2 float64
	for _, bucket := range bounds {
		count := histogram[bucket.label]
		if count == 0 {
			continue
		}
		midpoint := bucket.min + (bucket.max-bucket.min)/2
		sumW += midpoint * float64(count)
		sumW2 += midpoint * midpoint * float64(count)
		total += count
	}
	if total == 0 {
		return nil
	}
	mean := sumW / float64(total)
	variance := sumW2/float64(total) - mean*mean
	if variance < 0 { // floating-point round-off guard
		variance = 0
	}
	std := math.Sqrt(variance)
	return &std
}

func clampFloatPtr(value *float64, minValue, maxValue *uint64) {
	if value == nil {
		return
	}
	if minValue != nil && *value < float64(*minValue) {
		*value = float64(*minValue)
	}
	if maxValue != nil && *value > float64(*maxValue) {
		*value = float64(*maxValue)
	}
}
