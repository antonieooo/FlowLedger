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
	SchemaVersion     = "v1alpha2"
	FeatureSetVersion = "flowledger-fast-features-v0"

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
	PktSizeHistogram map[string]uint64

	IATP50       *float64
	IATP95       *float64
	IATStd       *float64
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
	a.mergePacketSizeHistogram(ev.PacketSizeHistogram)
	a.mergeIATHistogram(ev.IATHistogram)
	a.updatePacketSizeMinMax(ev.PktSizeMin, ev.PktSizeMax)
	a.idleGapCount += ev.IdleGapCount
	a.burstCount += ev.BurstCount
	a.directionChanges += ev.DirectionChanges
	a.synCount += ev.SYNCount
	a.finCount += ev.FINCount
	a.rstCount += ev.RSTCount
	a.retransCount += ev.RetransCount
	if ev.RTTEstimateUS > 0 {
		v := ev.RTTEstimateUS
		a.rttEstimateUS = &v
	}

	switch strings.ToUpper(ev.EventType) {
	case "CONNECT", "ACCEPT":
		a.synCount++
	case "CLOSE":
		a.finCount++
	}
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

	iatHistogram := EmptyIATHistogram()
	for _, iat := range a.iatMicros {
		iatHistogram[IATBucket(iat)]++
	}
	mergeHistogram(iatHistogram, a.iatHistogram)

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
	if histogramHasData(a.packetSizeHistogram) {
		// Percentiles from eBPF histograms are estimates; exact raw packet
		// length sequences are deliberately not retained in eBPF mode.
		pktSizeP50 = estimateHistogramPercentile(histogram, packetSizeBucketBounds(), 50)
		pktSizeP95 = estimateHistogramPercentile(histogram, packetSizeBucketBounds(), 95)
		clampFloatPtr(pktSizeP50, pktSizeMin, pktSizeMax)
		clampFloatPtr(pktSizeP95, pktSizeMin, pktSizeMax)
		pktSizeMean = estimateHistogramMean(histogram, packetSizeBucketBounds())
		clampFloatPtr(pktSizeMean, pktSizeMin, pktSizeMax)
	}

	iatP50 := percentileUint64(iatMicros, 50)
	iatP95 := percentileUint64(iatMicros, 95)
	iatStd := stddevUint64(iatMicros)
	if histogramHasData(a.iatHistogram) {
		// IAT percentiles from cgroup_skb are histogram estimates. Standard
		// deviation cannot be recovered from histogram buckets alone. Keep
		// P50/P95/Std on the same histogram-derived distribution instead of
		// mixing histogram percentiles with raw-sample standard deviation.
		iatP50 = estimateHistogramPercentile(iatHistogram, iatBucketBounds(), 50)
		iatP95 = estimateHistogramPercentile(iatHistogram, iatBucketBounds(), 95)
		iatStd = nil
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
		PktSizeHistogram: histogram,

		IATP50:       iatP50,
		IATP95:       iatP95,
		IATStd:       iatStd,
		IdleGapCount: countAbove(iatMicros, 1_000_000) + a.idleGapCount,
		BurstCount:   countBelow(iatMicros, 10_000) + a.burstCount,

		ByteRate:   Rate(bytesTotal, duration),
		PacketRate: Rate(packetsTotal, duration),

		SYNCount:      a.synCount,
		FINCount:      a.finCount,
		RSTCount:      a.rstCount,
		RetransCount:  a.retransCount,
		RTTEstimateUS: a.rttEstimateUS,

		TrafficAccountingAvailable: a.trafficAccountingAvailable,
		PacketTimingAvailable:      a.packetTimingAvailable,
		TCPMetricsAvailable:        a.tcpMetricsAvailable,
		IsLongLived:                duration >= longLivedThreshold,
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
