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

type Snapshot struct {
	BytesTotal  uint64
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
	PacketTimingAvailable     bool
	TCPMetricsAvailable        bool
	IsLongLived                bool
}

type Accumulator struct {
	packetSizes []uint64
	iatMicros   []uint64

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
	if ev.TCPMetricsAvailable || ev.SYNCount > 0 || ev.FINCount > 0 || ev.RSTCount > 0 || ev.RetransCount > 0 || ev.RTTEstimateUS > 0 {
		a.tcpMetricsAvailable = true
	}

	a.packetSizes = append(a.packetSizes, ev.PacketSizes...)
	a.iatMicros = append(a.iatMicros, ev.IATMicros...)
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

	bytesTotal := bytesOut + bytesIn
	packetsTotal := packetsOut + packetsIn
	packetSizes := append([]uint64{}, a.packetSizes...)
	iatMicros := append([]uint64{}, a.iatMicros...)

	return Snapshot{
		BytesTotal:  bytesTotal,
		PacketsTotal: packetsTotal,

		ByteRatioOutIn:   SafeRatio(bytesOut, bytesIn),
		PacketRatioOutIn: SafeRatio(packetsOut, packetsIn),
		DirectionChanges: a.directionChanges,

		PktSizeMin:       minUint64(packetSizes),
		PktSizeMax:       maxUint64(packetSizes),
		PktSizeMean:      meanUint64(packetSizes),
		PktSizeP50:       percentileUint64(packetSizes, 50),
		PktSizeP95:       percentileUint64(packetSizes, 95),
		PktSizeHistogram: histogram,

		IATP50:       percentileUint64(iatMicros, 50),
		IATP95:       percentileUint64(iatMicros, 95),
		IATStd:       stddevUint64(iatMicros),
		IdleGapCount: countAbove(iatMicros, 1_000_000),
		BurstCount:   countBelow(iatMicros, 10_000),

		ByteRate:   Rate(bytesTotal, duration),
		PacketRate: Rate(packetsTotal, duration),

		SYNCount:      a.synCount,
		FINCount:      a.finCount,
		RSTCount:      a.rstCount,
		RetransCount:  a.retransCount,
		RTTEstimateUS: a.rttEstimateUS,

		TrafficAccountingAvailable: a.trafficAccountingAvailable,
		PacketTimingAvailable:     a.packetTimingAvailable,
		TCPMetricsAvailable:        a.tcpMetricsAvailable,
		IsLongLived:                duration >= longLivedThreshold,
	}
}

func EmptyPacketSizeHistogram() map[string]uint64 {
	out := make(map[string]uint64, len(PacketSizeHistogramBuckets))
	for _, bucket := range PacketSizeHistogramBuckets {
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
