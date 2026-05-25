package features

import (
	"reflect"
	"testing"
	"time"

	"FlowLedger/pkg/collector"
)

func TestAccumulatorSnapshotStats(t *testing.T) {
	var acc Accumulator
	acc.AddEvent(collector.FlowEvent{
		EventType:        "STATS",
		BytesSent:        300,
		BytesRecv:        100,
		PacketsSent:      3,
		PacketsRecv:      1,
		PacketSizes:      []uint64{60, 100, 1400, 1600},
		IATMicros:        []uint64{100, 10_000, 2_000_000},
		DirectionChanges: 2,
		RetransCount:     1,
		RTTEstimateUS:    500,
	})

	s := acc.Snapshot(300, 100, 3, 1, 2*time.Second, 5*time.Minute)
	if s.BytesTotal != 400 || s.PacketsTotal != 4 {
		t.Fatalf("unexpected totals: %#v", s)
	}
	if s.ByteRatioOutIn == nil || *s.ByteRatioOutIn != 3 {
		t.Fatalf("unexpected byte ratio: %#v", s.ByteRatioOutIn)
	}
	if s.PktSizeHistogram["0-63"] != 1 || s.PktSizeHistogram[">1500"] != 1 {
		t.Fatalf("unexpected histogram: %#v", s.PktSizeHistogram)
	}
	if s.PktSizeP50 == nil || *s.PktSizeP50 != 750 {
		t.Fatalf("unexpected p50: %#v", s.PktSizeP50)
	}
	if s.IdleGapCount != 1 || s.BurstCount != 1 || s.RetransCount != 1 || s.RTTEstimateUS == nil || *s.RTTEstimateUS != 500 {
		t.Fatalf("unexpected timing/tcp features: %#v", s)
	}
}

func TestAccumulatorHistogramEstimatedPercentiles(t *testing.T) {
	minSize := uint64(64)
	maxSize := uint64(255)
	var acc Accumulator
	acc.AddEvent(collector.FlowEvent{
		EventType: "STATS",
		PacketSizeHistogram: map[string]uint64{
			"64-127":  10,
			"128-255": 10,
		},
		IATHistogram: map[string]uint64{
			"100-1000":   4,
			"1000-10000": 6,
		},
		PktSizeMin:                 &minSize,
		PktSizeMax:                 &maxSize,
		IdleGapCount:               1,
		BurstCount:                 2,
		PacketTimingAvailable:      true,
		RealPacketsSent:            12,
		RealPacketsRecv:            8,
		TCPMetricsAvailable:        false,
		TrafficAccountingAvailable: true,
	})

	s := acc.Snapshot(1000, 2000, 3, 4, time.Second, 5*time.Minute)
	if s.PktSizeP50 == nil || *s.PktSizeP50 < 126 || *s.PktSizeP50 > 128 {
		t.Fatalf("histogram packet p50 = %#v, want estimate near 127", s.PktSizeP50)
	}
	if s.PktSizeP95 == nil || *s.PktSizeP95 < 241 || *s.PktSizeP95 > 244 {
		t.Fatalf("histogram packet p95 = %#v, want estimate near 242", s.PktSizeP95)
	}
	if s.IATP50 == nil || *s.IATP50 < 2499 || *s.IATP50 > 2501 {
		t.Fatalf("histogram iat p50 = %#v, want estimate near 2500", s.IATP50)
	}
	// L18/B: histogram-derived IATStd is now populated using bucket-midpoint
	// approximation. Histogram has 4 samples at midpoint 550 + 6 at midpoint
	// 5500: mean = 3520, stddev ≈ 2425.
	if s.IATStd == nil {
		t.Fatalf("histogram-only IATStd = nil, want approximate value")
	}
	if *s.IATStd < 2420 || *s.IATStd > 2430 {
		t.Fatalf("histogram-only IATStd = %f, want ~2425", *s.IATStd)
	}
	if s.IATMean == nil || *s.IATMean < 3515 || *s.IATMean > 3525 {
		t.Fatalf("histogram-only IATMean = %#v, want ~3520", s.IATMean)
	}
	if s.PktSizeMin == nil || *s.PktSizeMin != 64 || s.PktSizeMax == nil || *s.PktSizeMax != 255 {
		t.Fatalf("unexpected min/max: %#v %#v", s.PktSizeMin, s.PktSizeMax)
	}
	if s.IdleGapCount != 1 || s.BurstCount != 2 {
		t.Fatalf("unexpected burst/idle counts: %#v", s)
	}
}

func TestAccumulatorIATStatsUseHistogramPathWhenMixed(t *testing.T) {
	var acc Accumulator
	acc.AddEvent(collector.FlowEvent{
		EventType: "STATS",
		IATMicros: []uint64{1, 2, 3},
		IATHistogram: map[string]uint64{
			"1000-10000": 10,
		},
		PacketTimingAvailable: true,
	})

	s := acc.Snapshot(0, 0, 0, 0, time.Second, 5*time.Minute)
	// L18/B: when histogram has data, IATStd uses the histogram-derived
	// approximation on the MERGED histogram (input histogram + raw-sample
	// bucketing). Raw samples [1,2,3] map to bucket "<100" (midpoint 49.5),
	// input histogram contributes "1000-10000":10 (midpoint 5500). Merged:
	// 3 samples at 49.5 + 10 at 5500 → mean ≈ 4242, stddev ≈ 2296.
	if s.IATStd == nil {
		t.Fatalf("mixed raw+histogram IATStd = nil, want approximate value")
	}
	if *s.IATStd < 2290 || *s.IATStd > 2300 {
		t.Fatalf("mixed raw+histogram IATStd = %f, want ~2296", *s.IATStd)
	}
	if s.IATP50 == nil || *s.IATP50 < 4149 || *s.IATP50 > 4151 {
		t.Fatalf("mixed raw+histogram IATP50 = %#v, want histogram estimate near 4150", s.IATP50)
	}
}

// TestEstimateHistogramStddev_KnownDistribution verifies the bucket-midpoint
// approximation against a hand-computed reference. With buckets [0-63]=50%
// and [128-255]=50%, midpoints are 31.5 and 191.5; the population stddev
// of those two equal-weight samples is |191.5-31.5|/2 = 80.
func TestEstimateHistogramStddev_KnownDistribution(t *testing.T) {
	hist := map[string]uint64{
		"0-63":    100,
		"128-255": 100,
	}
	std := estimateHistogramStddev(hist, packetSizeBucketBounds())
	if std == nil {
		t.Fatalf("got nil std, want ~80")
	}
	if *std < 79.5 || *std > 80.5 {
		t.Fatalf("std = %f, want approximately 80", *std)
	}
}

// TestEstimateHistogramStddev_Empty returns nil for an empty histogram.
func TestEstimateHistogramStddev_Empty(t *testing.T) {
	std := estimateHistogramStddev(map[string]uint64{}, packetSizeBucketBounds())
	if std != nil {
		t.Fatalf("empty histogram std = %v, want nil", std)
	}
}

func TestReasonCodes(t *testing.T) {
	got := ReasonCodes(ReasonContext{
		CrossNamespace:      true,
		ExternalDestination: true,
		LongLived:           true,
		UnknownIdentity:     true,
		VisibilityDegraded:  true,
	})
	want := []string{"CROSS_NAMESPACE", "EXTERNAL_DESTINATION", "LONG_LIVED", "UNKNOWN_IDENTITY", "VISIBILITY_DEGRADED"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReasonCodes() = %v, want %v", got, want)
	}
}

func TestSafeRatioUnavailable(t *testing.T) {
	if got := SafeRatio(10, 0); got != nil {
		t.Fatalf("SafeRatio denominator zero = %#v, want nil", got)
	}
}
