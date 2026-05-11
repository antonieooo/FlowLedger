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
