package main

import (
	"testing"

	"FlowLedger/pkg/collector"
	flmetrics "FlowLedger/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// newUnregisteredMetrics builds a Metrics with fresh, unregistered collectors
// covering every field the drop-routing and occupancy paths touch, so tests
// can assert exact values without fighting the global registry.
func newUnregisteredMetrics() *flmetrics.Metrics {
	counter := func(name string) prometheus.Counter {
		return prometheus.NewCounter(prometheus.CounterOpts{Name: name})
	}
	gauge := func(name string) prometheus.Gauge {
		return prometheus.NewGauge(prometheus.GaugeOpts{Name: name})
	}
	return &flmetrics.Metrics{
		EBPFMapFullDropsTotal:       counter("t_map_full_drops"),
		EBPFRingbufReserveFailures:  counter("t_ringbuf_reserve_failures"),
		EBPFLostEventsTotal:         counter("t_lost_events"),
		TLSBufferReserveFailedTotal: counter("t_tls_buffer_reserve_failed"),
		TLSServerHelloNoStatsTotal:  counter("t_tls_server_hello_no_stats"),
		EBPFRetransFlowMissTotal:    counter("t_retrans_flow_miss"),
		EBPFPacketEpMissTotal:       counter("t_packet_ep_miss"),
		EBPFDropsByReason: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "t_drops_by_reason"}, []string{"reason"}),
		EBPFFlowMapEntries:        gauge("t_flow_entries"),
		EBPFFlowMapMaxEntries:     gauge("t_flow_max"),
		EBPFLocalEpMapEntries:     gauge("t_local_ep_entries"),
		EBPFLocalEpMapMaxEntries:  gauge("t_local_ep_max"),
		EBPFTlsSeenMapEntries:     gauge("t_tls_seen_entries"),
		EBPFTlsSeenMapMaxEntries:  gauge("t_tls_seen_max"),
		EBPFRecvArgsMapEntries:    gauge("t_recv_args_entries"),
		EBPFRecvArgsMapMaxEntries: gauge("t_recv_args_max"),
		EBPFMapOccupancyRatio: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "t_occupancy_ratio"}, []string{"map"}),
	}
}

// Every kernel DROP reason must land in exactly its expected metric —
// packet_ep_miss and retrans_flow_miss must never inflate lost_events_total,
// and lost_events_total may only aggregate the two ring buffer reserve
// failures (the only true pre-userspace event losses).
func TestApplyEBPFDropMetricRoutingExhaustive(t *testing.T) {
	const count = 3
	// Mirror of the reason list produced by readDropCounterDeltas (BPF drop
	// counter indices 0-8) plus an unknown future reason.
	cases := []struct {
		reason string
		want   map[string]float64 // metric name -> expected value; all others must stay 0
	}{
		{"map_update_failed", map[string]float64{"map_full_drops": count}},
		{"ringbuf_reserve_failed", map[string]float64{"ringbuf_reserve_failures": count, "lost_events": count}},
		{"unsupported_family", map[string]float64{}},
		{"recv_arg_missed", map[string]float64{}},
		{"tls_buffer_reserve_failed", map[string]float64{"tls_buffer_reserve_failed": count, "lost_events": count}},
		{"tls_server_hello_no_stats", map[string]float64{"tls_server_hello_no_stats": count}},
		{"unsupported_ipv6", map[string]float64{"drops_by_reason": count}},
		{"packet_ep_miss", map[string]float64{"packet_ep_miss": count}},
		{"retrans_flow_miss", map[string]float64{"retrans_flow_miss": count}},
		{"some_future_reason", map[string]float64{"drops_by_reason": count}},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			m := newUnregisteredMetrics()
			applyEBPFDropMetric(m, collector.FlowEvent{
				EventType:  "DROP",
				DropReason: tc.reason,
				DropCount:  count,
			})
			got := map[string]float64{
				"map_full_drops":            testutil.ToFloat64(m.EBPFMapFullDropsTotal),
				"ringbuf_reserve_failures":  testutil.ToFloat64(m.EBPFRingbufReserveFailures),
				"lost_events":               testutil.ToFloat64(m.EBPFLostEventsTotal),
				"tls_buffer_reserve_failed": testutil.ToFloat64(m.TLSBufferReserveFailedTotal),
				"tls_server_hello_no_stats": testutil.ToFloat64(m.TLSServerHelloNoStatsTotal),
				"retrans_flow_miss":         testutil.ToFloat64(m.EBPFRetransFlowMissTotal),
				"packet_ep_miss":            testutil.ToFloat64(m.EBPFPacketEpMissTotal),
				"drops_by_reason":           testutil.ToFloat64(m.EBPFDropsByReason.WithLabelValues(tc.reason)),
			}
			for name, value := range got {
				want := tc.want[name]
				if value != want {
					t.Errorf("reason %q: metric %s = %v, want %v", tc.reason, name, value, want)
				}
			}
		})
	}
}

// A DROP event with zero count (defensive path) still counts as one.
func TestApplyEBPFDropMetricZeroCountDefaultsToOne(t *testing.T) {
	m := newUnregisteredMetrics()
	applyEBPFDropMetric(m, collector.FlowEvent{EventType: "DROP", DropReason: "packet_ep_miss"})
	if got := testutil.ToFloat64(m.EBPFPacketEpMissTotal); got != 1 {
		t.Fatalf("packet_ep_miss = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.EBPFLostEventsTotal); got != 0 {
		t.Fatalf("lost_events = %v, want 0", got)
	}
}

func TestApplyMapOccupancyMetrics(t *testing.T) {
	m := newUnregisteredMetrics()
	applyMapOccupancyMetrics(m, []collector.EBPFMapOccupancy{
		{Name: "flow_stats", Entries: 16384, MaxEntries: 65536},
		{Name: "local_ep", Entries: 100, MaxEntries: 65536},
		{Name: "tls_seen", Entries: 0, MaxEntries: 65536},
		{Name: "recv_args", Entries: 8, MaxEntries: 16384},
		{Name: "not_a_known_map", Entries: 9, MaxEntries: 9},
	})
	checks := []struct {
		name  string
		gauge prometheus.Gauge
		want  float64
	}{
		{"flow entries", m.EBPFFlowMapEntries, 16384},
		{"flow max", m.EBPFFlowMapMaxEntries, 65536},
		{"local_ep entries", m.EBPFLocalEpMapEntries, 100},
		{"local_ep max", m.EBPFLocalEpMapMaxEntries, 65536},
		{"tls_seen entries", m.EBPFTlsSeenMapEntries, 0},
		{"tls_seen max", m.EBPFTlsSeenMapMaxEntries, 65536},
		{"recv_args entries", m.EBPFRecvArgsMapEntries, 8},
		{"recv_args max", m.EBPFRecvArgsMapMaxEntries, 16384},
	}
	for _, c := range checks {
		if got := testutil.ToFloat64(c.gauge); got != c.want {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
	if got := testutil.ToFloat64(m.EBPFMapOccupancyRatio.WithLabelValues("flow_stats")); got != 0.25 {
		t.Errorf("flow_stats occupancy ratio = %v, want 0.25", got)
	}
	if got := testutil.ToFloat64(m.EBPFMapOccupancyRatio.WithLabelValues("recv_args")); got != 8.0/16384.0 {
		t.Errorf("recv_args occupancy ratio = %v", got)
	}
}

// max_entries == 0 must not export a ratio (no NaN/Inf gauges).
func TestApplyMapOccupancyMetricsZeroMaxNoRatio(t *testing.T) {
	m := newUnregisteredMetrics()
	applyMapOccupancyMetrics(m, []collector.EBPFMapOccupancy{
		{Name: "flow_stats", Entries: 5, MaxEntries: 0},
	})
	if n := testutil.CollectAndCount(m.EBPFMapOccupancyRatio); n != 0 {
		t.Fatalf("occupancy ratio series = %d, want 0 when max_entries is 0", n)
	}
}
