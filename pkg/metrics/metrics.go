package metrics

import (
	"errors"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	EventsTotal                  prometheus.Counter
	SessionsActive               prometheus.Gauge
	SessionsEmittedTotal         prometheus.Counter
	UnknownSrcMappings           prometheus.Counter
	UnknownDstMappings           prometheus.Counter
	LedgerWriteErrors            prometheus.Counter
	K8sCachePods                 prometheus.Gauge
	K8sCacheServices             prometheus.Gauge
	K8sWatchErrors               prometheus.Counter
	ExperimentLabelReadErrors    prometheus.Counter
	EBPFEventsTotal              prometheus.Counter
	EBPFReadErrors               prometheus.Counter
	EBPFAttachErrors             prometheus.Counter
	EBPFEventsByType             *prometheus.CounterVec
	EBPFFlowMapEntries           prometheus.Gauge
	EBPFFlowMapMaxEntries        prometheus.Gauge
	EBPFMapFullDropsTotal        prometheus.Counter
	EBPFRingbufReserveFailures   prometheus.Counter
	EBPFLostEventsTotal          prometheus.Counter
	EBPFStatsEventsTotal         prometheus.Counter
	EBPFConnectEventsTotal       prometheus.Counter
	EBPFCloseEventsTotal         prometheus.Counter
	EBPFTrafficAccountingEnabled prometheus.Gauge
	TLSHandshakesParsed          *prometheus.CounterVec
	TLSUnmatchedTotal            prometheus.Counter
	TLSBufferReserveFailedTotal  prometheus.Counter
	CgroupResolutionsTotal       *prometheus.CounterVec
	CgroupMapSize                prometheus.Gauge
}

func New() *Metrics {
	m := &Metrics{
		EventsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_events_total",
			Help: "Total flow events collected.",
		}),
		SessionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_sessions_active",
			Help: "Current active flow sessions.",
		}),
		SessionsEmittedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_sessions_emitted_total",
			Help: "Total emitted flow sessions.",
		}),
		UnknownSrcMappings: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_unknown_src_mapping_total",
			Help: "Total flow sessions with unknown source identity mapping.",
		}),
		UnknownDstMappings: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_unknown_dst_mapping_total",
			Help: "Total flow sessions with unknown destination identity mapping.",
		}),
		LedgerWriteErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ledger_write_errors_total",
			Help: "Total JSONL ledger write errors.",
		}),
		K8sCachePods: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_k8s_cache_pods",
			Help: "Pods currently held in the Kubernetes metadata cache.",
		}),
		K8sCacheServices: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_k8s_cache_services",
			Help: "Services currently held in the Kubernetes metadata cache.",
		}),
		K8sWatchErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_k8s_watch_errors_total",
			Help: "Total Kubernetes watch/cache errors.",
		}),
		ExperimentLabelReadErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_experiment_label_read_errors_total",
			Help: "Total experiment label ConfigMap read errors.",
		}),
		EBPFEventsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_events_total",
			Help: "Total eBPF flow events read from the kernel.",
		}),
		EBPFReadErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_read_errors_total",
			Help: "Total eBPF ring buffer read or decode errors.",
		}),
		EBPFAttachErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_attach_errors_total",
			Help: "Total eBPF program load or attach errors.",
		}),
		EBPFEventsByType: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowledger_ebpf_events_by_type_total",
			Help: "Total eBPF flow events read from the kernel by event type.",
		}, []string{"event_type"}),
		EBPFFlowMapEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_flow_map_entries",
			Help: "Current eBPF flow map entries when exported by the collector.",
		}),
		EBPFFlowMapMaxEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_flow_map_max_entries",
			Help: "Configured maximum eBPF flow map entries.",
		}),
		EBPFMapFullDropsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_map_full_drops_total",
			Help: "Total eBPF flow/drop map update failures.",
		}),
		EBPFRingbufReserveFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_ringbuf_reserve_failures_total",
			Help: "Total eBPF ring buffer reserve failures reported by the kernel program.",
		}),
		EBPFLostEventsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_lost_events_total",
			Help: "Total eBPF events dropped before userspace processing.",
		}),
		EBPFStatsEventsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_stats_events_total",
			Help: "Total eBPF STATS summary events.",
		}),
		EBPFConnectEventsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_connect_events_total",
			Help: "Total eBPF CONNECT summary events.",
		}),
		EBPFCloseEventsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_close_events_total",
			Help: "Total eBPF CLOSE summary events.",
		}),
		EBPFTrafficAccountingEnabled: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_traffic_accounting_enabled",
			Help: "Whether eBPF send/recv traffic accounting hooks are enabled.",
		}),
		TLSHandshakesParsed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowledger_tls_handshakes_parsed_total",
			Help: "Total TLS ClientHello inspection events by parse status.",
		}, []string{"status"}),
		TLSUnmatchedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_tls_unmatched_total",
			Help: "Total TLS handshake events that could not be joined to an active flow session.",
		}),
		TLSBufferReserveFailedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_tls_buffer_reserve_failed_total",
			Help: "Total TLS handshake ring buffer reserve failures reported by the kernel program.",
		}),
		CgroupResolutionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowledger_cgroup_resolutions_total",
			Help: "Total cgroup_id to pod identity resolution attempts by result.",
		}, []string{"result"}),
		CgroupMapSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_cgroup_map_size",
			Help: "Current number of cgroup_id entries in the local cgroup resolver map.",
		}),
	}
	prometheus.MustRegister(
		m.EventsTotal,
		m.SessionsActive,
		m.SessionsEmittedTotal,
		m.UnknownSrcMappings,
		m.UnknownDstMappings,
		m.LedgerWriteErrors,
		m.K8sCachePods,
		m.K8sCacheServices,
		m.K8sWatchErrors,
		m.ExperimentLabelReadErrors,
		m.EBPFEventsTotal,
		m.EBPFReadErrors,
		m.EBPFAttachErrors,
		m.EBPFEventsByType,
		m.EBPFFlowMapEntries,
		m.EBPFFlowMapMaxEntries,
		m.EBPFMapFullDropsTotal,
		m.EBPFRingbufReserveFailures,
		m.EBPFLostEventsTotal,
		m.EBPFStatsEventsTotal,
		m.EBPFConnectEventsTotal,
		m.EBPFCloseEventsTotal,
		m.EBPFTrafficAccountingEnabled,
		m.TLSHandshakesParsed,
		m.TLSUnmatchedTotal,
		m.TLSBufferReserveFailedTotal,
		m.CgroupResolutionsTotal,
		m.CgroupMapSize,
	)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}

func (m *Metrics) Serve(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	server := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server stopped: %v", err)
		}
	}()
	return server
}
