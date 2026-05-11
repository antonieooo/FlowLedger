package metrics

import (
	"errors"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	EventsTotal               prometheus.Counter
	SessionsActive            prometheus.Gauge
	SessionsEmittedTotal      prometheus.Counter
	UnknownSrcMappings        prometheus.Counter
	UnknownDstMappings        prometheus.Counter
	LedgerWriteErrors         prometheus.Counter
	K8sCachePods              prometheus.Gauge
	K8sCacheServices          prometheus.Gauge
	K8sWatchErrors            prometheus.Counter
	ExperimentLabelReadErrors prometheus.Counter
	EBPFEventsTotal           prometheus.Counter
	EBPFReadErrors            prometheus.Counter
	EBPFAttachErrors          prometheus.Counter
	EBPFEventsByType          *prometheus.CounterVec
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
