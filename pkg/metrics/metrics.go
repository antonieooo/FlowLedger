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
	PhantomSrcFilteredTotal      prometheus.Counter
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
	EBPFLocalEpMapEntries        prometheus.Gauge
	EBPFLocalEpMapMaxEntries     prometheus.Gauge
	EBPFTlsSeenMapEntries        prometheus.Gauge
	EBPFTlsSeenMapMaxEntries     prometheus.Gauge
	EBPFRecvArgsMapEntries       prometheus.Gauge
	EBPFRecvArgsMapMaxEntries    prometheus.Gauge
	EBPFMapOccupancyRatio        *prometheus.GaugeVec
	EBPFMapWalkErrors            *prometheus.CounterVec
	EBPFMapFullDropsTotal        prometheus.Counter
	EBPFRingbufReserveFailures   prometheus.Counter
	EBPFLostEventsTotal          prometheus.Counter
	EBPFPacketEpMissTotal        prometheus.Counter
	EBPFDropsByReason            *prometheus.CounterVec
	EBPFStatsEventsTotal         prometheus.Counter
	EBPFConnectEventsTotal       prometheus.Counter
	EBPFCloseEventsTotal         prometheus.Counter
	EBPFTrafficAccountingEnabled prometheus.Gauge
	TLSHandshakesParsed          *prometheus.CounterVec
	TLSUnmatchedTotal            prometheus.Counter
	TLSBufferReserveFailedTotal  prometheus.Counter
	TLSServerHelloNoStatsTotal   prometheus.Counter
	TLSServerHellosParsedTotal   prometheus.Counter
	TLSServerHelloUnmatchedTotal prometheus.Counter
	TLSServerHelloParseErrors    prometheus.Counter
	TLSServerHelloNATAliasHits   prometheus.Counter
	TLSServerHelloNATAliasMisses prometheus.Counter
	CgroupResolutionsTotal       *prometheus.CounterVec
	CgroupMapSize                prometheus.Gauge
	EBPFRetransAttachTotal       *prometheus.CounterVec
	EBPFRetransHookAttached      prometheus.Gauge
	EBPFRetransFlowMissTotal     prometheus.Counter
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
		PhantomSrcFilteredTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_phantom_src_filtered_total",
			Help: "Total flow sessions dropped because the source pod is not local to this node (kind shared-kernel phantom from global kprobes; a no-op on real independent-kernel nodes).",
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
			Help: "Current flow_stats_map entries, sampled by the low-frequency map occupancy walker (default every 15s); an under-count is possible while entries churn during a walk.",
		}),
		EBPFFlowMapMaxEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_flow_map_max_entries",
			Help: "Configured maximum flow_stats_map entries.",
		}),
		EBPFLocalEpMapEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_local_ep_map_entries",
			Help: "Current local_ep_to_key entries (DNAT-invariant local-endpoint index), sampled by the map occupancy walker.",
		}),
		EBPFLocalEpMapMaxEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_local_ep_map_max_entries",
			Help: "Configured maximum local_ep_to_key entries.",
		}),
		EBPFTlsSeenMapEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_tls_seen_map_entries",
			Help: "Current tls_server_hello_seen_map entries (ServerHello dedup), sampled by the map occupancy walker.",
		}),
		EBPFTlsSeenMapMaxEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_tls_seen_map_max_entries",
			Help: "Configured maximum tls_server_hello_seen_map entries.",
		}),
		EBPFRecvArgsMapEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_recv_args_map_entries",
			Help: "Current recv_args_map entries (in-flight tcp_recvmsg args), sampled by the map occupancy walker.",
		}),
		EBPFRecvArgsMapMaxEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_recv_args_map_max_entries",
			Help: "Configured maximum recv_args_map entries.",
		}),
		EBPFMapOccupancyRatio: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_map_occupancy_ratio",
			Help: "Sampled entries / max_entries per eBPF map (flow_stats | local_ep | tls_seen | recv_args); sustained values near 1.0 mean LRU eviction pressure.",
		}, []string{"map"}),
		EBPFMapWalkErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowledger_ebpf_map_walk_errors_total",
			Help: "Total failed occupancy walks per eBPF map; the collector keeps running and retries at the next sample interval.",
		}, []string{"map"}),
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
			Help: "Events genuinely lost before reaching userspace: the sum of flow-event and TLS ring buffer reserve failures — the only pre-userspace losses this implementation can measure. Per-packet/protocol drop reasons (packet_ep_miss, retrans_flow_miss, unsupported_*) are deliberately NOT included; see their dedicated counters.",
		}),
		EBPFPacketEpMissTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_packet_ep_miss_total",
			Help: "cgroup_skb packets whose canonical local_ep_to_key lookup missed (no flow_stats entry for the endpoint). A per-PACKET counter for flows outside socket-hook visibility — not a lost event and not ring buffer loss.",
		}),
		EBPFDropsByReason: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowledger_ebpf_drops_by_reason_total",
			Help: "Kernel-side drop counters that have no dedicated metric, by raw reason (e.g. unsupported_ipv6, or a reason added in BPF before userspace learned about it). Diagnostic only — not part of lost_events_total.",
		}, []string{"reason"}),
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
		TLSServerHelloNoStatsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_tls_server_hello_no_stats_total",
			Help: "Total TLS ServerHello ingress packets seen without a matching eBPF flow_stats entry.",
		}),
		TLSServerHellosParsedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_tls_server_hellos_parsed_total",
			Help: "Total TLS ServerHello inspection events parsed successfully.",
		}),
		TLSServerHelloUnmatchedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_tls_server_hello_unmatched_total",
			Help: "Total TLS ServerHello events that could not be joined to an active flow session.",
		}),
		TLSServerHelloParseErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_tls_server_hello_parse_errors_total",
			Help: "Total TLS ServerHello inspection events that did not parse successfully.",
		}),
		TLSServerHelloNATAliasHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_tls_server_hello_nat_alias_hits_total",
			Help: "Total TLS ServerHello events joined to an active session through EndpointSlice Service aliasing.",
		}),
		TLSServerHelloNATAliasMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_tls_server_hello_nat_alias_misses_total",
			Help: "Total TLS ServerHello alias fallback attempts that did not find an active Service session.",
		}),
		CgroupResolutionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowledger_cgroup_resolutions_total",
			Help: "Total cgroup_id to pod identity resolution attempts by result.",
		}, []string{"result"}),
		CgroupMapSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_cgroup_map_size",
			Help: "Current number of cgroup_id entries in the local cgroup resolver map.",
		}),
		EBPFRetransAttachTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowledger_ebpf_retrans_attach_total",
			Help: "tcp/tcp_retransmit_skb tracepoint attach outcomes by status (success|failure).",
		}, []string{"status"}),
		EBPFRetransHookAttached: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowledger_ebpf_retrans_hook_attached",
			Help: "Whether the tcp/tcp_retransmit_skb tracepoint is currently attached (1) or not (0); when 0, local_retrans_available is false on every record.",
		}),
		EBPFRetransFlowMissTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowledger_ebpf_retrans_flow_miss_total",
			Help: "Total retransmit tracepoint hits whose socket flow key had no flow_stats entry (evicted or raced with CLOSE); these retransmissions are counted nowhere.",
		}),
	}
	prometheus.MustRegister(
		m.EventsTotal,
		m.SessionsActive,
		m.SessionsEmittedTotal,
		m.PhantomSrcFilteredTotal,
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
		m.EBPFLocalEpMapEntries,
		m.EBPFLocalEpMapMaxEntries,
		m.EBPFTlsSeenMapEntries,
		m.EBPFTlsSeenMapMaxEntries,
		m.EBPFRecvArgsMapEntries,
		m.EBPFRecvArgsMapMaxEntries,
		m.EBPFMapOccupancyRatio,
		m.EBPFMapWalkErrors,
		m.EBPFMapFullDropsTotal,
		m.EBPFRingbufReserveFailures,
		m.EBPFLostEventsTotal,
		m.EBPFPacketEpMissTotal,
		m.EBPFDropsByReason,
		m.EBPFStatsEventsTotal,
		m.EBPFConnectEventsTotal,
		m.EBPFCloseEventsTotal,
		m.EBPFTrafficAccountingEnabled,
		m.TLSHandshakesParsed,
		m.TLSUnmatchedTotal,
		m.TLSBufferReserveFailedTotal,
		m.TLSServerHelloNoStatsTotal,
		m.TLSServerHellosParsedTotal,
		m.TLSServerHelloUnmatchedTotal,
		m.TLSServerHelloParseErrors,
		m.TLSServerHelloNATAliasHits,
		m.TLSServerHelloNATAliasMisses,
		m.CgroupResolutionsTotal,
		m.CgroupMapSize,
		m.EBPFRetransAttachTotal,
		m.EBPFRetransHookAttached,
		m.EBPFRetransFlowMissTotal,
	)
	return m
}

func (m *Metrics) IncTLSServerHelloNATAliasHit() {
	m.TLSServerHelloNATAliasHits.Inc()
}

func (m *Metrics) IncTLSServerHelloNATAliasMiss() {
	m.TLSServerHelloNATAliasMisses.Inc()
}

// IncCgroupResolution implements the k8smeta.CgroupMetrics interface for C10
// diagnostics. Labels: hit | miss | retry_hit | retry_miss.
func (m *Metrics) IncCgroupResolution(result string) {
	if m == nil || m.CgroupResolutionsTotal == nil {
		return
	}
	m.CgroupResolutionsTotal.WithLabelValues(result).Inc()
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
