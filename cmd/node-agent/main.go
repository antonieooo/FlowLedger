package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"FlowLedger/pkg/collector"
	"FlowLedger/pkg/experiment"
	"FlowLedger/pkg/identity"
	"FlowLedger/pkg/k8smeta"
	"FlowLedger/pkg/ledger"
	flmetrics "FlowLedger/pkg/metrics"
	"FlowLedger/pkg/sessionizer"

	"github.com/prometheus/client_golang/prometheus"
	promdto "github.com/prometheus/client_model/go"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type config struct {
	nodeName                      string
	clusterID                     string
	agentID                       string
	mode                          string
	mockEventsPath                string
	ledgerPath                    string
	namespace                     string
	experimentConfigMap           string
	sessionTimeout                time.Duration
	windowSize                    time.Duration
	longLivedThreshold            time.Duration
	metricsAddr                   string
	logLevel                      string
	metadataSyncTimeout           time.Duration
	allowUnsyncedMeta             bool
	dropNonLocalSrc               bool
	ledgerMaxBytes                int64
	ledgerMaxAge                  time.Duration
	ledgerRetentionAge            time.Duration
	ledgerRetentionBytes          int64
	ledgerRetentionInterval       time.Duration
	ebpfFlowMapMaxEntries         uint
	ebpfStatsEmitInterval         time.Duration
	ebpfEnableTrafficAccounting   bool
	ebpfEnableTCPBasicMetrics     bool
	ebpfEnablePacketTiming        bool
	ebpfEnablePacketHistogram     bool
	ebpfEnableTLSHandshakeInspect bool
	ebpfEnableHeaderAggregates    bool
	ebpfEnableNetFlowV2Histogram  bool
	ebpfMapStatsInterval          time.Duration
}

func main() {
	cfg := parseFlags()
	if cfg.nodeName == "" {
		if envNode := os.Getenv("NODE_NAME"); envNode != "" {
			cfg.nodeName = envNode
		} else if host, err := os.Hostname(); err == nil {
			cfg.nodeName = host
		}
	}
	if cfg.nodeName == "" {
		log.Fatal("--node-name is required when NODE_NAME and hostname are unavailable")
	}
	if cfg.agentID == "" {
		cfg.agentID = defaultAgentID(cfg.nodeName)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := flmetrics.New()
	metricsServer := m.Serve(cfg.metricsAddr)
	defer shutdownHTTP(metricsServer)

	metaCache := k8smeta.NewCache()
	cgroupResolver := k8smeta.NewCgroupResolver()
	// C10: wire the metrics sink so {hit, miss, retry_hit, retry_miss} are tracked
	// in flowledger_cgroup_resolutions_total{result=...}. This is the headline
	// diagnostic for the identity resolution race condition.
	cgroupResolver.SetMetrics(m)
	go cgroupResolver.Start(ctx)
	kubeClient := maybeKubernetesClient()
	if kubeClient != nil {
		runner := k8smeta.NewInformerRunner(kubeClient, metaCache, func() { m.K8sWatchErrors.Inc() })
		metadataReady := make(chan error, 1)
		go func() {
			if err := runner.Run(ctx, metadataReady); err != nil && ctx.Err() == nil {
				log.Printf("kubernetes informer stopped: %v", err)
				m.K8sWatchErrors.Inc()
			}
		}()
		if err := waitForMetadataSync(ctx, metadataReady, cfg.metadataSyncTimeout, cfg.allowUnsyncedMeta); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Print("kubernetes in-cluster config not available; running with empty metadata cache")
	}

	labelReader := experiment.NewReader(kubeClient, cfg.namespace, cfg.experimentConfigMap)
	labels, err := labelReader.ReadWithStatus(ctx)
	if err != nil {
		m.ExperimentLabelReadErrors.Inc()
		log.Printf("read experiment labels: %v; using last known labels", err)
	}

	writer, err := ledger.NewWriterWithOptions(ledger.WriterOptions{
		Path:              cfg.ledgerPath,
		MaxBytes:          cfg.ledgerMaxBytes,
		MaxAge:            cfg.ledgerMaxAge,
		RetentionAge:      cfg.ledgerRetentionAge,
		RetentionBytes:    cfg.ledgerRetentionBytes,
		RetentionInterval: cfg.ledgerRetentionInterval,
	})
	if err != nil {
		log.Fatalf("open ledger writer: %v", err)
	}
	defer writer.Close()

	var flowCollector collector.Collector
	switch cfg.mode {
	case "mock":
		flowCollector = collector.NewMockCollector(cfg.mockEventsPath)
	case "ebpf":
		flowCollector = collector.NewEBPFCollectorWithOptions(collector.EBPFOptions{
			FlowMapMaxEntries:         uint32(cfg.ebpfFlowMapMaxEntries),
			StatsEmitInterval:         cfg.ebpfStatsEmitInterval,
			EnableTrafficAccounting:   cfg.ebpfEnableTrafficAccounting,
			EnableTCPBasicMetrics:     cfg.ebpfEnableTCPBasicMetrics,
			EnablePacketTiming:        cfg.ebpfEnablePacketTiming,
			EnablePacketHistogram:     cfg.ebpfEnablePacketHistogram,
			EnableTLSHandshakeInspect: cfg.ebpfEnableTLSHandshakeInspect,
			EnableHeaderAggregates:    cfg.ebpfEnableHeaderAggregates,
			EnableNetFlowV2Histogram:  cfg.ebpfEnableNetFlowV2Histogram,
			OnRetransAttach: func(attached bool) {
				if attached {
					m.EBPFRetransAttachTotal.WithLabelValues("success").Inc()
					m.EBPFRetransHookAttached.Set(1)
				} else {
					m.EBPFRetransAttachTotal.WithLabelValues("failure").Inc()
					m.EBPFRetransHookAttached.Set(0)
				}
			},
			MapStatsInterval: cfg.ebpfMapStatsInterval,
			OnMapOccupancy: func(samples []collector.EBPFMapOccupancy) {
				applyMapOccupancyMetrics(m, samples)
			},
			OnMapWalkError: func(mapName string, err error) {
				m.EBPFMapWalkErrors.WithLabelValues(mapName).Inc()
				log.Printf("ebpf map occupancy walk failed map=%s: %v", mapName, err)
			},
		})
	default:
		log.Fatalf("unsupported --mode %q", cfg.mode)
	}
	m.EBPFFlowMapMaxEntries.Set(float64(cfg.ebpfFlowMapMaxEntries))
	if cfg.mode == "ebpf" && cfg.ebpfEnableTrafficAccounting {
		m.EBPFTrafficAccountingEnabled.Set(1)
	}

	events, errs := flowCollector.Run(ctx)
	sessions := sessionizer.NewWithLongLivedThreshold(cfg.nodeName, cfg.sessionTimeout, cfg.windowSize, cfg.longLivedThreshold)
	sessions.SetK8sMeta(metaCache)
	sessions.SetNATAliasMetrics(m)
	resolver := identity.NewResolverWithCgroups(metaCache, cgroupResolver)
	// Freeze source identity per connection generation at event time; record
	// emission then materializes the frozen snapshot instead of re-resolving
	// the source against the current cache state.
	sessions.SetSourceIdentityResolver(resolver)
	recordContext := ledger.BuildContext{
		ClusterID:      cfg.clusterID,
		AgentID:        cfg.agentID,
		CollectionMode: cfg.mode,
		HookSource:     hookSource(cfg.mode),
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	labelTicker := time.NewTicker(30 * time.Second)
	defer labelTicker.Stop()
	// C1: dump TLS handshake + cgroup resolution metrics to stderr every 30s so
	// the user can diagnose ServerHello / JA4S coverage from kubectl logs alone,
	// without deploying Prometheus. This is the primary diagnostic channel for
	// the "ja4s 100% missing" problem documented in PROBLEMS.md.
	diagTicker := time.NewTicker(30 * time.Second)
	defer diagTicker.Stop()

	log.Printf("flow-ledger node-agent started mode=%s node=%s ledger=%s metrics=%s", cfg.mode, cfg.nodeName, cfg.ledgerPath, cfg.metricsAddr)
	log.Printf("ebpf flags: traffic_accounting=%t tcp_metrics=%t packet_timing=%t packet_histogram=%t tls_handshake_inspect=%t header_aggregates=%t netflow_v2_histogram=%t",
		cfg.ebpfEnableTrafficAccounting, cfg.ebpfEnableTCPBasicMetrics,
		cfg.ebpfEnablePacketTiming, cfg.ebpfEnablePacketHistogram,
		cfg.ebpfEnableTLSHandshakeInspect, cfg.ebpfEnableHeaderAggregates,
		cfg.ebpfEnableNetFlowV2Histogram)

	eventsClosed := false
	var lastCgroupErrors uint64
	for {
		select {
		case <-ctx.Done():
			emitSessions(writer, resolver, labels, sessions.CloseAll("timeout", time.Now().UTC()), m, recordContext, cfg.dropNonLocalSrc, metaCache)
			return
		case ev, ok := <-events:
			if !ok {
				if !eventsClosed {
					eventsClosed = true
					emitSessions(writer, resolver, labels, sessions.CloseAll("timeout", time.Now().UTC()), m, recordContext, cfg.dropNonLocalSrc, metaCache)
					log.Print("collector finished; node-agent remains up for metrics until interrupted")
				}
				events = nil
				continue
			}
			if cfg.mode == "ebpf" && ev.EventType == "DROP" {
				applyEBPFDropMetric(m, ev)
				continue
			}
			m.EventsTotal.Inc()
			if cfg.mode == "ebpf" {
				m.EBPFEventsTotal.Inc()
				m.EBPFEventsByType.WithLabelValues(ev.EventType).Inc()
				switch ev.EventType {
				case "CONNECT":
					m.EBPFConnectEventsTotal.Inc()
				case "STATS":
					m.EBPFStatsEventsTotal.Inc()
				case "CLOSE":
					m.EBPFCloseEventsTotal.Inc()
				}
			}
			if ev.EventType == "TLS_HANDSHAKE" {
				if ev.JA4S != "" || ev.ServerHelloSeen || ev.TLSServerParseStatus != "" {
					status := ev.TLSServerParseStatus
					if status == "" {
						status = collector.TLSParseStatusParseError
					}
					if status == collector.TLSParseStatusParsed {
						m.TLSServerHellosParsedTotal.Inc()
					} else {
						m.TLSServerHelloParseErrors.Inc()
					}
					if !sessions.ProcessTLSHandshake(ev) {
						m.TLSServerHelloUnmatchedTotal.Inc()
					}
				} else {
					status := ev.TLSParseStatus
					if status == "" {
						status = collector.TLSParseStatusParseError
					}
					m.TLSHandshakesParsed.WithLabelValues(status).Inc()
					if !sessions.ProcessTLSHandshake(ev) {
						m.TLSUnmatchedTotal.Inc()
					}
				}
				continue
			}
			emitSessions(writer, resolver, labels, sessions.Process(ev), m, recordContext, cfg.dropNonLocalSrc, metaCache)
			m.SessionsActive.Set(float64(sessions.ActiveCount()))
		case err, ok := <-errs:
			if ok && err != nil && err != context.Canceled {
				if cfg.mode == "ebpf" {
					if strings.Contains(err.Error(), "attach") || strings.Contains(err.Error(), "load ebpf") {
						m.EBPFAttachErrors.Inc()
					} else {
						m.EBPFReadErrors.Inc()
					}
				}
				log.Printf("collector error: %v", err)
			}
		case <-ticker.C:
			emitSessions(writer, resolver, labels, sessions.Sweep(time.Now().UTC()), m, recordContext, cfg.dropNonLocalSrc, metaCache)
			m.SessionsActive.Set(float64(sessions.ActiveCount()))
			pods, services := metaCache.Stats()
			m.K8sCachePods.Set(float64(pods))
			m.K8sCacheServices.Set(float64(services))
			m.CgroupMapSize.Set(float64(cgroupResolver.Size()))
			if errs := cgroupResolver.ErrorCount(); errs > lastCgroupErrors {
				m.CgroupResolutionsTotal.WithLabelValues("error").Add(float64(errs - lastCgroupErrors))
				lastCgroupErrors = errs
			}
		case <-labelTicker.C:
			var err error
			labels, err = labelReader.ReadWithStatus(ctx)
			if err != nil {
				m.ExperimentLabelReadErrors.Inc()
				log.Printf("read experiment labels: %v; using last known labels", err)
			}
		case <-diagTicker.C:
			// C1: dump key diagnostic metrics so problems are visible from logs.
			// Read counter values via Prometheus dto.
			logTLSDiagnostics(m)
			logIdentityDiagnostics(m)
		}
	}
}

// logTLSDiagnostics prints ServerHello / JA4S coverage so the user can
// diagnose the "ja4s 100% missing" problem from kubectl logs.
func logTLSDiagnostics(m *flmetrics.Metrics) {
	parsed := counterValue(m.TLSServerHellosParsedTotal)
	errs := counterValue(m.TLSServerHelloParseErrors)
	unmatched := counterValue(m.TLSServerHelloUnmatchedTotal)
	noStats := counterValue(m.TLSServerHelloNoStatsTotal)
	natHits := counterValue(m.TLSServerHelloNATAliasHits)
	natMisses := counterValue(m.TLSServerHelloNATAliasMisses)
	clientParsed := counterVecValue(m.TLSHandshakesParsed, "parsed")
	clientFrag := counterVecValue(m.TLSHandshakesParsed, "fragmented")
	clientErr := counterVecValue(m.TLSHandshakesParsed, "parse_error")
	clientUnmatched := counterValue(m.TLSUnmatchedTotal)
	log.Printf("tls-diag client_hello: parsed=%d fragmented=%d errors=%d unmatched=%d | server_hello: parsed=%d errors=%d unmatched=%d no_stats=%d nat_alias_hits=%d nat_alias_misses=%d",
		clientParsed, clientFrag, clientErr, clientUnmatched,
		parsed, errs, unmatched, noStats, natHits, natMisses)
	if parsed == 0 && natMisses == 0 && unmatched == 0 && noStats == 0 {
		log.Printf("tls-diag WARNING: no server_hello signal at all (bpf hook not firing, cgroup v2 missing, or no inbound TLS to local pods)")
	} else if parsed == 0 && (unmatched > 0 || natMisses > 0) {
		log.Printf("tls-diag WARNING: server_hello events seen (%d unmatched, %d nat_alias_misses) but 0 parsed; check tls_server_parse_status in records",
			unmatched, natMisses)
	}
}

// logIdentityDiagnostics prints cgroup -> pod identity resolution outcomes.
func logIdentityDiagnostics(m *flmetrics.Metrics) {
	hit := counterVecValue(m.CgroupResolutionsTotal, "hit")
	miss := counterVecValue(m.CgroupResolutionsTotal, "miss")
	retryHit := counterVecValue(m.CgroupResolutionsTotal, "retry_hit")
	retryMiss := counterVecValue(m.CgroupResolutionsTotal, "retry_miss")
	errs := counterVecValue(m.CgroupResolutionsTotal, "error")
	total := hit + miss + retryHit + retryMiss
	rate := 0.0
	if total > 0 {
		rate = float64(hit+retryHit) / float64(total)
	}
	log.Printf("identity-diag cgroup_resolutions: hit=%d miss=%d retry_hit=%d retry_miss=%d scan_errors=%d hit_rate=%.3f",
		hit, miss, retryHit, retryMiss, errs, rate)
}

func counterValue(c prometheus.Counter) uint64 {
	if c == nil {
		return 0
	}
	var dto promdto.Metric
	if err := c.Write(&dto); err != nil {
		return 0
	}
	if dto.Counter == nil || dto.Counter.Value == nil {
		return 0
	}
	return uint64(*dto.Counter.Value)
}

func counterVecValue(c *prometheus.CounterVec, label string) uint64 {
	if c == nil {
		return 0
	}
	m, err := c.GetMetricWithLabelValues(label)
	if err != nil {
		return 0
	}
	var dto promdto.Metric
	if err := m.Write(&dto); err != nil {
		return 0
	}
	if dto.Counter == nil || dto.Counter.Value == nil {
		return 0
	}
	return uint64(*dto.Counter.Value)
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.nodeName, "node-name", "", "Kubernetes node name")
	flag.StringVar(&cfg.clusterID, "cluster-id", os.Getenv("FLOWLEDGER_CLUSTER_ID"), "cluster identifier for ledger records")
	flag.StringVar(&cfg.agentID, "agent-id", os.Getenv("FLOWLEDGER_AGENT_ID"), "agent identifier for ledger records")
	flag.StringVar(&cfg.mode, "mode", "mock", "collector mode: mock or ebpf")
	flag.StringVar(&cfg.mockEventsPath, "mock-events-path", "", "JSONL mock flow event path")
	flag.StringVar(&cfg.ledgerPath, "ledger-path", "/var/lib/flow-ledger/flows.jsonl", "output JSONL path")
	flag.StringVar(&cfg.namespace, "namespace", "flow-ledger-system", "namespace for Flow Ledger resources")
	flag.StringVar(&cfg.experimentConfigMap, "experiment-configmap", "flow-ledger-experiment", "experiment label ConfigMap name")
	flag.DurationVar(&cfg.sessionTimeout, "session-timeout", 60*time.Second, "session inactivity timeout")
	flag.DurationVar(&cfg.windowSize, "window-size", 30*time.Second, "long connection summary window size")
	flag.DurationVar(&cfg.longLivedThreshold, "long-lived-threshold", 5*time.Minute, "duration threshold for is_long_lived feature")
	flag.StringVar(&cfg.metricsAddr, "metrics-addr", ":9090", "metrics listen address")
	flag.StringVar(&cfg.logLevel, "log-level", "info", "log level")
	flag.DurationVar(&cfg.metadataSyncTimeout, "metadata-sync-timeout", 30*time.Second, "maximum time to wait for Kubernetes metadata cache sync before processing events")
	flag.BoolVar(&cfg.allowUnsyncedMeta, "allow-unsynced-metadata", false, "continue if Kubernetes metadata cache sync fails or times out")
	flag.BoolVar(&cfg.dropNonLocalSrc, "drop-nonlocal-src", true, "drop flow sessions whose source pod is not on this node. Corrects kind's shared-kernel phantom duplication (global kprobes record every host flow on every node); a no-op on real independent-kernel nodes where the kprobe only sees local flows")
	flag.Int64Var(&cfg.ledgerMaxBytes, "ledger-max-bytes", 100*1024*1024, "rotate ledger when current file reaches this many bytes; 0 disables size rotation")
	flag.DurationVar(&cfg.ledgerMaxAge, "ledger-max-age", 0, "rotate ledger after this duration; 0 disables age rotation")
	flag.DurationVar(&cfg.ledgerRetentionAge, "ledger-retention-age", 24*time.Hour, "delete rotated ledger files older than this; 0 disables age-based retention")
	flag.Int64Var(&cfg.ledgerRetentionBytes, "ledger-retention-bytes", 2*1024*1024*1024, "delete oldest rotated ledger files until total rotated bytes are below this; 0 disables byte-based retention")
	flag.DurationVar(&cfg.ledgerRetentionInterval, "ledger-retention-interval", 5*time.Minute, "how often the retention sweep runs")
	flag.UintVar(&cfg.ebpfFlowMapMaxEntries, "ebpf-flow-map-max-entries", 65536, "maximum entries for the eBPF flow stats map")
	flag.DurationVar(&cfg.ebpfStatsEmitInterval, "ebpf-stats-emit-interval", 5*time.Second, "target eBPF STATS summary emit interval; currently mirrored by a BPF compile-time constant")
	flag.BoolVar(&cfg.ebpfEnableTrafficAccounting, "ebpf-enable-traffic-accounting", true, "attach eBPF tcp_sendmsg/tcp_recvmsg accounting hooks")
	flag.BoolVar(&cfg.ebpfEnableTCPBasicMetrics, "ebpf-enable-tcp-basic-metrics", true, "enable basic eBPF TCP lifecycle counters when supported")
	flag.BoolVar(&cfg.ebpfEnablePacketTiming, "ebpf-enable-packet-timing", true, "attach eBPF cgroup_skb hooks for histogram-based IAT features")
	flag.BoolVar(&cfg.ebpfEnablePacketHistogram, "ebpf-enable-packet-histogram", true, "attach eBPF cgroup_skb hooks for packet size histogram features")
	flag.BoolVar(&cfg.ebpfEnableTLSHandshakeInspect, "ebpf-enable-tls-handshake-inspect", true, "inspect at most the first 1024 bytes of the first TLS ClientHello per flow")
	flag.BoolVar(&cfg.ebpfEnableHeaderAggregates, "ebpf-enable-header-aggregates", true, "collect TCP/IP header aggregates (TTL/flags/window/IP-length envelopes) in BPF; when false the kernel skips the updates and the extra TCP header load")
	flag.BoolVar(&cfg.ebpfEnableNetFlowV2Histogram, "ebpf-enable-netflow-v2-histogram", true, "collect the NetFlow-v2 IP-size histogram in BPF; when false the kernel skips the histogram updates")
	flag.DurationVar(&cfg.ebpfMapStatsInterval, "ebpf-map-stats-interval", 15*time.Second, "period of the low-frequency eBPF map occupancy sampler (recommended 10-30s); 0 uses the default, negative disables sampling")
	flag.Parse()
	return cfg
}

func waitForMetadataSync(ctx context.Context, ready <-chan error, timeout time.Duration, allowUnsynced bool) error {
	var timeoutC <-chan time.Time
	var timer *time.Timer
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		timeoutC = timer.C
		defer timer.Stop()
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-ready:
		if err == nil {
			log.Print("kubernetes metadata cache synced; starting collector")
			return nil
		}
		if allowUnsynced {
			log.Printf("kubernetes metadata cache sync failed; continuing with possibly incomplete metadata: %v", err)
			return nil
		}
		return fmt.Errorf("kubernetes metadata cache sync failed: %w", err)
	case <-timeoutC:
		if allowUnsynced {
			log.Printf("kubernetes metadata cache sync timed out after %s; continuing with possibly incomplete metadata", timeout)
			return nil
		}
		return fmt.Errorf("kubernetes metadata cache sync timed out after %s", timeout)
	}
}

func maybeKubernetesClient() kubernetes.Interface {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Printf("build kubernetes client: %v", err)
		return nil
	}
	return client
}

func emitSessions(w *ledger.Writer, resolver *identity.Resolver, labels experiment.Labels, sessions []sessionizer.FlowSession, m *flmetrics.Metrics, recordContext ledger.BuildContext, dropNonLocalSrc bool, cache *k8smeta.Cache) {
	for _, session := range sessions {
		resolved := resolver.Resolve(session)
		// Phantom filter: under kind, all "nodes" share one host kernel, so this
		// collector's global tcp_sendmsg/recvmsg kprobes record every host flow,
		// not just this node's. Only the flow's home node also has node-scoped
		// cgroup_skb packet data, so non-local records are packet-less duplicates.
		// Keep only flows whose source pod is on this node. On a real
		// independent-kernel node the kprobe never fires for non-local flows, so
		// the source node always equals session.NodeName and this is a no-op.
		if dropNonLocalSrc {
			srcNode := resolved.Src.NodeName
			// resolveSource can return "" for a resolvable pod (e.g. cgroup_id ->
			// pod_uid hit but informer cache miss); fall back to the authoritative
			// cluster-wide pod-by-IP index so a remote reverse-leg phantom is still
			// recognized as non-local. Genuinely unknown source (external,
			// host-network, IP not in cache) stays "" and is kept.
			if srcNode == "" {
				if pod, ok := cache.PodByIP(session.SrcIP); ok {
					srcNode = pod.NodeName
				}
			}
			if srcNode != "" && srcNode != session.NodeName {
				m.PhantomSrcFilteredTotal.Inc()
				continue
			}
		}
		if session.CgroupID != 0 {
			if resolved.Src.Method == "cgroup_id" {
				m.CgroupResolutionsTotal.WithLabelValues("hit").Inc()
			} else {
				m.CgroupResolutionsTotal.WithLabelValues("miss").Inc()
			}
		}
		if resolved.Src.Confidence == "unknown" {
			m.UnknownSrcMappings.Inc()
		}
		if resolved.Dst.Confidence == "unknown" {
			m.UnknownDstMappings.Inc()
		}
		record := ledger.BuildRecordWithContext(session, resolved, labels, recordContext)
		if err := w.Write(record); err != nil {
			m.LedgerWriteErrors.Inc()
			log.Printf("write ledger record %s: %v", session.FlowID, err)
			continue
		}
		m.SessionsEmittedTotal.Inc()
	}
}

func defaultAgentID(nodeName string) string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return nodeName
	}
	if nodeName == "" || nodeName == host {
		return host
	}
	return nodeName + "/" + host
}

func hookSource(mode string) string {
	switch mode {
	case "mock":
		return "mock"
	case "ebpf":
		return "tracepoint:sock:inet_sock_set_state"
	default:
		return "unknown"
	}
}

func applyEBPFDropMetric(m *flmetrics.Metrics, ev collector.FlowEvent) {
	count := float64(ev.DropCount)
	if count == 0 {
		count = 1
	}
	switch ev.DropReason {
	case "map_update_failed":
		m.EBPFMapFullDropsTotal.Add(count)
	case "ringbuf_reserve_failed":
		// A reserve failure IS a flow event lost before userspace: count it
		// both in its dedicated metric and in the lost-events aggregate.
		m.EBPFRingbufReserveFailures.Add(count)
		m.EBPFLostEventsTotal.Add(count)
	case "tls_buffer_reserve_failed":
		m.TLSBufferReserveFailedTotal.Add(count)
		m.EBPFLostEventsTotal.Add(count)
	case "tls_server_hello_no_stats":
		m.TLSServerHelloNoStatsTotal.Add(count)
	case "retrans_flow_miss":
		m.EBPFRetransFlowMissTotal.Add(count)
	case "packet_ep_miss":
		// Per-packet canonical-endpoint miss — NOT a lost event; it must
		// never inflate lost_events_total.
		m.EBPFPacketEpMissTotal.Add(count)
	case "unsupported_family", "recv_arg_missed":
		// Deliberately unmetered: expected high-volume noise (non-IPv4
		// traffic, sendfile-style recv paths).
		return
	default:
		// Anything else (unsupported_ipv6, future BPF-side reasons) is
		// surfaced by raw reason for diagnosis, but is not a measured
		// pre-userspace event loss and stays out of lost_events_total.
		m.EBPFDropsByReason.WithLabelValues(ev.DropReason).Add(count)
	}
}

// applyMapOccupancyMetrics publishes one round of eBPF map occupancy samples.
// Ratio is only exported when max_entries is known (> 0).
func applyMapOccupancyMetrics(m *flmetrics.Metrics, samples []collector.EBPFMapOccupancy) {
	type gaugePair struct {
		entries prometheus.Gauge
		max     prometheus.Gauge
	}
	gauges := map[string]gaugePair{
		"flow_stats": {m.EBPFFlowMapEntries, m.EBPFFlowMapMaxEntries},
		"local_ep":   {m.EBPFLocalEpMapEntries, m.EBPFLocalEpMapMaxEntries},
		"tls_seen":   {m.EBPFTlsSeenMapEntries, m.EBPFTlsSeenMapMaxEntries},
		"recv_args":  {m.EBPFRecvArgsMapEntries, m.EBPFRecvArgsMapMaxEntries},
	}
	for _, sample := range samples {
		pair, ok := gauges[sample.Name]
		if !ok {
			continue
		}
		pair.entries.Set(float64(sample.Entries))
		pair.max.Set(float64(sample.MaxEntries))
		if sample.MaxEntries > 0 {
			m.EBPFMapOccupancyRatio.WithLabelValues(sample.Name).Set(float64(sample.Entries) / float64(sample.MaxEntries))
		}
	}
}

func shutdownHTTP(server *http.Server) {
	if server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "shutdown metrics server: %v\n", err)
	}
}
