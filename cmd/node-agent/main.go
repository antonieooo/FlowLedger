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

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type config struct {
	nodeName            string
	mode                string
	mockEventsPath      string
	ledgerPath          string
	namespace           string
	experimentConfigMap string
	sessionTimeout      time.Duration
	windowSize          time.Duration
	metricsAddr         string
	logLevel            string
	metadataSyncTimeout time.Duration
	allowUnsyncedMeta   bool
	ledgerMaxBytes      int64
	ledgerMaxAge        time.Duration
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := flmetrics.New()
	metricsServer := m.Serve(cfg.metricsAddr)
	defer shutdownHTTP(metricsServer)

	metaCache := k8smeta.NewCache()
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
		Path:     cfg.ledgerPath,
		MaxBytes: cfg.ledgerMaxBytes,
		MaxAge:   cfg.ledgerMaxAge,
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
		flowCollector = collector.NewEBPFCollector()
	default:
		log.Fatalf("unsupported --mode %q", cfg.mode)
	}

	events, errs := flowCollector.Run(ctx)
	sessions := sessionizer.New(cfg.nodeName, cfg.sessionTimeout, cfg.windowSize)
	resolver := identity.NewResolver(metaCache)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	labelTicker := time.NewTicker(30 * time.Second)
	defer labelTicker.Stop()

	log.Printf("flow-ledger node-agent started mode=%s node=%s ledger=%s metrics=%s", cfg.mode, cfg.nodeName, cfg.ledgerPath, cfg.metricsAddr)

	eventsClosed := false
	for {
		select {
		case <-ctx.Done():
			emitSessions(writer, resolver, labels, sessions.CloseAll("timeout", time.Now().UTC()), m)
			return
		case ev, ok := <-events:
			if !ok {
				if !eventsClosed {
					eventsClosed = true
					emitSessions(writer, resolver, labels, sessions.CloseAll("timeout", time.Now().UTC()), m)
					log.Print("collector finished; node-agent remains up for metrics until interrupted")
				}
				events = nil
				continue
			}
			m.EventsTotal.Inc()
			if cfg.mode == "ebpf" {
				m.EBPFEventsTotal.Inc()
				m.EBPFEventsByType.WithLabelValues(ev.EventType).Inc()
			}
			emitSessions(writer, resolver, labels, sessions.Process(ev), m)
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
			emitSessions(writer, resolver, labels, sessions.Sweep(time.Now().UTC()), m)
			m.SessionsActive.Set(float64(sessions.ActiveCount()))
			pods, services := metaCache.Stats()
			m.K8sCachePods.Set(float64(pods))
			m.K8sCacheServices.Set(float64(services))
		case <-labelTicker.C:
			var err error
			labels, err = labelReader.ReadWithStatus(ctx)
			if err != nil {
				m.ExperimentLabelReadErrors.Inc()
				log.Printf("read experiment labels: %v; using last known labels", err)
			}
		}
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.nodeName, "node-name", "", "Kubernetes node name")
	flag.StringVar(&cfg.mode, "mode", "mock", "collector mode: mock or ebpf")
	flag.StringVar(&cfg.mockEventsPath, "mock-events-path", "", "JSONL mock flow event path")
	flag.StringVar(&cfg.ledgerPath, "ledger-path", "/var/lib/flow-ledger/flows.jsonl", "output JSONL path")
	flag.StringVar(&cfg.namespace, "namespace", "flow-ledger-system", "namespace for Flow Ledger resources")
	flag.StringVar(&cfg.experimentConfigMap, "experiment-configmap", "flow-ledger-experiment", "experiment label ConfigMap name")
	flag.DurationVar(&cfg.sessionTimeout, "session-timeout", 60*time.Second, "session inactivity timeout")
	flag.DurationVar(&cfg.windowSize, "window-size", 30*time.Second, "long connection summary window size")
	flag.StringVar(&cfg.metricsAddr, "metrics-addr", ":9090", "metrics listen address")
	flag.StringVar(&cfg.logLevel, "log-level", "info", "log level")
	flag.DurationVar(&cfg.metadataSyncTimeout, "metadata-sync-timeout", 30*time.Second, "maximum time to wait for Kubernetes metadata cache sync before processing events")
	flag.BoolVar(&cfg.allowUnsyncedMeta, "allow-unsynced-metadata", false, "continue if Kubernetes metadata cache sync fails or times out")
	flag.Int64Var(&cfg.ledgerMaxBytes, "ledger-max-bytes", 100*1024*1024, "rotate ledger when current file reaches this many bytes; 0 disables size rotation")
	flag.DurationVar(&cfg.ledgerMaxAge, "ledger-max-age", 0, "rotate ledger after this duration; 0 disables age rotation")
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

func emitSessions(w *ledger.Writer, resolver *identity.Resolver, labels experiment.Labels, sessions []sessionizer.FlowSession, m *flmetrics.Metrics) {
	for _, session := range sessions {
		resolved := resolver.Resolve(session)
		if resolved.Src.Confidence == "unknown" {
			m.UnknownSrcMappings.Inc()
		}
		if resolved.Dst.Confidence == "unknown" {
			m.UnknownDstMappings.Inc()
		}
		record := ledger.BuildRecord(session, resolved, labels)
		if err := w.Write(record); err != nil {
			m.LedgerWriteErrors.Inc()
			log.Printf("write ledger record %s: %v", session.FlowID, err)
			continue
		}
		m.SessionsEmittedTotal.Inc()
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
