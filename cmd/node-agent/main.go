package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
		go func() {
			if err := runner.Run(ctx); err != nil && ctx.Err() == nil {
				log.Printf("kubernetes informer stopped: %v", err)
				m.K8sWatchErrors.Inc()
			}
		}()
	} else {
		log.Print("kubernetes in-cluster config not available; running with empty metadata cache")
	}

	labelReader := experiment.NewReader(kubeClient, cfg.namespace, cfg.experimentConfigMap)
	labels := labelReader.Read(ctx)

	writer, err := ledger.NewWriter(cfg.ledgerPath)
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
			emitSessions(writer, resolver, labels, sessions.Process(ev), m)
			m.SessionsActive.Set(float64(sessions.ActiveCount()))
		case err, ok := <-errs:
			if ok && err != nil && err != context.Canceled {
				log.Printf("collector error: %v", err)
			}
		case <-ticker.C:
			emitSessions(writer, resolver, labels, sessions.Sweep(time.Now().UTC()), m)
			m.SessionsActive.Set(float64(sessions.ActiveCount()))
			pods, services := metaCache.Stats()
			m.K8sCachePods.Set(float64(pods))
			m.K8sCacheServices.Set(float64(services))
		case <-labelTicker.C:
			labels = labelReader.Read(ctx)
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
	flag.Parse()
	return cfg
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
