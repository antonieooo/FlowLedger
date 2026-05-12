# Flow Ledger v0

Flow Ledger v0 is a Kubernetes-aware flow evidence ledger. It records aggregated TCP flow metadata as JSONL `session_summary` and `window_summary` records with Kubernetes identity, service, topology, and model-ready feature context.

It is a flow/session metadata ledger. It is not an IDS, alerting system, machine-learning system, packet capture tool, or TLS decryption tool. It does not store payloads.

## What v0 Implements

- Mock flow-event ingestion from JSONL.
- Session/window aggregation for `CONNECT`, `ACCEPT`, `STATS`, and `CLOSE` events.
- Kubernetes metadata cache using client-go informers for Pods, Services, EndpointSlices, workload controllers, Jobs, CronJobs, and ServiceAccounts.
- Endpoint identity enrichment for Linux cgroup IDs, Pod IPs, Service ClusterIPs, EndpointSlice backends, external IPs, and `unknown`.
- Experiment labels from the `flow-ledger-experiment` ConfigMap with last-known-good behavior on read failures.
- JSONL ledger writing with basic size/age rotation.
- Prometheus metrics on `/metrics`.
- A Kubernetes DaemonSet manifest for lifecycle, metadata, ledger, and metrics validation using mock events.
- An experimental Linux eBPF collector for IPv4 TCP lifecycle events plus lightweight send/recv traffic accounting.
- Schema `v1alpha2` records with flow lifecycle fields, traffic statistics, Kubernetes identity, service/topology context, TLS/protocol visibility placeholders, and Fast Path / Slow Path review placeholders.

## What v0 Does Not Implement

- The primary `packets_out` / `packets_in` fields remain syscall/message-level approximations from `tcp_sendmsg` and `tcp_recvmsg`; packet-level `cgroup_skb` hooks provide histogram-derived packet features without changing those field semantics.
- No fast-path detection yet.
- No slow-path review yet.
- No alerting yet.
- No machine learning model yet.
- No TLS decryption.
- No payload storage.
- TLS ClientHello inspection is limited to the first 1024 bytes of the first egress TLS handshake record per flow. FlowLedger extracts JA4, TLS version, ALPN, and a hash of SNI only.
- No TLS decryption.
- No plaintext SNI storage.
- No certificate capture.
- No fragmented ClientHello reassembly.
- No HTTP path, HTTP header, or HTTP body capture in the current implementation.
- No ML inference or Slow Path reviewer verdicts yet; model/review fields are placeholders with simple reason codes.
- No production retention, compression, or upload pipeline for ledger files.
- No assumption that every flow maps to a Pod; `unknown` mapping is normal.

## Components

- `collector`: reads raw flow events from mock JSONL or, on Linux, from an experimental eBPF tracepoint collector.
- `sessionizer`: aggregates flow events into session/window summaries.
- `k8smeta`: watches Kubernetes metadata and maintains local lookup caches.
- `identity`: maps session endpoints to Kubernetes or external identities.
- `ledger`: writes JSONL records and rotates the active ledger file.
- `experiment`: reads scenario labels from a ConfigMap.
- `metrics`: exposes Prometheus metrics.

## Run Local Mock Mode

```bash
go run ./cmd/node-agent \
  --mode mock \
  --mock-events-path ./testdata/mock_flow_events.jsonl \
  --ledger-path ./flows.jsonl \
  --node-name local-test
```

The agent keeps running after the mock file is consumed so `/metrics` stays available. Stop it with `Ctrl-C`.

Check output:

```bash
cat ./flows.jsonl
curl http://localhost:9090/metrics
```

Without an in-cluster Kubernetes config, metadata cache startup is skipped and identity fields resolve to `unknown`.

Useful ledger flags:

```bash
--ledger-max-bytes=104857600
--ledger-max-age=0s
```

`--ledger-max-bytes=0` disables size-based rotation. `--ledger-max-age=0s` disables age-based rotation.

## Build eBPF Bindings

The generated eBPF bindings are checked in. Regenerate them after changing `bpf/flow_events.bpf.c`:

```bash
go generate ./...
```

Generation requires:

- Go with tool support for `go tool bpf2go`
- `clang`

The checked-in generator uses `bpf2go -no-strip`, so `llvm-strip` is not required for the default development workflow.

The project pins `github.com/cilium/ebpf/cmd/bpf2go` in `go.mod` with a `tool` directive.

## Deploy To Kubernetes For Lifecycle Validation

The default manifests do not collect real node traffic. They run the node-agent as a DaemonSet in mock mode with mock events mounted from `flow-ledger-mock-events`. This validates image startup, RBAC, informer sync, metadata enrichment behavior, JSONL writing, and metrics exposure.

Build and publish an image for your cluster:

```bash
docker build -t flow-ledger:v0 .
```

For a remote cluster, push the image to your registry and update `deploy/daemonset.yaml`:

```yaml
image: your-registry/flow-ledger:v0
```

Apply:

```bash
kubectl apply -f deploy/
```

Expected resources:

- Namespace: `flow-ledger-system`
- ServiceAccount, ClusterRole, ClusterRoleBinding
- ConfigMap: `flow-ledger-experiment`
- ConfigMap: `flow-ledger-mock-events`
- DaemonSet: `flow-ledger-node-agent`

The DaemonSet mounts `/var/lib/flow-ledger` from each node. View records on a node:

```bash
sudo tail -f /var/lib/flow-ledger/flows.jsonl
```

View metrics:

```bash
kubectl -n flow-ledger-system port-forward ds/flow-ledger-node-agent 9090:9090
curl http://localhost:9090/metrics
```

## Experimental eBPF Collector

The eBPF collector is Linux-only and experimental. It attaches to the `sock/inet_sock_set_state` tracepoint for lifecycle events, `tcp_sendmsg` / `tcp_recvmsg` kprobe hooks for lightweight traffic accounting, and optional `cgroup_skb/ingress` plus `cgroup_skb/egress` hooks for packet-level histograms and first-ClientHello inspection.

Current capture behavior:

- `newstate == TCP_ESTABLISHED` becomes `CONNECT`.
- `newstate == TCP_CLOSE` becomes `CLOSE`.
- IPv6 is not emitted yet.
- eBPF maps aggregate cumulative `bytes_sent`, `bytes_recv`, `packets_sent`, and `packets_recv` per flow.
- `cgroup_skb` packet hooks update packet size histograms, IAT histograms, min/max packet size, idle/burst counters, and real packet counters in the same flow map.
- Events include cgroup ID and best-effort network namespace identity. Sock-based hooks read `net.ns.inum`; cgroup_skb uses the kernel netns cookie when direct socket context is unavailable.
- `STATS` summary events are emitted at a fixed interval instead of per packet/message.
- Packet counters are approximate syscall/message counters, not exact wire packet counts.
- Histogram-derived percentiles are estimates; raw packet length and raw IAT sequences are not stored.
- The first egress TLS ClientHello can be copied to a separate ring buffer for userspace parsing. The capture limit is 1024 bytes and the flow is marked inspected after one attempt.
- SNI plaintext is never written to JSONL; only the first 16 hex characters of SHA-256 over the lowercased SNI are recorded.
- No payload is written to the ledger; bounded ClientHello bytes are transiently copied to userspace only for metadata extraction.
- TLS is not decrypted.

Traffic accounting flags:

```bash
--ebpf-flow-map-max-entries=65536
--ebpf-stats-emit-interval=5s
--ebpf-enable-traffic-accounting=true
--ebpf-enable-tcp-basic-metrics=true
--ebpf-enable-packet-timing=true
--ebpf-enable-packet-histogram=true
--ebpf-enable-tls-handshake-inspect=true
```

`--ebpf-flow-map-max-entries` is applied to the eBPF LRU flow map before load. The current STATS interval is mirrored by a BPF compile-time constant; change `EBPF_EMIT_INTERVAL_NS` in `bpf/flow_events.bpf.c` and run `go generate ./...` if you need a different kernel-side interval. Packet timing, packet histogram, and TLS ClientHello inspection attach `cgroup_skb` programs on cgroup v2 systems. Experimental deployments default them on; production operators can opt out with `--ebpf-enable-packet-timing=false --ebpf-enable-packet-histogram=false --ebpf-enable-tls-handshake-inspect=false`.

Local Linux test, usually requiring root or equivalent BPF permissions:

```bash
sudo go run ./cmd/node-agent \
  --mode ebpf \
  --ledger-path ./flows.jsonl \
  --node-name local-ebpf-test
```

In another shell, create TCP activity with `curl`, `nc`, or `wget`, then inspect `flows.jsonl` and `/metrics`.

Kubernetes experimental deployment:

```bash
kubectl apply -f deploy/
kubectl apply -f deploy/experimental/daemonset-ebpf.yaml
```

The experimental DaemonSet uses privileged/capability access and host mounts for BPF/tracing. Do not apply it as part of the default mock validation path.

## Metadata Sync

When running in Kubernetes, the agent waits for informer cache sync before starting the collector. The default timeout is 30 seconds:

```bash
--metadata-sync-timeout=30s
--allow-unsynced-metadata=false
```

If sync times out and `--allow-unsynced-metadata=false`, the agent exits instead of writing early records with incomplete metadata. Local runs without in-cluster config skip this gate and use an empty metadata cache.

## JSONL Record Fields

Each line is a `session_summary` or `window_summary` using schema `v1alpha2`. See [docs/schema-v1alpha2.md](docs/schema-v1alpha2.md) for field semantics, availability, and an example record.

- Record metadata: `schema_version`, `cluster_id`, `node_name`, `agent_id`, `collection_mode`, `hook_source`, experiment labels.
- Flow lifecycle: `flow_id`, `window_id`, 5-tuple, direction, IP family, connection timing, TCP state, close reason, long-lived flag.
- Traffic statistics: bytes, packets, totals, ratios, rates, packet size histogram, IAT estimates, TCP counters, and availability flags.
- TLS/protocol metadata: `protocol_guess`, `is_tls_like`, ClientHello-derived `tls_version`, `sni_hash`, `alpn`, `ja4`, `tls_parse_status`, and visibility flags; no TLS plaintext or payload is stored.
- Kubernetes identity: source and destination Pod, node, workload, ReplicaSet, service account, container metadata when available, image digest when available, cgroup ID, and mapping confidence.
- Service/topology/policy context: destination service fields, namespace/workload relation flags, external destination flag, and reserved policy/baseline fields.
- Data quality and sampling metadata: `sampling_applied=false`, `sampling_rate=1.0`, `sampling_reason=none`, `histogram_truncated=false`, `iat_overflow=false`, and `tls_parse_status`.
- Fast/review placeholders: feature set version, model/review placeholders, reason codes, action suggestion, retention tier, and `payload_collected=false`.

Mapping confidence values are `high`, `medium`, `low`, and `unknown`. Mapping methods include `cgroup_id`, `pod_ip`, `service_cluster_ip`, `endpoint_slice`, `external`, and `unknown`.

`rollout_window`, `hpa_scaling_window`, `expected_edge`, and `network_policy_allowed` are reserved or conservative in v0. `pod_restart_window` is based on low-confidence pod mapping windows.

## Metrics

- `flowledger_events_total`
- `flowledger_sessions_active`
- `flowledger_sessions_emitted_total`
- `flowledger_unknown_src_mapping_total`
- `flowledger_unknown_dst_mapping_total`
- `flowledger_ledger_write_errors_total`
- `flowledger_k8s_cache_pods`
- `flowledger_k8s_cache_services`
- `flowledger_k8s_watch_errors_total`
- `flowledger_experiment_label_read_errors_total`
- `flowledger_ebpf_events_total`
- `flowledger_ebpf_read_errors_total`
- `flowledger_ebpf_attach_errors_total`
- `flowledger_ebpf_events_by_type_total`
- `flowledger_ebpf_stats_events_total`
- `flowledger_ebpf_connect_events_total`
- `flowledger_ebpf_close_events_total`
- `flowledger_ebpf_ringbuf_reserve_failures_total`
- `flowledger_ebpf_map_full_drops_total`
- `flowledger_ebpf_lost_events_total`
- `flowledger_ebpf_traffic_accounting_enabled`
- `flowledger_tls_handshakes_parsed_total`
- `flowledger_tls_unmatched_total`
- `flowledger_tls_buffer_reserve_failed_total`
- `flowledger_cgroup_resolutions_total`
- `flowledger_cgroup_map_size`

## Known Limitations

- The default Kubernetes deployment validates lifecycle and metadata plumbing only, not real traffic collection.
- The experimental eBPF collector captures TCP IPv4 lifecycle, lightweight send/receive counters, and cgroup_skb histogram-based packet features on cgroup v2 systems.
- Histogram-based packet/IAT percentiles are estimates with bucket-width-bounded error; FlowLedger does not retain raw packet length or raw IAT sequences.
- ClientHello inspection is best-effort and bounded to the first 1024 bytes of the first egress TLS handshake record. Fragmented ClientHellos are marked `fragmented` and are not reassembled.
- Session byte and packet counters treat event counters as cumulative and keep the maximum seen value.
- Owner resolution depends on informer cache freshness and may temporarily emit `BarePod`, `ReplicaSet`, or `unknown` during startup or cache churn.
- Local source attribution prefers cgroup ID to Pod UID mapping when Kubernetes cgroup paths are visible. Missing cgroup v2/kubepods paths degrade gracefully to Pod IP mapping.
- Host-network Pod identity can still be ambiguous; netns identity is used as a confidence signal where available.
- Ledger rotation is local-only and does not compress, upload, or enforce global retention.

## Next Steps Toward Richer eBPF Collection

- Add TC/SKB hooks if strict wire packet count semantics are needed in top-level packet counters.
- Add richer packet timing summaries without exporting raw packet sequences.
- Add IPv6 event conversion.
- Add integration tests or a privileged smoke-test path that is separate from regular unit tests.
- Keep experimental eBPF deployment separate until kernel compatibility is well understood.
