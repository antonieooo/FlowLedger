# Flow Ledger v0

Flow Ledger v0 is a Kubernetes-aware flow evidence ledger. It records aggregated TCP flow metadata as JSONL `session_summary` and `window_summary` records with Kubernetes identity, service, topology, and model-ready feature context.

It is a flow/session metadata ledger. It is not an IDS, alerting system, machine-learning system, packet capture tool, or TLS decryption tool. It does not collect payloads.

## What v0 Implements

- Mock flow-event ingestion from JSONL.
- Session/window aggregation for `CONNECT`, `ACCEPT`, `STATS`, and `CLOSE` events.
- Kubernetes metadata cache using client-go informers for Pods, Services, EndpointSlices, workload controllers, Jobs, CronJobs, and ServiceAccounts.
- Endpoint identity enrichment for Pod IPs, Service ClusterIPs, EndpointSlice backends, external IPs, and `unknown`.
- Experiment labels from the `flow-ledger-experiment` ConfigMap with last-known-good behavior on read failures.
- JSONL ledger writing with basic size/age rotation.
- Prometheus metrics on `/metrics`.
- A Kubernetes DaemonSet manifest for lifecycle, metadata, ledger, and metrics validation using mock events.
- An experimental Linux eBPF collector for IPv4 TCP lifecycle events from `sock/inet_sock_set_state`.
- Schema `v1alpha2` records with flow lifecycle fields, traffic statistics, Kubernetes identity, service/topology context, TLS/protocol visibility placeholders, and Fast Path / Slow Path review placeholders.

## What v0 Does Not Implement

- No full traffic accounting yet; eBPF bytes and packet counters are currently zero.
- No fast-path detection yet.
- No slow-path review yet.
- No alerting yet.
- No machine learning model yet.
- No TLS decryption.
- No payload capture or storage.
- No TLS ClientHello, SNI, JA3, JA4, HTTP path, HTTP header, or HTTP body capture in the current implementation.
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
- `llvm-strip`

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

The eBPF collector is Linux-only and experimental. It attaches to the `sock/inet_sock_set_state` tracepoint and emits TCP IPv4 lifecycle events into the existing FlowLedger pipeline.

Current capture behavior:

- `newstate == TCP_ESTABLISHED` becomes `CONNECT`.
- `newstate == TCP_CLOSE` becomes `CLOSE`.
- IPv6 is not emitted yet.
- Bytes and packet counters are emitted as `0`.
- No payload is captured.
- TLS is not decrypted.

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
- TLS/protocol metadata: reserved visibility fields such as `protocol_guess`, `is_tls_like`, `sni_hash`, `ja3_or_ja4_hash`, and `visibility_degraded`; no TLS plaintext or payload is stored.
- Kubernetes identity: source and destination Pod, node, workload, ReplicaSet, service account, container metadata when available, image digest when available, and mapping confidence.
- Service/topology/policy context: destination service fields, namespace/workload relation flags, external destination flag, and reserved policy/baseline fields.
- Fast/review placeholders: feature set version, model/review placeholders, reason codes, action suggestion, retention tier, and `payload_collected=false`.

Mapping confidence values are `high`, `medium`, `low`, and `unknown`. Mapping methods include `pod_ip`, `service_cluster_ip`, `endpoint_slice`, `external`, and `unknown`.

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

## Known Limitations

- The default Kubernetes deployment validates lifecycle and metadata plumbing only, not real traffic collection.
- The experimental eBPF collector captures TCP IPv4 connect/close lifecycle only.
- eBPF byte and packet counters are currently zero until send/receive accounting is added.
- Session byte and packet counters treat event counters as cumulative and keep the maximum seen value.
- Owner resolution depends on informer cache freshness and may temporarily emit `BarePod`, `ReplicaSet`, or `unknown` during startup or cache churn.
- Node-origin detection is minimal in v0; hostNetwork Pods are preserved when they can be mapped by Pod IP.
- Ledger rotation is local-only and does not compress, upload, or enforce global retention.

## Next Steps Toward Richer eBPF Collection

- Add `tcp_sendmsg` / `tcp_recvmsg` or equivalent accounting for bytes.
- Add packet counters only if they can be collected without payload capture.
- Add IPv6 event conversion.
- Add netns inode enrichment from `skaddr` or task context.
- Add integration tests or a privileged smoke-test path that is separate from regular unit tests.
- Keep experimental eBPF deployment separate until kernel compatibility is well understood.
