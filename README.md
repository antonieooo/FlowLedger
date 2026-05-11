# Flow Ledger v0

Flow Ledger v0 is a Kubernetes node agent prototype that records TCP/TLS connection metadata as JSONL session records with Kubernetes identity context. It is designed to run once per Linux node as a DaemonSet.

## What v0 Does Not Do

- No machine learning model.
- No alerting.
- No TLS decryption.
- No payload capture or storage.
- No assumption that every flow maps to a Pod; `unknown` mapping is normal.

## Components

- `collector`: reads raw flow events from mock JSONL, with an eBPF collector stub kept compile-safe for v0.
- `sessionizer`: aggregates `CONNECT`, `ACCEPT`, `STATS`, and `CLOSE` events into sessions.
- `k8smeta`: watches Pods, Services, EndpointSlices, workload controllers, Jobs, CronJobs, and ServiceAccounts with client-go informers.
- `identity`: maps session endpoints to Pods, Services, EndpointSlice backends, external IPs, or unknown.
- `ledger`: writes JSONL records.
- `experiment`: reads labels from the `flow-ledger-experiment` ConfigMap.
- `metrics`: exposes Prometheus metrics on `/metrics`.

## Run Locally In Mock Mode

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

## Deploy To Kubernetes

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

## JSONL Record Fields

Each line is a `session_summary` or `window_summary`.

- Flow timing: `flow_id`, `node_name`, `start_time`, `end_time`, `duration_ms`
- Network tuple: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`
- Counters: `bytes_out`, `bytes_in`, `packets_out`, `packets_in`
- Source identity: `src_namespace`, `src_pod_name`, `src_pod_uid`, `src_workload_kind`, `src_workload_name`, `src_workload_uid`, `src_service_account`, `src_revision`
- Destination identity: `dst_namespace`, `dst_pod_name`, `dst_pod_uid`, `dst_workload_kind`, `dst_workload_name`, `dst_workload_uid`, `dst_service_account`, `dst_service_name`, `dst_external`
- Mapping quality: `src_mapping_confidence`, `dst_mapping_confidence`, `mapping_method`
- Experiment labels: `experiment_id`, `scenario_label`, `scenario_phase`, `attack_enabled`, `load_level`
- Windows: `rollout_window`, `pod_restart_window`

Mapping confidence values are `high`, `medium`, `low`, and `unknown`. Mapping methods include `pod_ip`, `service_cluster_ip`, `endpoint_slice`, `external_ip`, and `unknown`.

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

## Current Limitations

- The eBPF collector is a v0 stub; use mock mode for local validation.
- Session byte and packet counters treat event counters as cumulative and keep the maximum seen value.
- Owner resolution depends on informer cache freshness and may temporarily emit `BarePod`, `ReplicaSet`, or `unknown` during startup.
- Node-origin detection is minimal in v0; hostNetwork Pods are preserved when they can be mapped by Pod IP.
