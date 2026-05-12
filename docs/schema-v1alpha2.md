# FlowLedger Schema v1alpha2

FlowLedger is a Kubernetes-aware flow evidence ledger. It records aggregated flow/session evidence for later Fast Path feature checks and Slow Path review workflows.

It is not an IDS, an ML inference service, a packet capture system, a TLS decryptor, or a payload recorder.

## Record Types

FlowLedger writes JSONL records. Each line is either:

- `session_summary`: a closed or timed-out connection summary.
- `window_summary`: an intermediate summary for a longer active connection.

## Field Groups

### Record metadata

- `schema_version`: currently `v1alpha2`.
- `record_type`: `session_summary` or `window_summary`.
- `cluster_id`: optional flag/env supplied cluster identifier.
- `node_name`: Kubernetes node name.
- `agent_id`: explicit agent id, or a node/hostname-derived id.
- `collection_mode`: `mock` or `ebpf`.
- `hook_source`: `mock` or `tracepoint:sock:inet_sock_set_state`.
- `start_time`, `end_time`: wall-clock RFC3339Nano timestamps.
- `experiment_id`, `scenario_label`: experiment labels from ConfigMap or local fallback.

### Flow lifecycle

- `flow_id`, `window_id`
- `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`
- `direction`: `ingress`, `egress`, `local`, or `unknown`.
- `ip_family`: `ipv4`, `ipv6`, or `unknown`.
- `conn_start_time`, `conn_end_time`, `duration_ms`
- `tcp_state`, `close_reason`
- `is_long_lived`

`flow_id` is stable for the observed 5-tuple plus connection start time. `window_id` increments for `window_summary` records and is `0` on `session_summary`.

### Traffic statistics

- Basic counters: `bytes_out`, `bytes_in`, `packets_out`, `packets_in`, `bytes_total`, `packets_total`
- Directional features: `byte_ratio_out_in`, `packet_ratio_out_in`, `direction_changes`
- Packet size features: `pkt_size_min`, `pkt_size_max`, `pkt_size_mean`, `pkt_size_p50`, `pkt_size_p95`, `pkt_size_histogram`
- Timing features: `iat_p50`, `iat_p95`, `iat_std`, `idle_gap_count`, `burst_count`
- Rates: `byte_rate`, `packet_rate`
- TCP behavior: `syn_count`, `fin_count`, `rst_count`, `retrans_count`, `rtt_estimate_us`
- Availability flags: `traffic_accounting_available`, `packet_timing_available`, `tcp_metrics_available`

Unavailable numeric estimates are serialized as `null` where the type is an estimate, or `0` for counters. With the current eBPF traffic-accounting hooks, packet counters are syscall/message-level approximations from `tcp_sendmsg` and `tcp_recvmsg`, not exact wire packet counts. The packet size histogram uses fixed buckets:

```text
0-63, 64-127, 128-255, 256-511, 512-1023, 1024-1500, >1500
```

### TLS and protocol metadata

- `protocol_guess`
- `is_tls_like`
- `tls_version`
- `sni_hash`
- `alpn`
- `ja3_or_ja4_hash`
- `tls_record_size_histogram`
- `handshake_seen`
- `sni_visibility`
- `visibility_degraded`
- `visibility_degraded_reason`

Current implementation does not parse TLS ClientHello, decrypt TLS, store SNI plaintext, store certificates, or save HTTP path/header/body/payload. TLS fields are schema placeholders except for weak port-based `protocol_guess` and `is_tls_like`.

### Kubernetes identity

Source and destination endpoints include:

- Namespace, Pod name, Pod UID, node
- Container name, container ID, cgroup ID
- Service account
- Workload kind/name/UID
- ReplicaSet, pod template hash, revision
- Image digest
- Mapping confidence

Field prefixes are `src_` and `dst_`. Missing container ID, cgroup ID, or image digest values are empty or `0`; they are not fabricated.

### Service, topology, and policy context

- `dst_service_name`, `dst_service_uid`, `dst_service_namespace`
- `dst_service_port_name`, `dst_app_protocol`
- `dst_is_service_backend`, `dst_external`
- `same_namespace`, `same_workload`, `cross_namespace`
- `expected_edge`
- `network_policy_allowed`, `policy_confidence`
- `rollout_window`, `hpa_scaling_window`, `node_visibility_degraded`

Service context is derived from Service and EndpointSlice cache data when available. `expected_edge` and NetworkPolicy fields are reserved and currently default to `unknown`; FlowLedger does not claim full CNI policy evaluation.

### Fast Path and review placeholders

- `feature_set_version`: currently `flowledger-fast-features-v0`.
- `fast_model_version`: currently `none`.
- `fast_score`, `fast_threshold`
- `reason_codes`
- `review_required`
- `review_id`, `review_score`, `review_verdict`
- `action_suggestion`
- `retention_tier`
- `payload_collected`

No ML model runs today. `reason_codes` are simple explainable flags such as `EXTERNAL_DESTINATION`, `LONG_LIVED`, `UNKNOWN_IDENTITY`, `CROSS_NAMESPACE`, `ROLLOUT_WINDOW`, and `VISIBILITY_DEGRADED`. `payload_collected` is always `false`.

## Currently Real vs Reserved

Currently real:

- Mock and eBPF lifecycle events.
- eBPF IPv4 TCP `CONNECT` and `CLOSE` from `sock/inet_sock_set_state`.
- eBPF cumulative `bytes_sent` / `bytes_recv` when traffic accounting is enabled.
- eBPF approximate `packets_sent` / `packets_recv` when traffic accounting is enabled.
- eBPF `STATS` summary events emitted at the configured kernel interval.
- Session/window aggregation.
- Mock-provided bytes, packets, packet sizes, IATs, retransmits, and RTT estimates.
- Kubernetes Pod IP, Service ClusterIP, EndpointSlice backend, owner/workload, and external IP mapping.
- JSONL rotation and Prometheus counters.

Still unavailable:

- True wire-level packet counts from eBPF when only `tcp_sendmsg` / `tcp_recvmsg` hooks are enabled.
- Packet timing from eBPF.
- TLS ClientHello/SNI/JA3/JA4 parsing.
- NetworkPolicy allow/deny evaluation.
- Global expected-edge baselines.
- HPA scaling window detection.
- ML scores and Slow Path verdicts.

## eBPF Collector Limits

- IPv4 TCP lifecycle only.
- Current eBPF byte counters are cumulative send/receive byte counts when traffic accounting is enabled.
- Current eBPF packet counters are approximate syscall/message counts, not exact wire packets.
- No payload capture.
- No TLS decryption.
- PID and CgroupID at the current tracepoint are best-effort attribution signals.

## Example

```json
{
  "schema_version": "v1alpha2",
  "record_type": "session_summary",
  "cluster_id": "kind-thesis",
  "node_name": "thesis-worker",
  "agent_id": "thesis-worker/flow-ledger-node-agent-ebpf-x",
  "collection_mode": "ebpf",
  "hook_source": "tracepoint:sock:inet_sock_set_state",
  "start_time": "2026-05-11T22:14:24.668892614Z",
  "end_time": "2026-05-11T22:14:24.701614555Z",
  "experiment_id": "unknown",
  "scenario_label": "unlabeled",
  "flow_id": "8bebaa9d2d75aa10ab858c99f3077b4ed7f0644e",
  "window_id": 0,
  "src_ip": "10.244.1.166",
  "src_port": 35626,
  "dst_ip": "104.20.23.154",
  "dst_port": 80,
  "protocol": "tcp",
  "direction": "egress",
  "ip_family": "ipv4",
  "conn_start_time": "2026-05-11T22:14:24.668892614Z",
  "conn_end_time": "2026-05-11T22:14:24.701614555Z",
  "duration_ms": 32,
  "tcp_state": "unknown",
  "close_reason": "unknown",
  "is_long_lived": false,
  "bytes_out": 0,
  "bytes_in": 0,
  "packets_out": 0,
  "packets_in": 0,
  "bytes_total": 0,
  "packets_total": 0,
  "traffic_accounting_available": false,
  "packet_timing_available": false,
  "tcp_metrics_available": false,
  "protocol_guess": "http",
  "is_tls_like": false,
  "handshake_seen": false,
  "sni_visibility": "unknown",
  "visibility_degraded": true,
  "visibility_degraded_reason": "traffic_accounting_unavailable",
  "src_namespace": "default",
  "src_pod_name": "flowledger-curl-test",
  "src_service_account": "default",
  "src_workload_kind": "BarePod",
  "src_mapping_confidence": "high",
  "dst_external": true,
  "dst_mapping_confidence": "low",
  "mapping_method": "external",
  "expected_edge": "unknown",
  "network_policy_allowed": "unknown",
  "feature_set_version": "flowledger-fast-features-v0",
  "fast_model_version": "none",
  "reason_codes": ["EXTERNAL_DESTINATION", "VISIBILITY_DEGRADED"],
  "review_required": true,
  "review_verdict": "unknown",
  "action_suggestion": "observe",
  "payload_collected": false
}
```
