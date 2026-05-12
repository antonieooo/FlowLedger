# eBPF Flow Counter Design

FlowLedger's eBPF collector is a lightweight flow counter, not a packet capture system. It aggregates TCP lifecycle and traffic counters in kernel maps and sends only summary events to userspace.

## Why Not Per-Packet Reporting

Per-packet ring buffer events would create high userspace overhead, large JSONL volume, and unnecessary payload-adjacent risk. FlowLedger only needs model-ready flow evidence, so the eBPF program keeps cumulative counters in maps and emits:

- one `CONNECT` event when a TCP flow reaches `TCP_ESTABLISHED`
- periodic `STATS` events when counters changed and the emit interval has elapsed
- one `CLOSE` event with final counters

No TLS plaintext, HTTP path, HTTP headers, or HTTP body is captured. TLS ClientHello inspection is limited to the first 1024 bytes of the first egress handshake record per flow and is sent to userspace only for metadata parsing.

## Maps

`flow_stats_map`

- Type: `BPF_MAP_TYPE_LRU_HASH`
- Key: `struct flow_key`
- Value: `struct flow_stats`
- Default max entries: `65536`
- Purpose: cumulative bytes/packets, packet/IAT histograms, and lightweight TCP lifecycle counters per flow

`recv_args_map`

- Type: `BPF_MAP_TYPE_HASH`
- Key: `pid_tgid`
- Value: `struct flow_key`
- Default max entries: `16384`
- Purpose: carries the flow key from `tcp_recvmsg` entry to return

`drop_counters`

- Type: `BPF_MAP_TYPE_ARRAY`
- Purpose: best-effort counters for map update failures, ring buffer reserve failures, unsupported family drops, and missed recv args

`events`

- Type: `BPF_MAP_TYPE_RINGBUF`
- Purpose: summary events only

`tls_handshake_events`

- Type: `BPF_MAP_TYPE_RINGBUF`
- Purpose: bounded first-ClientHello capture for userspace JA4/SNI-hash/ALPN parsing
- Max bytes copied per flow: `1024`

## Hooks

`tracepoint/sock/inet_sock_set_state`

- Creates flow entries on `TCP_ESTABLISHED`
- Emits `CONNECT`
- Emits `CLOSE` and deletes flow entries on `TCP_CLOSE`

`kprobe/tcp_sendmsg`

- Adds `size` to `bytes_sent`
- Increments `packets_sent` by 1 as a syscall/message approximation
- May emit `STATS` if the flow's emit interval elapsed

`kprobe/tcp_recvmsg` and `kretprobe/tcp_recvmsg`

- Entry stores the flow key in `recv_args_map`
- Return adds positive return bytes to `bytes_recv`
- Increments `packets_recv` by 1 as a syscall/message approximation
- May emit `STATS` if the flow's emit interval elapsed

`cgroup_skb/ingress` and `cgroup_skb/egress`

- Parse IPv4 TCP headers only.
- Look up the existing lifecycle-owned flow entry; they do not create flow entries.
- Update packet size histogram buckets, IAT histogram buckets, packet min/max, idle gaps, bursts, and real packet counters.
- May emit `STATS` if the flow's emit interval elapsed.
- Never export per-packet records; TLS payload inspection is limited to the first ClientHello bytes described below.
- On egress, optionally inspect the first payload bytes once per flow. If they look like TLS ClientHello, copy up to 1024 bytes to `tls_handshake_events` and set `handshake_inspected`.

## Snapshot Semantics

All eBPF traffic counters are cumulative snapshots for the flow:

- `bytes_sent`
- `bytes_recv`
- `packets_sent`
- `packets_recv`
- packet size histogram buckets
- IAT histogram buckets
- packet min/max, idle gaps, bursts, and real packet counts

They are not deltas. The Go sessionizer keeps the maximum counter value seen for the session, so `CONNECT`, `STATS`, and `CLOSE` can arrive as cumulative observations without double counting.

## Performance Protection

- No per-packet ring buffer output.
- LRU flow map bounds memory use.
- Periodic STATS emission is rate-limited by `EBPF_EMIT_INTERVAL_NS`.
- `--ebpf-flow-map-max-entries` can adjust the flow map size before object load.
- `--ebpf-enable-traffic-accounting=false` can run lifecycle-only collection.
- `--ebpf-enable-packet-histogram=false --ebpf-enable-packet-timing=false` skips `cgroup_skb` packet hooks entirely.
- `--ebpf-enable-tls-handshake-inspect=false` disables ClientHello events through the BPF config map.
- Packet histograms and IAT histograms are kept as fixed-size bucket counters only.
- Each flow is inspected at most once for TLS ClientHello.

## Known Limitations

- IPv4 TCP only.
- Top-level `packets_sent` / `packets_recv` are syscall/message approximations and retain their existing semantics.
- cgroup_skb real packet counters are currently used to drive histogram-derived packet features, not to rename or replace the existing top-level packet fields.
- `--ebpf-stats-emit-interval` is currently mirrored by the BPF compile-time constant `EBPF_EMIT_INTERVAL_NS`; change the constant and run `go generate ./...` for a different kernel-side interval.
- Packet size and IAT percentiles are estimated from histograms. The error is bounded by the bucket width except for open-ended tail buckets.
- `iat_std` remains unavailable from eBPF histogram-only data.
- cgroup_skb attach requires cgroup v2; on cgroup v1 hosts the agent logs a warning and continues without packet histogram/timing hooks.
- No RTT estimate or retransmit detection from eBPF yet.
- No HTTP, gRPC, generic payload parsing, or post-handshake TLS parsing.
- TLS inspection handles ClientHello only. It does not decrypt TLS, store plaintext SNI, parse ServerHello, capture certificates, or reassemble fragmented ClientHellos.
- CgroupID is best-effort attribution context and is not a stable Kubernetes identity by itself.

## Future Work

- TC/SKB hooks if top-level packet counters need strict wire-level semantics.
- Additional compact timing summaries without exporting per-packet data.
- RTT/retransmit counters from stable TCP instrumentation points.
- Runtime BPF global configuration for emit interval if needed.
