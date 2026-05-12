# eBPF Flow Counter Design

FlowLedger's eBPF collector is a lightweight flow counter, not a packet capture system. It aggregates TCP lifecycle and traffic counters in kernel maps and sends only summary events to userspace.

## Why Not Per-Packet Reporting

Per-packet ring buffer events would create high userspace overhead, large JSONL volume, and unnecessary payload-adjacent risk. FlowLedger only needs model-ready flow evidence, so the eBPF program keeps cumulative counters in maps and emits:

- one `CONNECT` event when a TCP flow reaches `TCP_ESTABLISHED`
- periodic `STATS` events when counters changed and the emit interval has elapsed
- one `CLOSE` event with final counters

No payload, TLS plaintext, HTTP path, HTTP headers, or HTTP body is captured.

## Maps

`flow_stats_map`

- Type: `BPF_MAP_TYPE_LRU_HASH`
- Key: `struct flow_key`
- Value: `struct flow_stats`
- Default max entries: `65536`
- Purpose: cumulative bytes/packets and lightweight TCP lifecycle counters per flow

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

## Snapshot Semantics

All eBPF traffic counters are cumulative snapshots for the flow:

- `bytes_sent`
- `bytes_recv`
- `packets_sent`
- `packets_recv`

They are not deltas. The Go sessionizer keeps the maximum counter value seen for the session, so `CONNECT`, `STATS`, and `CLOSE` can arrive as cumulative observations without double counting.

## Performance Protection

- No per-packet ring buffer output.
- LRU flow map bounds memory use.
- Periodic STATS emission is rate-limited by `EBPF_EMIT_INTERVAL_NS`.
- `--ebpf-flow-map-max-entries` can adjust the flow map size before object load.
- `--ebpf-enable-traffic-accounting=false` can run lifecycle-only collection.
- Packet timing and packet histogram flags remain disabled/reserved.

## Known Limitations

- IPv4 TCP only.
- Packet counters are syscall/message approximations, not wire packet counts.
- `--ebpf-stats-emit-interval` is currently mirrored by the BPF compile-time constant `EBPF_EMIT_INTERVAL_NS`; change the constant and run `go generate ./...` for a different kernel-side interval.
- No packet timing, packet size histogram, RTT estimate, or retransmit detection from eBPF yet.
- No TLS ClientHello, SNI, JA3, JA4, HTTP, gRPC, or payload parsing.
- CgroupID is best-effort attribution context and is not a stable Kubernetes identity by itself.

## Future Work

- TC/SKB hooks for exact wire-level packet counts.
- Packet size histograms without storing packet records.
- Inter-arrival timing summaries without exporting per-packet data.
- RTT/retransmit counters from stable TCP instrumentation points.
- Runtime BPF global configuration for emit interval if needed.
