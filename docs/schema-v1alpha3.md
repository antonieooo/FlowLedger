# FlowLedger Schema v1alpha3

v1alpha3 is a correctness + coverage release on top of v1alpha2:

- **P0 — cumulative-snapshot aggregation fix**: eBPF counter/histogram fields
  are no longer re-summed across the flow's repeated STATS snapshots.
- **P0 — exported skb packet counters**: the cgroup_skb-observed packet counts
  that already existed inside the collector (`real_packets_sent/recv`) now
  reach the ledger under honest names.
- **P1 — TCP/IP header aggregates**: TTL, TCP flag OR-masks, raw advertised
  window maxima, per-direction active durations, IP total-length envelope, a
  NetFlow-v2 edge histogram, and Go-derived byte/bit rates. All extracted from
  the IPv4/TCP headers the cgroup_skb hooks already read — no new hooks, no
  per-packet userspace events.
- **P2 — local retransmissions**: LOCAL egress retransmission skb counts from
  the `tcp/tcp_retransmit_skb` tracepoint. Explicitly NOT a full
  bidirectional nProbe RETRANSMITTED_* implementation — the peer direction is
  unobservable and stays null.

Deliberately **not** in this version (deferred): DNS/ICMP/FTP features,
initiator-role (client/server) mapping, window-scale correction, peer-side
retransmission observation.

Everything in [schema-v1alpha2.md](schema-v1alpha2.md) still applies unless
amended below.

## Counter semantics

Internally every `FlowEvent` now carries `counter_semantics`:

- `cumulative` — **eBPF mode.** Every CONNECT/STATS/CLOSE event carries the
  flow's totals since flow start (the kernel `flow_stats` entry is a per-flow
  monotonic accumulator). Cumulative fields: `bytes_sent/recv`,
  `packets_sent/recv`, `real_packets_sent/recv`, the packet-size and IAT
  histograms, `pkt_size_min/max` (envelopes), `idle_gap_count`, `burst_count`,
  `syn/fin/rst_count`, and any future TCP/IP counters.
- `delta` (or absent — legacy default) — **mock mode.** Counters are per-event
  increments; aggregation sums them, exactly as in v1alpha2, including the
  implied SYN-on-CONNECT / FIN-on-CLOSE.

Aggregation rules for cumulative events:

| Field class | Rule |
|---|---|
| bytes / packets / real packets | latest monotonic cumulative value (increases only) |
| histograms | replaced by the latest complete snapshot — never bucket-summed |
| idle/burst/SYN/FIN/RST | latest monotonic cumulative value |
| min/max | global min / global max |
| flag masks (P1) | bitwise OR |
| max window / min-max envelopes (P1) | monotone max / global min-max |
| direction durations (P1) | monotone max (last-first grows with the flow) |

**Reset handling**: a cumulative counter that regresses (new value below the
stored one, and non-zero) means the kernel-side accumulator was reset — LRU
map eviction with re-create, or an agent restart. The pre-reset maximum is
kept (no negative deltas are ever produced), pre- and post-reset values are
**never summed**, and the event is recorded in `counter_reset_count`. A zero
counter means "not provided" (e.g. a CLOSE emitted after the map entry
vanished) and is not a reset.

## New record fields

| Field | Type | Meaning |
|---|---|---|
| `observed_skb_packets_out` | uint64 | skbs observed at `cgroup_skb/egress` for this flow (cumulative; latest monotonic value). `out` = egress from the flow's src endpoint (the local socket side in eBPF mode). |
| `observed_skb_packets_in` | uint64 | Same at `cgroup_skb/ingress`. |
| `observed_skb_packets_total` | uint64 | `out + in`. |
| `observed_skb_packets_available` | bool | True iff ≥1 skb count was observed (needs cgroup v2, attached cgroup_skb hooks, local-endpoint index hit, and `EnablePacketHistogram`). |
| `observed_skb_packets_source` | string | `"cgroup_skb"` (eBPF), `"mock"` (mock fixtures), `""` (unavailable). |
| `counter_reset_detected` | bool | ≥1 cumulative counter reset was observed for this flow; totals are a lower bound. |
| `counter_reset_count` | uint64 | Number of events in which a reset was observed (sessionizer- plus feature-level detections). |

**These are skb counts, not wire packets.** At the cgroup_skb hooks one skb
may be a GSO aggregate (egress, before segmentation) or a GRO aggregate
(ingress, after coalescing) of many MTU-sized wire packets. Uncalibrated, they
must not be called exact wire packet counts nor compared 1:1 against PCAP.
The legacy `packets_out` / `packets_in` fields keep their v1alpha2
syscall/message semantics (`tcp_sendmsg`/`tcp_recvmsg` call counts) — they
were **not** redefined.

## P1: TCP/IP header aggregate fields

Direction convention for every `*_out` / `*_in` field: **out = local
socket/cgroup egress, in = local ingress.** These are NOT client/server. Only
a downstream cohort that has independently established the local end as the
active connection initiator may map out/in to client/server; if a generic
client/server field is ever added it must carry its own initiator-role
availability flag rather than guessing.

All kernel-side values are cumulative per flow and are aggregated with
idempotent operations (min/max envelope, bitwise OR, monotone max), so
repeated cumulative snapshots and reordered events never re-accumulate.
Source hook for all of them: the IPv4/TCP headers already parsed in
`cgroup_skb/{ingress,egress}`. Every pointer field is null — and its
availability flag false — when the signal was never observed or the packet
feature hooks are disabled; a value is never fabricated.

**Collector gates (kernel-side).** Two node-agent flags control these fields
via `flow_config` bits read by the BPF program itself (not just Go-side
nulling): `-ebpf-enable-header-aggregates` (TTL/flags/window/IP-length
envelopes) and `-ebpf-enable-netflow-v2-histogram` (the IP-size histogram),
both default true. With a gate off the kernel skips the corresponding
updates — for header aggregates it also skips the extra TCP byte-12..15
load — and every affected field surfaces as null/unavailable. Hot-path
layout: the TCP byte-12..15 load happens only after the canonical
`local_ep_to_key` lookup hit, so `packet_ep_miss` traffic (flows that never
reach `flow_stats`) pays no header-aggregate parsing cost.

**Observation witness (`tcp_header_observed_*`).** The kernel keeps a
monotonic per-direction flag, `tcp_header_observed_sent/recv`, set exactly
when the TCP byte-12..15 header load succeeded — **never** inferred from the
flag or window *values*. All `tcp_flags_*`/`tcp_window_*` availability is
derived from this witness. Consequence: a direction observed with an all-zero
flag byte (TCP NULL scan) or a permanently zero advertised window serializes
as a **genuine `0` with `available=true`**, while a never-observed direction
stays null. Mock fixtures modelling TCP header observation must set the
witness fields explicitly.

**Concurrency semantics (per-flow, cross-CPU).**

- *Exact:* all `__sync_fetch_and_add` counters (bytes, packets, histogram
  buckets, retransmissions) and the per-direction TCP flag OR-masks — the
  latter use a 32-bit **atomic fetch-or** (`__sync_fetch_and_or`, BPF ISA v3
  via `-mcpu=v3`), so a one-shot SYN/RST/FIN bit can never be lost to a
  cross-CPU race. Minimum kernel for these atomics: Linux ≥ 5.12 (x86_64
  JIT), ≥ 5.17 (arm64 JIT); the deployment target is Ubuntu 6.8.
- *Concurrent best-effort extrema (NOT exact):* `ip_ttl_min/max`,
  `tcp_window_max_out/in`, `ip_pkt_len_min/max`, and `pkt_size_min/max` are
  updated with a non-atomic compare-then-store; two CPUs racing on the same
  flow can each pass the compare and the later store wins, so an individual
  extremum update can be lost. A strict per-packet CAS loop was judged not
  worth the hot-path cost. Treat these as high-probability envelopes, not
  guarantees.

| Field | Type | Meaning |
|---|---|---|
| `ip_ttl_min` / `ip_ttl_max` | uint32?, uint32? | Observed IPv4 TTL envelope over **both directions** combined. Note egress TTL is what the local stack set (usually a constant 64), so the envelope typically mixes a constant with the remote hop-derived ingress TTL. |
| `ip_ttl_available` | bool | ≥1 TTL observed. |
| `tcp_flags_all` / `tcp_flags_out` / `tcp_flags_in` | uint32? | Bitwise **OR** of the raw TCP flag byte (CWR\|ECE\|URG\|ACK\|PSH\|RST\|SYN\|FIN), read from TCP header byte 13 — never a count, and never inferred from `inet_sock_set_state`. `all = out \| in`. Null per direction iff `tcp_header_observed_*` is false there; an observed direction with an all-zero flag byte (TCP NULL scan) is a genuine `0`, not null. Kernel merge is a 32-bit **atomic fetch-or** (`-mcpu=v3`): exact, no lost bits under cross-CPU concurrency. |
| `tcp_flags_available` | bool | `tcp_header_observed_sent \|\| tcp_header_observed_recv` — derived from the header-observed witness, never from the mask values. Governs `tcp_flags_all` too. |
| `tcp_window_max_out` / `_in` | uint32? | Per-direction maximum of the **raw advertised window** field (TCP header bytes 14–15, converted from network byte order). This is NOT the effective scaled window: window scaling (RFC 7323) is negotiated in SYN options and is neither implemented nor verified here. Null iff the direction's `tcp_header_observed_*` witness is false; an observed direction whose every segment advertised window 0 is a genuine `0`. Concurrent best-effort extremum (see above), not exact. |
| `tcp_window_available` | bool | ≥1 direction header-observed (witness-derived). |
| `direction_duration_out_ms` / `_in_ms` | uint64? | Active span per direction: last-minus-first observed skb, computed in the kernel at event emit time. The raw first/last timestamps are **kernel-internal only** and never exported. A direction with exactly one packet reports a genuine `0`; a never-observed direction is null. |
| `direction_duration_available` | bool | ≥1 direction observed. |
| `ip_pkt_len_min` / `ip_pkt_len_max` | uint32? | Envelope of `ntohs(ip.tot_len)` (IPv4 total length, host byte order). Distinct from `pkt_size_min/max`, which keep their existing `skb->len` (flow_pkt_len) semantics. tot_len values `< 20` are treated as implausible and skipped. May reflect GSO/GRO aggregates. |
| `ip_pkt_len_available` | bool | ≥1 valid tot_len observed. |
| `netflow_v2_ip_size_histogram` | map? | NetFlow-v2 edge histogram over `ntohs(ip.tot_len)`, both directions: `<=128`, `129-256`, `257-512`, `513-1024`, `1025-1514`, `>1514`. The `>1514` bucket is **overflow** (mostly GSO/GRO aggregates a fixed-MTU capture would never see): an Anomal-E adapter selects only the first five buckets and must report overflow separately — never fold it into `1025-1514`. Cumulative events replace the stored histogram with the latest snapshot; delta (mock) events sum. Null when nothing was observed. |
| `netflow_v2_ip_size_histogram_available` | bool | ≥1 bucketed length observed. |
| `bytes_per_second_out` / `_in` | float64? | Go-derived: syscall-level `bytes_out/in` divided by the whole session duration, in **bytes per second**. Null when duration ≤ 0 or traffic accounting is unavailable (division by zero duration is never performed); a genuine 0 is possible for a zero-byte direction. |
| `throughput_bps_out` / `_in` | float64? | The same quantity in **bits per second** (×8). Same null rules. |

## Migration from v1alpha2

### Cumulative-snapshot double counting is fixed

v1alpha2 **summed** the cumulative snapshots that eBPF CONNECT/STATS/CLOSE
events carry. Every additional STATS emission re-added the flow's entire
history, so these fields were inflated roughly in proportion to flow age:

- `pkt_size_histogram`, `iat_histogram` — and every estimate derived from
  them (`pkt_size_mean/p50/p95/std`, `iat_mean/p50/p95/std`)
- `idle_gap_count`, `burst_count`
- `syn_count`, `fin_count`, `rst_count` — additionally double-counted once by
  a Go-side auto-increment on CONNECT/CLOSE duplicating the BPF-side count
  (now restricted to delta/mock events)
- `direction_changes`, `retrans_count` (eBPF path; mock unaffected)

v1alpha3 resolves each to the latest snapshot. **Do not mix v1alpha2 and
v1alpha3 records when training or comparing these features**;
`feature_set_version` was bumped (`flowledger-fast-features-v0` →
`flowledger-fast-features-v1`) to make the boundary machine-checkable.

### Unchanged

- `bytes_out/in`, `packets_out/in`: semantics unchanged (latest cumulative
  value; syscall-level packet approximation).
- `pkt_size_min/max`, TLS fields, identity fields, sampling fields, record
  types, rotation, retention: unchanged.
- Mock (delta) aggregation: unchanged, byte-for-byte v1alpha2 behaviour.
- The eBPF program and its map layouts: unchanged in this release.

### New fields

The P0 fields (seven) plus the P1 header aggregates listed above. A v1alpha2
reader that ignores unknown keys parses v1alpha3 records unchanged. The BPF
`flow_stats` map value and `flow_event` record grew in P1, so the collector
binary and BPF object must be upgraded together.

## Anomal-E / NetFlow-v2 note

Coverage against the NetFlow-v2 feature set after P0+P1:

- IN_PKTS / OUT_PKTS analogues: `observed_skb_packets_in/out` (skb-vs-wire
  caveat above).
- MIN_TTL / MAX_TTL: `ip_ttl_min/max`.
- TCP_FLAGS: `tcp_flags_all` (out/in masks additionally available).
  CLIENT/SERVER_TCP_FLAGS require initiator-role knowledge the ledger does
  not record — an adapter may map out/in to client/server only when its
  cohort has independently established the local end as the active initiator.
- TCP_WIN_MAX_IN/OUT: `tcp_window_max_in/out` (raw advertised window,
  unscaled, matching nProbe's field).
- DURATION_IN / DURATION_OUT: `direction_duration_in/out_ms`.
- MIN/MAX_IP_PKT_LEN: `ip_pkt_len_min/max`; LONGEST/SHORTEST_FLOW_PKT:
  `pkt_size_min/max` (skb->len semantics).
- NUM_PKTS_UP_TO_128_BYTES … NUM_PKTS_1024_TO_1514_BYTES: the first five
  buckets of `netflow_v2_ip_size_histogram`; `>1514` is overflow and must be
  reported separately.
- SRC_TO_DST / DST_TO_SRC_AVG_THROUGHPUT: `throughput_bps_out/in` (bits/s);
  `bytes_per_second_out/in` are the bytes/s variants.

Still not covered: peer-direction retransmission features
(RETRANSMITTED_IN_*: unobservable from local hooks, always null),
SECOND_BYTES accumulators, ICMP/DNS/FTP/L7 features (out of scope — TCP-only,
no payload inspection). Absent features stay absent — never fabricated zeros.

## P2: local retransmissions

| Field | Type | Meaning |
|---|---|---|
| `local_retrans_skb_count` | uint64? | Cumulative count of skbs the LOCAL stack re-queued for transmission on this flow (latest monotonic value). **skb granularity**: a retransmitted skb may be a GSO aggregate covering several wire segments, so this is NOT a wire-packet or segment count and the name deliberately keeps `skb`. Null when the tracepoint is unavailable; a present `0` means "hook attached, no retransmissions observed". |
| `local_retrans_skb_bytes` | uint64? | Cumulative `skb->len` bytes of those skbs (CO-RE read; approximate — the skb at this tracepoint is TCP-level, not wire framing). Same null semantics. |
| `local_retrans_available` | bool | True iff the tracepoint attached in this collector instance. Comes exclusively from the attach status — never inferred from counter values, so an unattached hook can never report 0 as "confirmed no retransmissions". |
| `local_retrans_source` | string | `"tcp_retransmit_skb"` (eBPF), `"mock"` (fixtures), `""` (unavailable). |
| `peer_retrans_skb_count` / `peer_retrans_skb_bytes` | — | **Always null.** Remote (dst→src) retransmissions are not observable from local socket hooks. Local values are never copied into the peer direction. |
| `peer_retrans_available` | bool | **Always false.** |

### Semantics and DNAT

- **Hook**: `tracepoint/tcp/tcp_retransmit_skb`. The flow key is built from
  the tracepoint's `skaddr` socket exactly like the tcp_sendmsg/tcp_recvmsg
  accounting hooks (`key_from_sock`), so it is the **pre-DNAT canonical
  socket key**: a client flow to a Service accumulates retransmissions on the
  ClusterIP tuple — the same `flow_stats` entry every other socket hook
  updates. No kube-proxy DNAT reconciliation is needed or performed.
- IPv4 and IPv4-mapped IPv6 sockets are supported; genuine IPv6 remains
  unsupported (dropped with `unsupported_ipv6`, unchanged).
- Only `flow_stats_map` is updated; **no per-retransmit ringbuf event is ever
  emitted**. Totals ride the existing STATS emission cadence (≥5 s) as
  cumulative snapshots with the standard latest-monotonic merge and reset
  detection (`counter_reset_*`).
- A retransmit whose flow has no `flow_stats` entry (LRU-evicted, or raced
  with CLOSE) is counted in the `retrans_flow_miss` drop counter /
  `flowledger_ebpf_retrans_flow_miss_total` metric instead of being
  attributed anywhere.

### Anomal-E mapping restriction

Only when a downstream cohort has independently established the local end as
the **active initiator** may `local_retrans_*` be read as an approximation of
src→dst (RETRANSMITTED_OUT_*) retransmissions. The dst→src direction cannot
be measured from this hook; its fields stay null/false, and copying the local
values into both directions is forbidden.

### Runtime dependencies and failure mode

- Tracepoint `tcp/tcp_retransmit_skb` (present since Linux 4.15; the
  validated target environment is the Ubuntu 6.8 kernel on the k3s VMs).
- Kernel BTF (`CONFIG_DEBUG_INFO_BTF=y`, `/sys/kernel/btf/vmlinux`) for the
  CO-RE `skb->len` read — no hard-coded struct offsets are used.
- Attach is best-effort: on failure the collector keeps running, logs the
  error, reports `flowledger_ebpf_retrans_attach_total{status="failure"}` and
  `flowledger_ebpf_retrans_hook_attached=0`, and every record carries
  `local_retrans_available=false` with null counters.
- Privileged smoke test: `scripts/retrans_smoke_test.sh` (root; mutates local
  tc qdisc; must NOT be run against the thesis cluster without explicit
  authorization).
