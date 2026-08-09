# FlowLedger Schema v1alpha4

v1alpha4 changes TWO things on top of v1alpha3 (both ship together; v1alpha4
was never released with only the first):

1. **`window_summary` records carry per-window deltas** instead of
   lifetime-cumulative copies. A schema version bump is mandatory because the
   meaning of every additive counter on window records changes; a consumer
   must never interpret a v1alpha4 window with v1alpha3 (cumulative)
   semantics or vice versa.
2. **Source identity is a frozen per-generation snapshot** resolved near
   connection establishment — records no longer reflect emission-time cache
   state for the source endpoint (see "Source identity snapshot" below).
   Destination fields keep their emission-time resolution semantics.

Everything in [schema-v1alpha3.md](schema-v1alpha3.md) still applies unless
amended below. The kernel/BPF layer is untouched: it still emits cumulative
snapshots; the differencing happens in the userspace sessionizer.

## Record-level counter semantics

Every record now self-describes via `counter_semantics`:

| record_type | counter_semantics | additive counters mean |
|---|---|---|
| `window_summary` | `window_delta` | current cumulative snapshot **minus** the previous accepted baseline: the increment of this window only |
| `session_summary` | `lifetime_cumulative` | whole-connection totals (unchanged from v1alpha3) |

**The fixed-window dataset is exactly `record_type == "window_summary"`.**
`session_summary` is retained as a lifetime diagnostic record; it REPEATS
everything already emitted in the flow's windows and must never be counted as
another window. It never carries `window_valid=true`, `final_window=true`, or
a `window_start_time`.

### Fields with window-delta semantics on `window_summary`

`bytes_out/in`, `packets_out/in` (send/recv observation counts),
`observed_skb_packets_out/in`, `pkt_size_histogram`, `iat_histogram`,
`netflow_v2_ip_size_histogram`, `idle_gap_count`, `burst_count`,
`syn/fin/rst_count`, `retrans_count`, `local_retrans_skb_count/bytes`,
`direction_changes`, and all values derived from them: `bytes_total`,
`packets_total`, ratio fields, `pkt_size_mean/p50/p95/std`,
`iat_mean/p50/p95/std` (recomputed from the DELTA histograms),
`byte_rate`/`packet_rate` and `bytes_per_second_*`/`throughput_bps_*`
(computed over the window's data span `window_start_time … end_time`, not the
connection lifetime).

### Fields that deliberately KEEP lifetime semantics on windows

These are not additive and cannot be differenced; they are carried as
lifetime context and documented as such:

- `pkt_size_min/max`, `ip_ttl_min/max`, `ip_pkt_len_min/max`,
  `tcp_window_max_*` — envelopes (the kernel only keeps lifetime extrema);
- `tcp_flags_*` — monotone OR-masks;
- `direction_duration_*` — lifetime first-to-last packet spans;
- `duration_ms`, `conn_start_time`, `conn_end_time` — connection lifetime;
- TLS fields, identity fields, `is_long_lived`, availability flags,
  `counter_reset_detected/count` (lifetime diagnostics).

## Window validity

| field | meaning |
|---|---|
| `window_valid` (bool) | the delta counters are a trustworthy fixed-window increment. Always `false` on `session_summary`. |
| `window_invalid_reason` | `""` when valid; `unknown_baseline` — the generation's first observed event was a mid-flight cumulative snapshot (no `EVENT_CONNECT` proving counters started at zero, e.g. agent restart), so no baseline existed; `counter_reset` — a cumulative counter or histogram bucket regressed since the previous baseline (kernel map entry evicted/re-created). |
| `counter_epoch` (uint64) | groups windows differenced over one continuous kernel counter lineage. Starts at 0; the `counter_reset` window itself is recorded under the OLD epoch and the epoch increments for the windows after it. |
| `final_window` (bool) | the partial window flushed exactly once when the connection ends (CLOSE, inactivity timeout, agent shutdown, or a superseding CONNECT after a lost CLOSE). |
| `window_start_time` (RFC3339) | start of the delta interval (previous baseline snapshot time); the interval ends at `end_time`. |

**An invalid window carries all-zero delta counters and all-zero delta
histograms.** An unattributable cumulative mass is never presented as a window
increment. In both invalid cases the current snapshot becomes the new
baseline, so the NEXT window recovers normal differencing.

## Baseline / generation rules

- A connection generation that begins with `EVENT_CONNECT` (or mock `ACCEPT`)
  provably starts with zero counters: its zero baseline is trusted and the
  first window is a genuine increment (it includes the SYN).
- Any other first sighting ⇒ `unknown_baseline` first window (see above).
- A normal window emission (event-driven or Sweep-driven) advances the
  baseline and keeps the session alive; it never clears it.
- Connection end (CLOSE / inactivity timeout / shutdown) flushes the final
  partial window once, then destroys the session and its baseline.
- An `EVENT_CONNECT` arriving for a live session key means the previous
  connection on that 5-tuple ended without an observed CLOSE: the old
  generation is finalized (final window + `session_summary`,
  `close_reason=unknown`) and the new connection starts a fresh session with a
  new `flow_id` and a zero baseline. A reused 5-tuple can never inherit a
  baseline.
- After an agent restart no session state survives; resumed flows re-enter
  through the `unknown_baseline` path.

## Source identity snapshot

All `src_*` identity fields (pod, workload, revision, confidence, status) on
every window/session record come from ONE atomic resolution performed near
the connection generation's establishment, then frozen:

- Attempt 1 runs on the generation's first event (`EVENT_CONNECT` when
  observed; otherwise the first cumulative snapshot).
- Transient outcomes (`informer_miss`, `unknown` — caches not ready yet)
  retry on later events, at most 5 attempts per generation.
- Terminal outcomes freeze immediately: a resolved pod identity, or
  by-design-no-identity (`host_network`, `external`, loopback).
- After the retry budget the last snapshot freezes as **permanently
  missing**: pod/workload fields stay empty with an explicit
  `src_identity_missing_reason` — identity is NEVER substituted with IP or
  pod name. `src_ip` (G1) is always present regardless.
- A frozen snapshot is immutable: pod deletion, rollouts, cache updates, or
  emission timing cannot rewrite it. Already-written records are never
  backfilled. New generations (CONNECT supersede, 5-tuple reuse), CLOSE,
  timeout, and agent restart always start from a fresh, empty snapshot.

Contract fields:

| field | meaning |
|---|---|
| `src_identity_resolution_method` | SOURCE-only resolution path (`cgroup_id` / `pod_ip` / `host_netns` / `external` / `informer_miss` / `unknown`). Read THIS for source provenance — the record-level `mapping_method` reports the destination's method whenever the source did not resolve via `cgroup_id`, and must not be used for source statistics. |
| `src_identity_frozen` | the snapshot is final for this generation |
| `src_identity_observed_time` | when the resolution that produced the identity ran |
| `src_identity_attempts` | resolution attempts so far |
| `src_identity_missing_reason` | why pod identity is absent (`informer_miss`, `unknown_source`, `host_network`, `external_source`, ...); empty when resolved |
| `src_revision_source` | how `src_revision` was derived: `replicaset_revision` / `controller_revision_hash` / `pod_template_hash` / `not_applicable` / `unavailable` |
| `src_key_g2_available` | G2 (pod UID) constructible from this record |
| `src_key_g3_available` | G3 (namespace + top-level controller kind + controller UID) constructible |
| `src_key_g4_available` | G4 (G3 + rollout revision) constructible; `not_applicable` counts as constructible (G4 degenerates to G3 deterministically) |

**Revision semantics (G4)**: `src_revision` is bound to the POD's own
rollout, never the controller's current latest revision. Deployment pods take
the `deployment.kubernetes.io/revision` annotation of their OWNER ReplicaSet
(each ReplicaSet permanently carries the revision of the rollout that created
it), falling back to the pod's `pod-template-hash` label; StatefulSet/
DaemonSet pods use their `controller-revision-hash` label; Jobs/bare pods are
`not_applicable`. Consequences: pod recreation and same-rollout scale-up keep
G4 unchanged; a rolling update keeps G3 and changes G4; coexisting old/new
pods each carry their own revision. (`dst_revision` still uses the legacy
controller-level derivation and must not be used as a rollout key.)

## Versioning

- `schema_version`: `v1alpha4`
- `feature_set_version`: `flowledger-fast-features-v2` (window features are
  now fixed-window increments; their distributions are not comparable with
  v1 windows).

## Migration from v1alpha3

v1alpha3 windows were lifetime-cumulative prefixes: consumers had to
difference consecutive windows per `flow_id` themselves and had no validity,
epoch, or final-window markers. In v1alpha4 that differencing (including
reset/unknown-baseline handling) is done in the sessionizer and every window
is directly usable as a fixed-window sample after filtering
`window_valid == true`.
