# eBPF Smoke Test

## Purpose

This smoke test verifies the local Linux eBPF collector path for real TCP lifecycle and lightweight counter events:

- The eBPF collector can start.
- The eBPF program can attach to `sock/inet_sock_set_state`.
- The eBPF program can attach to `tcp_sendmsg` / `tcp_recvmsg` accounting hooks when enabled.
- On cgroup v2 hosts, the eBPF program can attach to `cgroup_skb/ingress` and `cgroup_skb/egress` packet histogram hooks when enabled.
- The TLS ClientHello inspection ring buffer can deliver bounded first-handshake metadata to userspace.
- The ring buffer can deliver kernel events to Go userspace.
- `CONNECT`, `STATS`, and `CLOSE` events can be converted into `collector.FlowEvent`.
- The sessionizer can emit `session_summary` records.
- `flows.jsonl` can be written.
- Metrics can reflect eBPF events.

This smoke test does not verify:

- Kubernetes DaemonSet deployment.
- Pod identity enrichment.
- Service or EndpointSlice mapping.
- Changing top-level packet counter semantics; `packets_out` / `packets_in` remain syscall/message counters.
- TLS metadata.
- Malicious traffic detection.
- ML or alerting.
- TLS decryption, certificate capture, or fragmented ClientHello reassembly.

## Prerequisites

Use a Linux or WSL2 Ubuntu environment with:

- Root or `sudo` privileges.
- A working Go environment.
- `clang` and `llvm`.
- Optional `bpftool`.
- Kernel support for eBPF, tracepoints, and ring buffers.
- A passing `go test ./...` run.
- Awareness that the current eBPF collector only supports IPv4 TCP lifecycle, lightweight send/recv accounting, and cgroup v2 packet histogram hooks.

Install common dependencies:

```sh
sudo apt update
sudo apt install -y clang llvm make gcc curl netcat-openbsd jq
```

Optionally install `bpftool`:

```sh
sudo apt install -y bpftool
```

## Build / Test Check

Run the regular test and Linux build checks first:

```sh
go test ./...
CGO_ENABLED=0 GOOS=linux go build ./cmd/node-agent
```

The generated eBPF bindings are checked in. Re-run generation only if generated files are missing or `bpf/flow_events.bpf.c` has changed:

```sh
go generate ./...
```

## Run node-agent In eBPF Mode

Start the agent as root so it can load and attach the eBPF program:

```sh
sudo rm -f ./flows.jsonl
sudo go run ./cmd/node-agent \
  --mode ebpf \
  --ledger-path ./flows.jsonl \
  --node-name local-ebpf-test \
  --metrics-addr :9090 \
  --ebpf-enable-traffic-accounting=true \
  --ebpf-enable-packet-histogram=true \
  --ebpf-enable-packet-timing=true \
  --ebpf-enable-tls-handshake-inspect=true
```

Expected logs should include:

- `flow-ledger node-agent started`
- `mode=ebpf`
- `kubernetes in-cluster config not available; running with empty metadata cache`, which is normal outside Kubernetes.
- `ebpf collector attached tracepoint sock/inet_sock_set_state`
- `ebpf collector attached tcp send/recv accounting hooks`
- `ebpf collector attached cgroup_skb packet hooks`, on cgroup v2 hosts.
- `ebpf collector started tls handshake ringbuf reader`, when TLS inspection is enabled.
- `ebpf collector started ringbuf reader`

## Generate Real TCP Traffic

In a second terminal, generate real IPv4 TCP connections:

```sh
curl -4 https://example.com
curl -4 http://example.com
```

You can also try a local `nc` connection.

Terminal A:

```sh
nc -l 127.0.0.1 18080
```

Terminal B:

```sh
echo "hello" | nc 127.0.0.1 18080
```

For a larger local transfer:

Terminal A:

```sh
nc -l 127.0.0.1 18080 > /tmp/flowledger-nc.out
```

Terminal B:

```sh
dd if=/dev/zero bs=1024 count=100 | nc 127.0.0.1 18080
```

Notes:

- The current eBPF collector observes TCP lifecycle state changes, lightweight send/recv counters, and packet histogram summaries. HTTPS/TLS content is not decrypted.
- `packets_out` and `packets_in` are syscall/message approximations. Packet-level cgroup_skb counters are used for histogram-derived features without changing those field semantics.
- Local loopback visibility can vary by kernel path. If loopback does not produce useful events, prefer external IPv4 traffic with `curl -4`.

## Verify flows.jsonl

Inspect the ledger:

```sh
sudo cat ./flows.jsonl
sudo cat ./flows.jsonl | jq .
sudo tail -n 20 ./flows.jsonl | jq .
```

Expected records should include at least one:

- `record_type` set to `session_summary`.
- `node_name` set to `local-ebpf-test`.
- `protocol` set to `tcp`.
- Event-derived `start_time`, `end_time`, and `duration_ms`.
- Non-empty `src_ip`, `dst_ip`, `src_port`, and `dst_port`.
- `src_mapping_confidence` and `dst_mapping_confidence` may be `unknown`, which is normal in a local non-Kubernetes environment.
- `STATS` records or final `CLOSE` records with `traffic_accounting_available=true`.
- `bytes_out` or `bytes_in` should be non-zero for flows that hit the send/recv hooks.
- `packets_out` and `packets_in` are approximate syscall/message counters.
- On cgroup v2 with packet hooks attached, `pkt_size_histogram` should have non-zero buckets.
- With packet timing enabled and at least two packets in the same direction, `iat_p50` / `iat_p95` should be non-null. They are estimates from fixed histogram buckets.
- For HTTPS flows with a complete first ClientHello in the captured 1024 bytes, `handshake_seen=true`, `tls_parse_status=parsed`, and `ja4`, `sni_hash`, and `alpn` should be populated.
- Plaintext SNI such as `example.com` should not appear in the JSONL.

## Verify Metrics

Inspect FlowLedger metrics:

```sh
curl localhost:9090/metrics | grep flowledger
```

Focus on:

- `flowledger_ebpf_events_total`
- `flowledger_ebpf_events_by_type_total`
- `flowledger_ebpf_read_errors_total`
- `flowledger_ebpf_attach_errors_total`
- `flowledger_ebpf_stats_events_total`
- `flowledger_ebpf_connect_events_total`
- `flowledger_ebpf_close_events_total`
- `flowledger_ebpf_ringbuf_reserve_failures_total`
- `flowledger_ebpf_map_full_drops_total`
- `flowledger_tls_handshakes_parsed_total`
- `flowledger_tls_unmatched_total`
- `flowledger_tls_buffer_reserve_failed_total`
- `flowledger_sessions_emitted_total`

Expected behavior:

- `flowledger_ebpf_events_total` is greater than `0`.
- `CONNECT` event count is greater than `0`.
- `CLOSE` event count is preferably greater than `0`.
- `STATS` events should increase during longer or larger transfers.
- Ring buffer reserve failures and map full drops should not continuously increase.
- Read errors should not continuously increase.
- Attach errors should be `0`.
- TLS parsed status should increase for HTTPS flows.
- Sessions emitted should increase as connections close.

## Troubleshooting

### A. permission denied / operation not permitted

The process needs root privileges, or the kernel may restrict unprivileged BPF. Run the node-agent with `sudo`.

### B. tracepoint attach failed

Check that the tracepoint exists:

```sh
sudo ls /sys/kernel/tracing/events/sock/inet_sock_set_state
sudo cat /sys/kernel/tracing/events/sock/inet_sock_set_state/format
```

If the path does not exist, the current kernel may not support this tracepoint.

### C. no flows.jsonl generated

Check:

- Whether `node-agent` is still running.
- Whether traffic used IPv4, for example `curl -4`.
- Whether real TCP connections were created.
- Whether `flowledger_ebpf_events_total` increased.
- If events increased but sessions were not emitted, whether `CONNECT` and `CLOSE` events share the same flow key.

### D. events exist but identity unknown

This is normal in local WSL/Linux tests. The process is not running as a Kubernetes Pod with a populated Kubernetes metadata cache.

### E. bytes/packets are zero

Check that the agent was started with `--ebpf-enable-traffic-accounting=true` and that logs show the tcp send/recv accounting hooks attached. Very short connections may close before a periodic `STATS` event, but the final `CLOSE` should carry counters if the send/recv hooks observed the flow. If counters remain zero, the current kernel may not expose the expected hook path for that traffic.

### F. IPv6 traffic not captured

The current collector only handles `AF_INET`, which means IPv4. Use `curl -4`.

### G. pkt_size_histogram remains empty

Check:

- The host uses cgroup v2: `test -f /sys/fs/cgroup/cgroup.controllers`.
- The agent logs include `ebpf collector attached cgroup_skb packet hooks`.
- `--ebpf-enable-packet-histogram=true` or `--ebpf-enable-packet-timing=true` was set.
- The connection lived long enough for packet hooks to observe traffic before the flow closed.

### H. ja4 / sni_hash remain empty

Check:

- The agent was started with `--ebpf-enable-tls-handshake-inspect=true`.
- The host uses cgroup v2 and cgroup_skb packet hooks attached.
- The test traffic is HTTPS with a ClientHello visible in the first egress payload.
- `flowledger_tls_handshakes_parsed_total{status="fragmented"}` did not increase instead; fragmented ClientHellos are not reassembled in this version.

## Pass Criteria

The smoke test passes when:

- `go test ./...` passes.
- `node-agent --mode ebpf` starts with `sudo`.
- eBPF attach has no error.
- After real `curl` or `nc` TCP connections, eBPF event metrics increase.
- `flows.jsonl` contains at least one `session_summary` from a real connection.
- With traffic accounting enabled, at least one `STATS` or `CLOSE` record has `traffic_accounting_available=true` and non-zero byte counters.
- On cgroup v2 with packet hooks enabled, at least one record has non-empty `pkt_size_histogram`; for multi-packet flows, `iat_p50` should be non-null.
- For HTTPS traffic, at least one record has `handshake_seen=true`, `tls_parse_status=parsed`, non-empty `ja4`, and non-empty `sni_hash`.
- `grep -i 'example.com' flows.jsonl` returns no plaintext SNI matches.
- The JSONL output can be parsed by `jq`.
- Ring buffer or read errors do not continuously increase.

## Known Limitations

- Does not verify Kubernetes deployment.
- Does not verify Pod identity.
- Does not verify Service mapping.
- Does not verify attack detection.
- Does not verify TLS tunnel identification.
- Does not capture payload.
- Does not decrypt TLS.
- Does not store plaintext SNI.
- Does not capture certificates.
- Does not reassemble fragmented ClientHellos.
- `packets_out` / `packets_in` are approximate syscall/message counters; cgroup_skb histogram features are packet-level but do not rename those fields.
- Packet and IAT percentiles are estimated from histograms, not raw sequences.
- IPv4 TCP only.
- PID and CgroupID at this tracepoint are best-effort and should not be treated as strong attribution evidence.
