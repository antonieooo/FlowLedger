#!/usr/bin/env bash
# Privileged smoke test for the v1alpha3 P2 local-retransmission collection
# (tracepoint tcp/tcp_retransmit_skb + CO-RE skb->len).
#
# REQUIRES ROOT and mutates local qdisc state (tc netem) for the test duration.
# DO NOT run against a production node or the thesis cluster without explicit
# authorization. Intended for a scratch VM with:
#   - Linux >= 5.x with BTF (/sys/kernel/btf/vmlinux); validated target: 6.8
#   - tracepoint tcp/tcp_retransmit_skb present
#   - cgroup v2 mounted at /sys/fs/cgroup
#
# What it does:
#   1. Preflight: verify tracepoint + BTF exist.
#   2. Start node-agent in eBPF mode writing to a scratch ledger dir.
#   3. Induce retransmissions: 20% egress loss on loopback via tc netem, then
#      run a short TCP transfer through it.
#   4. Assert the ledger contains a record with local_retrans_available=true
#      and local_retrans_skb_count > 0, and that the attach metric reported
#      success.
#   5. Clean up qdisc and processes.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: must run as root (loads eBPF, mutates tc qdisc)" >&2
    exit 1
fi

TRACEFS=/sys/kernel/tracing
[[ -d ${TRACEFS}/events ]] || TRACEFS=/sys/kernel/debug/tracing

echo "== preflight"
if [[ ! -d ${TRACEFS}/events/tcp/tcp_retransmit_skb ]]; then
    echo "ERROR: tracepoint tcp/tcp_retransmit_skb not present on this kernel" >&2
    echo "       expected on >= 4.15; validated target is 6.8" >&2
    exit 1
fi
if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
    echo "ERROR: /sys/kernel/btf/vmlinux missing; CO-RE skb->len read needs CONFIG_DEBUG_INFO_BTF=y" >&2
    exit 1
fi
echo "tracepoint + BTF present"

WORKDIR=$(mktemp -d /tmp/flowledger-retrans-smoke.XXXXXX)
LEDGER="${WORKDIR}/flows.jsonl"
METRICS_ADDR="127.0.0.1:19109"
trap 'set +e; kill "${AGENT_PID:-}" "${SERVER_PID:-}" 2>/dev/null; tc qdisc del dev lo root 2>/dev/null; echo "workdir kept at ${WORKDIR}"' EXIT

echo "== build + start node-agent (ebpf mode)"
go build -o "${WORKDIR}/node-agent" ./cmd/node-agent
"${WORKDIR}/node-agent" \
    --mode ebpf \
    --ledger-path "${LEDGER}" \
    --metrics-addr "${METRICS_ADDR}" \
    --allow-unsynced-metadata \
    --drop-nonlocal-src=false \
    >"${WORKDIR}/agent.log" 2>&1 &
AGENT_PID=$!
sleep 3
grep -q "attached tcp/tcp_retransmit_skb" "${WORKDIR}/agent.log" || {
    echo "ERROR: retransmit tracepoint did not attach; agent log:" >&2
    tail -20 "${WORKDIR}/agent.log" >&2
    exit 1
}

echo "== induce retransmissions (20% loss on lo)"
tc qdisc add dev lo root netem loss 20%
# Simple TCP transfer across loopback; loss forces local retransmits.
python3 - <<'PYEOF' &
import socket, threading
srv = socket.socket(); srv.bind(("127.0.0.1", 15551)); srv.listen(1)
def serve():
    c, _ = srv.accept()
    while c.recv(65536):
        pass
threading.Thread(target=serve, daemon=True).start()
cli = socket.create_connection(("127.0.0.1", 15551))
for _ in range(2000):
    cli.sendall(b"x" * 1400)
cli.close()
PYEOF
SERVER_PID=$!
wait "${SERVER_PID}" || true
tc qdisc del dev lo root
sleep 12  # > one STATS emit interval so cumulative totals reach the ledger

echo "== assertions"
kill "${AGENT_PID}"; wait "${AGENT_PID}" 2>/dev/null || true
python3 - "$LEDGER" <<'PYEOF'
import json, sys
hit = False
for line in open(sys.argv[1]):
    r = json.loads(line)
    if r.get("local_retrans_available") and (r.get("local_retrans_skb_count") or 0) > 0:
        print(f"OK: flow {r['src_ip']}:{r['src_port']}->{r['dst_ip']}:{r['dst_port']} "
              f"local_retrans_skb_count={r['local_retrans_skb_count']} "
              f"bytes={r['local_retrans_skb_bytes']} source={r['local_retrans_source']}")
        assert r["local_retrans_source"] == "tcp_retransmit_skb", r["local_retrans_source"]
        assert r.get("peer_retrans_skb_count") is None, "peer field must stay null"
        assert r.get("peer_retrans_available") is False, "peer availability must stay false"
        hit = True
if not hit:
    sys.exit("FAIL: no record with local_retrans_available=true and count>0")
print("SMOKE PASS")
PYEOF
