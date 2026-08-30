// SPDX-License-Identifier: Apache-2.0

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6

#define TCP_ESTABLISHED 1
// v1alpha6: entry creation moves forward to the SYN states so a connection's
// handshake packets have somewhere to be counted. TCP_NEW_SYN_RECV (12) is
// deliberately NOT handled: its tracepoint fires with skaddr pointing at a
// struct request_sock, whose layout only guarantees the embedded sock_common
// -- sk_cgrp_data (read by sk_cgroup_id) lives outside it, so attributing
// from that pointer would read whatever happens to sit at that offset.
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3
#define TCP_CLOSE 7

#define EVENT_CONNECT 1
#define EVENT_CLOSE 2
#define EVENT_STATS 3
#define EVENT_DROP 4

#define DIRECTION_UNKNOWN 0
#define DIRECTION_SEND 1
#define DIRECTION_RECV 2

// Raw TCP header flag bits, used only by the v1alpha5 per-direction flag
// counters. Deliberately NOT applied to tcp_flags_or_sent/recv, which keep
// exporting the whole flag byte unmasked.
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04

#define DROP_MAP_UPDATE_FAILED 0
#define DROP_RINGBUF_RESERVE_FAILED 1
#define DROP_UNSUPPORTED_FAMILY 2
#define DROP_RECV_ARG_MISSED 3
#define DROP_TLS_BUFFER_RESERVE_FAILED 4
#define DROP_TLS_SERVER_HELLO_NO_STATS 5
#define DROP_UNSUPPORTED_V6 6
#define DROP_PACKET_EP_MISS 7
#define DROP_RETRANS_FLOW_MISS 8
#define DROP_DEGENERATE_KEY 9
// v1alpha7 aliasing diagnostics. Neither is an error: DIRECT_MISS counts the
// packets that had to fall back to the (ambiguous) local-endpoint index, and
// ALIAS_OVERWRITE counts index slots taken away from a still-live neighbour.
#define DROP_PACKET_DIRECT_MISS 10
#define DROP_LOCAL_EP_ALIAS_OVERWRITE 11
#define DROP_COUNTERS_LEN 12

#define FLOW_STATS_MAX_ENTRIES 65536
#define RECV_ARGS_MAX_ENTRIES 16384
#define EBPF_EMIT_INTERVAL_NS 5000000000ULL
#define CGROUP_SKB_PASS 1
#define TLS_CAPTURE_MAX_BYTES 2048

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};
#define PT_REGS_PARM1(ctx) ((void *)(ctx)->di)
#define PT_REGS_PARM3(ctx) ((ctx)->dx)
#define PT_REGS_RC(ctx) ((ctx)->ax)
#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
	unsigned long regs[31];
	unsigned long sp;
	unsigned long pc;
	unsigned long pstate;
};
#define PT_REGS_PARM1(ctx) ((void *)(ctx)->regs[0])
#define PT_REGS_PARM3(ctx) ((ctx)->regs[2])
#define PT_REGS_RC(ctx) ((ctx)->regs[0])
#else
#error "unsupported target arch"
#endif

struct in6_addr {
	__u8 s6_addr[16];
};

struct sock_common {
	union {
		struct {
			__u32 skc_daddr;
			__u32 skc_rcv_saddr;
		};
	};
	union {
		__u32 skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		struct {
			__u16 skc_dport;
			__u16 skc_num;
		};
	};
	unsigned short skc_family;
	struct {
		struct net *net;
	} skc_net;
	// v6 address fields; CO-RE resolves their real offsets by name from BTF,
	// so their position in this local struct copy does not matter.
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

// Socket-owned cgroup chain (CO-RE, field offsets resolved from kernel BTF by name):
// sk->sk_cgrp_data.cgroup->kn->id == the cgroup v2 id of the socket's OWNING pod.
struct kernfs_node {
	__u64 id;
} __attribute__((preserve_access_index));

struct cgroup {
	struct kernfs_node *kn;
} __attribute__((preserve_access_index));

struct sock_cgroup_data {
	struct cgroup *cgroup;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	struct sock_cgroup_data sk_cgrp_data;
} __attribute__((preserve_access_index));

// Minimal kernel sk_buff view for the tcp_retransmit_skb tracepoint. The len
// field offset is resolved by name from kernel BTF via CO-RE
// (preserve_access_index); no hard-coded offset is used.
struct sk_buff {
	unsigned int len;
} __attribute__((preserve_access_index));

struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
	struct ns_common ns;
} __attribute__((preserve_access_index));

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
};

struct ipv4_header {
	__u8 ihl_version;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
};

struct tcp_ports {
	__u16 source;
	__u16 dest;
};

struct flow_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u8 direction;
	__u16 _pad0;
};

struct flow_stats {
	__u64 start_ns;
	__u64 last_seen_ns;
	__u64 last_emit_ns;
	__u64 cgroup_id;
	__u64 netns_ino;
	__u64 bytes_sent;
	__u64 bytes_recv;
	__u64 packets_sent;
	__u64 packets_recv;
	__u64 pkt_size_buckets[7];
	__u64 iat_buckets[6];
	__u64 pkt_size_min;
	__u64 pkt_size_max;
	__u64 idle_gap_count;
	__u64 burst_count;
	__u64 real_packets_sent;
	__u64 real_packets_recv;
	__u64 last_packet_ns_sent;
	__u64 last_packet_ns_recv;
	// v1alpha3 P1: TCP/IP header aggregates observed at cgroup_skb. All are
	// cumulative over the flow_stats entry lifetime. "sent" = local egress,
	// "recv" = local ingress; NOT client/server. first/last_packet_ns_* stay
	// kernel-internal: only the derived per-direction duration is exported.
	__u64 first_packet_ns_sent;
	__u64 first_packet_ns_recv;
	// NetFlow-v2 edge histogram over ntohs(ip.tot_len), both directions:
	// <=128, 129-256, 257-512, 513-1024, 1025-1514, >1514 (overflow bucket,
	// mostly GSO/GRO aggregates; must never be folded into 1025-1514).
	__u64 nf_ip_size_buckets[6];
	// v1alpha3 P2: LOCAL-egress retransmissions from tracepoint
	// tcp/tcp_retransmit_skb, keyed by the pre-DNAT socket flow key. skb
	// granularity: one retransmitted skb may be a GSO aggregate of several
	// wire segments, so this is NOT a wire-packet count. Peer (dst->src)
	// retransmissions are NOT observable from this hook.
	__u64 retrans_skb_count;
	__u64 retrans_skb_bytes;
	// v1alpha5: per-direction split of the packet-size and IAT histograms.
	// "out" = local egress, "in" = local ingress (the SAME `ingress` argument
	// of update_packet_stats that selects real_packets_sent/recv); NOT
	// client/server. Bucket edges are the SAME packet_size_bucket() /
	// iat_bucket() functions as the mixed arrays above -- there is no second
	// bucket table.
	//
	// pkt_size_buckets_out/in: EXACT decomposition of pkt_size_buckets --
	// every packet is counted once into the mixed array and once into its
	// direction array from the same call site, so out[i] + in[i] ==
	// pkt_size_buckets[i] holds bucket by bucket. The mixed array is
	// deliberately NOT rewritten as a derived sum: keeping the two
	// accumulations independent is what makes that identity a real check
	// instead of a tautology.
	//
	// iat_buckets_out/in: ALSO an exact decomposition, and this is a property
	// of the implementation, not of IAT in general. The mixed iat_buckets
	// array never measured cross-direction interleaving: update_packet_stats
	// has always differenced against last_packet_ns_sent / last_packet_ns_recv,
	// i.e. the previous packet IN THE SAME DIRECTION, and added the result to
	// one shared array. Splitting the destination therefore reproduces the
	// mixed array exactly. Do not describe these as "a new quantity that must
	// not be summed" -- for THIS collector out + in == mixed, per bucket.
	__u64 pkt_size_buckets_out[7];
	__u64 pkt_size_buckets_in[7];
	__u64 iat_buckets_out[6];
	__u64 iat_buckets_in[6];
	__u32 syn_count;
	__u32 fin_count;
	__u32 rst_count;
	// v1alpha5: per-direction TCP flag PACKET counts, read from the raw TCP
	// flag byte at cgroup_skb (bit 0x02 SYN, 0x01 FIN, 0x04 RST) on the same
	// phase-B path and under the same collect_header_aggregates gate as
	// tcp_flags_or_sent/recv. These are per-PACKET counts and are a DIFFERENT
	// quantity from the legacy syn_count/fin_count above, which are
	// per-CONNECTION constants written by the inet_sock_set_state tracepoint
	// (syn_count=1 at ESTABLISHED, fin_count+=1 at TCP_CLOSE). A SYN
	// retransmission increments syn_count_out and never touches syn_count.
	//
	// COVERAGE (structural, v1alpha5): the packet path is reached only after
	// canonical_key_from_skb resolves local_ep_to_key, which is populated
	// exclusively when a connection reaches ESTABLISHED. A connection that is
	// refused (SYN -> RST) or never answered (SYN -> timeout) has no
	// flow_stats entry at all, so its packets are counted in
	// DROP_PACKET_EP_MISS and are attributed nowhere. rst_count_in therefore
	// observes resets on ESTABLISHED connections (server reset, idle-timeout
	// reset, abortive close) and NOT closed-port connection refusals.
	__u32 syn_count_out;
	__u32 syn_count_in;
	__u32 fin_count_out;
	__u32 fin_count_in;
	__u32 rst_count_out;
	__u32 rst_count_in;
	// CONCURRENCY: the min/max extrema below (ip_ttl_*, tcp_win_max_*,
	// ip_pkt_len_*, and pkt_size_min/max above) are updated with non-atomic
	// compare-then-store. Two CPUs racing on the same flow can each pass the
	// compare and the later store wins, so an extremum update can be lost.
	// They are concurrent BEST-EFFORT extrema, NOT exact — a strict CAS loop
	// per packet is not worth the hot-path cost. The flag OR-masks are exempt:
	// they use atomic fetch-or and are exact.
	//
	// COMPACTNESS: fields are sized to their wire domain (window and tot_len
	// are 16-bit header fields, TTL is 8-bit). The flag OR-masks alone stay
	// __u32: the BPF atomic fetch-or needs a 4-byte-aligned 32-bit operand,
	// and both sit at 4-aligned offsets by construction.
	// Bitwise OR of the raw TCP flag byte per direction, updated with 32-bit
	// atomic fetch-or (BPF ISA v3, -mcpu=v3) so a one-shot SYN/RST/FIN bit can
	// never be lost to a cross-CPU race. 0 with tcp_header_observed_* set is a
	// genuine all-zero flag byte (TCP NULL scan), not "unobserved".
	__u32 tcp_flags_or_sent;
	__u32 tcp_flags_or_recv;
	__u16 tcp_win_max_sent; // raw advertised window (ntohs), NOT scale-corrected
	__u16 tcp_win_max_recv;
	__u16 ip_pkt_len_min; // ntohs(ip.tot_len); 0 = never observed
	__u16 ip_pkt_len_max;
	__u8 ip_ttl_min; // 0 = never observed (TTL 0 is invalid on the wire)
	__u8 ip_ttl_max;
	// v1alpha5: same TTL envelope, split by direction. Identical rolling
	// semantics to the mixed pair above -- cumulative over the flow_stats
	// entry lifetime, NEVER reset per window -- and the same best-effort
	// concurrent-extremum caveat. 0 = that direction never observed a packet.
	__u8 ip_ttl_min_out;
	__u8 ip_ttl_max_out;
	__u8 ip_ttl_min_in;
	__u8 ip_ttl_max_in;
	__u8 close_seen;
	__u8 client_hello_inspected;
	__u8 server_hello_inspected;
	__u8 traffic_accounting_available;
	__u8 packet_timing_available;
	__u8 tcp_metrics_available;
	// Monotonic 0->1 per-direction witness that the TCP byte-12..15 header
	// load succeeded at least once. Set on read success ONLY — never inferred
	// from flag/window values, so flags==0 / window==0 segments still count as
	// observed. A plain store is race-free here: every writer stores the same
	// value and the flag never goes back to 0 while the entry lives.
	__u8 tcp_header_observed_sent;
	__u8 tcp_header_observed_recv;
	// v1alpha6: 0 while the connection has NOT yet reached ESTABLISHED. It
	// gates update_packet_stats' single pre-establishment write barrier, where
	// the ONLY fields allowed to move are the six directional flag counters.
	// Kernel-internal: deliberately NOT mirrored into struct flow_event, so
	// v1alpha6 adds no ledger field at all. Carved out of the existing tail
	// padding, so sizeof(struct flow_stats) is unchanged at 600 bytes.
	//
	// Set to 1 by: the TCP_ESTABLISHED branch, and ensure_stats() -- a socket
	// already doing sendmsg/recvmsg is established by construction, and that
	// path must keep its full v1alpha5 accounting even when the ESTABLISHED
	// tracepoint was missed.
	__u8 established;
	__u8 _pad1[5];
};

struct flow_event {
	__u64 timestamp_ns;
	__u32 event_type;
	__u32 pid;
	__u32 tgid;
	__u64 cgroup_id;
	__u64 netns_ino;
	__u16 family;
	__u8 protocol;
	__u8 _pad1;
	__u32 src_ipv4;
	__u32 dst_ipv4;
	__u16 src_port;
	__u16 dst_port;
	__u64 bytes_sent;
	__u64 bytes_recv;
	__u64 packets_sent;
	__u64 packets_recv;
	__u64 pkt_size_buckets[7];
	__u64 iat_buckets[6];
	__u64 pkt_size_min;
	__u64 pkt_size_max;
	__u64 idle_gap_count;
	__u64 burst_count;
	__u64 real_packets_sent;
	__u64 real_packets_recv;
	// v1alpha3 P1 additions; must stay in sync with rawEBPFEvent in
	// pkg/collector/ebpf_event.go. Durations are derived from the
	// kernel-internal first/last packet timestamps at emit time.
	__u64 direction_duration_ns_sent;
	__u64 direction_duration_ns_recv;
	__u64 nf_ip_size_buckets[6];
	__u64 retrans_skb_count;
	__u64 retrans_skb_bytes;
	// v1alpha5 per-direction additions; must stay in sync with rawEBPFEvent
	// in pkg/collector/ebpf_event.go (TestRawEBPFEventLayoutMatchesBTF is the
	// authoritative check). See the flow_stats comments for semantics: the
	// two histogram pairs are EXACT decompositions of the mixed arrays, the
	// *_count_out/in are per-PACKET flag counts (not the per-connection
	// syn_count/fin_count), and the TTL pairs are lifetime envelopes.
	__u64 pkt_size_buckets_out[7];
	__u64 pkt_size_buckets_in[7];
	__u64 iat_buckets_out[6];
	__u64 iat_buckets_in[6];
	__u32 syn_count;
	__u32 fin_count;
	__u32 rst_count;
	__u32 syn_count_out;
	__u32 syn_count_in;
	__u32 fin_count_out;
	__u32 fin_count_in;
	__u32 rst_count_out;
	__u32 rst_count_in;
	// Same compactness/alignment rules as flow_stats: flags stay __u32 for
	// the atomic OR source field they mirror; window/tot_len are 16-bit wire
	// fields, TTL is 8-bit.
	__u32 tcp_flags_or_sent;
	__u32 tcp_flags_or_recv;
	__u16 tcp_win_max_sent;
	__u16 tcp_win_max_recv;
	__u16 ip_pkt_len_min;
	__u16 ip_pkt_len_max;
	__u8 ip_ttl_min;
	__u8 ip_ttl_max;
	__u8 ip_ttl_min_out;
	__u8 ip_ttl_max_out;
	__u8 ip_ttl_min_in;
	__u8 ip_ttl_max_in;
	__u8 traffic_accounting_available;
	__u8 packet_timing_available;
	__u8 tcp_metrics_available;
	__u8 tcp_header_observed_sent;
	__u8 tcp_header_observed_recv;
	__u8 _pad2[9];
};

struct trace_event_raw_inet_sock_set_state {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__u32 common_pid;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u32 saddr;
	__u32 daddr;
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

// tracepoint tcp/tcp_retransmit_skb: only the leading skbaddr/skaddr pointers
// (stable at offsets 8/16 since the tracepoint was introduced in 4.15) are
// declared; the record tail (state/ports/addrs) varies across kernel versions
// and is deliberately not referenced.
struct trace_event_raw_tcp_event_sk_skb {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__u32 common_pid;
	const void *skbaddr;
	const void *skaddr;
};

struct flow_config {
	__u8 tls_handshake_inspect_enabled;
	// v1alpha3 hot-path gates. When 0 the BPF program itself skips the
	// corresponding flow_stats updates — and, for header aggregates, the
	// phase-B TCP byte-12..15 load — so disabling a feature is never just
	// Go-side field nulling. Must stay in sync with bpfFlowConfig in
	// pkg/collector/ebpf_collector_linux.go.
	__u8 collect_header_aggregates;   // TTL/flags/window/IP-length envelopes
	__u8 collect_netflow_v2_histogram; // NetFlow-v2 IP-size histogram
	__u8 _pad[5];
};

struct tls_handshake_event {
	struct flow_key key;
	__u64 timestamp_ns;
	__u32 payload_len;
	__u32 captured_len;
	__u8 data[TLS_CAPTURE_MAX_BYTES];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} tls_handshake_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct flow_config);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FLOW_STATS_MAX_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct flow_stats);
} flow_stats_map SEC(".maps");

// Scratch space for the flow_stats initializer. struct flow_stats outgrew the
// 512-byte BPF stack in v1alpha5 (the per-direction histograms alone are 208
// bytes), so the zero-filled template is built in a per-CPU array instead of
// on the stack. Per-CPU means no cross-CPU sharing and no locking is needed;
// each user memsets it before filling and copies it into flow_stats_map in the
// same call, so nothing is ever read back from here. Entry-creation paths only
// (connection establishment / first syscall on an unindexed flow) -- never the
// per-packet path.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct flow_stats);
} flow_stats_init_scratch SEC(".maps");

// DNAT-invariant local-endpoint index: maps a connection's local endpoint
// (local IP + local port) to the canonical socket-side flow_key stored in
// flow_stats_map. The socket paths (kprobe/tracepoint) key by the pre-DNAT
// tuple (e.g. Service ClusterIP as dst), but cgroup_skb egress sees the
// post-kube-proxy-DNAT tuple (backend Pod IP as dst), so a direct tuple match
// misses and packet-size/IAT stats never merge (only ~25% of flows populated).
// kube-proxy DNAT rewrites only the destination, so the local endpoint is
// identical in both views; key_from_skb already normalizes the local side into
// key.src for both directions. The cgroup_skb hooks resolve their local
// endpoint to the canonical key through this map, so packet stats land on the
// same flow_stats entry the accounting hooks created.
struct local_ep {
	__u32 ip;
	__u16 port;
	__u16 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FLOW_STATS_MAX_ENTRIES);
	__type(key, struct local_ep);
	__type(value, struct flow_key);
} local_ep_to_key SEC(".maps");

// Dedicated ingress ServerHello dedup keyed by the post-NAT flow tuple.
// flow_stats_map is intentionally not reused because egress accounting may be
// keyed by the Service ClusterIP while ingress ServerHello is keyed by the
// backend Pod IP. LRU eviction can allow a duplicate ServerHello on very
// long-lived flows, which is acceptable for rare renegotiation/reused 5-tuples.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, __u8);
} tls_server_hello_seen_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, RECV_ARGS_MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct flow_key);
} recv_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DROP_COUNTERS_LEN);
	__type(key, __u32);
	__type(value, __u64);
} drop_counters SEC(".maps");

static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static __u64 (*bpf_skb_cgroup_id)(struct __sk_buff *skb) = (void *)79;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

static __u16 bpf_ntohs(__u16 v)
{
	return __builtin_bswap16(v);
}

// Extract the embedded IPv4 from an IPv4-mapped IPv6 address (::ffff:a.b.c.d).
// Dual-stack sockets (Python/grpcio, JVM, Node, ...) carry IPv4 traffic over an
// AF_INET6 socket using this mapping while the wire packets remain IPv4. On
// success writes the network-order IPv4 into *out_ip and returns 0; returns -1
// for a genuine (non-mapped) IPv6 address.
static int v4_from_mapped(const __u8 addr[16], __u32 *out_ip)
{
	if (addr[10] != 0xff || addr[11] != 0xff)
		return -1;
	__builtin_memcpy(out_ip, &addr[12], 4);
	return 0;
}

static void increment_drop(__u32 idx)
{
	__u64 *counter;

	counter = bpf_map_lookup_elem(&drop_counters, &idx);
	if (counter)
		__sync_fetch_and_add(counter, 1);
}

static struct flow_config *get_flow_config(void)
{
	__u32 idx = 0;

	return bpf_map_lookup_elem(&config_map, &idx);
}

static int tls_inspect_enabled(void)
{
	struct flow_config *cfg = get_flow_config();

	return cfg && cfg->tls_handshake_inspect_enabled;
}

static int key_from_sock(struct sock *sk, struct flow_key *key, __u8 direction)
{
	__u16 family = 0;
	__u16 dport = 0;

	if (!sk)
		return -1;

	bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

	__builtin_memset(key, 0, sizeof(*key));
	if (family == AF_INET) {
		bpf_probe_read_kernel(&key->src_ip, sizeof(key->src_ip), &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&key->dst_ip, sizeof(key->dst_ip), &sk->__sk_common.skc_daddr);
	} else if (family == AF_INET6) {
		__u8 saddr6[16] = {};
		__u8 daddr6[16] = {};

		bpf_probe_read_kernel(&saddr6, sizeof(saddr6), &sk->__sk_common.skc_v6_rcv_saddr);
		bpf_probe_read_kernel(&daddr6, sizeof(daddr6), &sk->__sk_common.skc_v6_daddr);
		if (v4_from_mapped(saddr6, &key->src_ip) != 0 ||
		    v4_from_mapped(daddr6, &key->dst_ip) != 0) {
			increment_drop(DROP_UNSUPPORTED_V6);
			return -1;
		}
	} else {
		increment_drop(DROP_UNSUPPORTED_FAMILY);
		return -1;
	}
	bpf_probe_read_kernel(&key->src_port, sizeof(key->src_port), &sk->__sk_common.skc_num);
	bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
	key->dst_port = bpf_ntohs(dport);
	// Degenerate-key guard: a socket doing sendmsg/recvmsg before the kernel has
	// assigned its source port (e.g. connect-during-sendmsg paths) yields skc_num==0.
	// Such a key can never be matched by the state/skb hooks (they see the real port),
	// so the entry would leak until session timeout. Reject at the single choke point.
	if (key->src_port == 0 || key->dst_port == 0) {
		increment_drop(DROP_DEGENERATE_KEY);
		return -1;
	}
	key->protocol = IPPROTO_TCP;
	key->direction = direction;
	return 0;
}

static __u64 netns_ino_from_sock(struct sock *sk)
{
	struct net *net = 0;
	unsigned int inum = 0;

	if (!sk)
		return 0;
	// CO-RE field access assumes kernels expose sock_common.skc_net.net and net.ns.inum in BTF.
	bpf_probe_read_kernel(&net, sizeof(net), &sk->__sk_common.skc_net.net);
	if (net)
		bpf_probe_read_kernel(&inum, sizeof(inum), &net->ns.inum);
	return inum;
}

// Socket-owned cgroup id: correct even when the hook fires in softirq (e.g. TCP_ESTABLISHED on
// SYN-ACK receipt for an active connector), where bpf_get_current_cgroup_id() would return an
// arbitrary co-located task's cgroup. Returns 0 for host-network / unowned sockets (caller falls back).
static __u64 sk_cgroup_id(struct sock *sk)
{
	struct cgroup *cgrp = 0;
	struct kernfs_node *kn = 0;
	__u64 id = 0;

	if (!sk)
		return 0;
	bpf_probe_read_kernel(&cgrp, sizeof(cgrp), &sk->sk_cgrp_data.cgroup);
	if (!cgrp)
		return 0;
	bpf_probe_read_kernel(&kn, sizeof(kn), &cgrp->kn);
	if (!kn)
		return 0;
	bpf_probe_read_kernel(&id, sizeof(id), &kn->id);
	return id;
}

static void fill_event_fields(struct flow_event *event, struct flow_key *key, struct flow_stats *stats, __u32 event_type, __u64 now)
{
	int i;

	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = now;
	event->event_type = event_type;
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->family = AF_INET;
	event->protocol = IPPROTO_TCP;
	event->src_ipv4 = key->src_ip;
	event->dst_ipv4 = key->dst_ip;
	event->src_port = key->src_port;
	event->dst_port = key->dst_port;
	if (stats) {
		event->cgroup_id = stats->cgroup_id;
		event->bytes_sent = stats->bytes_sent;
		event->bytes_recv = stats->bytes_recv;
		event->packets_sent = stats->packets_sent;
		event->packets_recv = stats->packets_recv;
#pragma unroll
		for (i = 0; i < 7; i++)
			event->pkt_size_buckets[i] = stats->pkt_size_buckets[i];
#pragma unroll
		for (i = 0; i < 6; i++)
			event->iat_buckets[i] = stats->iat_buckets[i];
		event->pkt_size_min = stats->pkt_size_min;
		event->pkt_size_max = stats->pkt_size_max;
		event->idle_gap_count = stats->idle_gap_count;
		event->burst_count = stats->burst_count;
		event->real_packets_sent = stats->real_packets_sent;
		event->real_packets_recv = stats->real_packets_recv;
		// first/last packet timestamps are kernel-internal; only the derived
		// per-direction active span leaves the kernel.
		if (stats->first_packet_ns_sent != 0 && stats->last_packet_ns_sent >= stats->first_packet_ns_sent)
			event->direction_duration_ns_sent = stats->last_packet_ns_sent - stats->first_packet_ns_sent;
		if (stats->first_packet_ns_recv != 0 && stats->last_packet_ns_recv >= stats->first_packet_ns_recv)
			event->direction_duration_ns_recv = stats->last_packet_ns_recv - stats->first_packet_ns_recv;
#pragma unroll
		for (i = 0; i < 6; i++)
			event->nf_ip_size_buckets[i] = stats->nf_ip_size_buckets[i];
#pragma unroll
		for (i = 0; i < 7; i++) {
			event->pkt_size_buckets_out[i] = stats->pkt_size_buckets_out[i];
			event->pkt_size_buckets_in[i] = stats->pkt_size_buckets_in[i];
		}
#pragma unroll
		for (i = 0; i < 6; i++) {
			event->iat_buckets_out[i] = stats->iat_buckets_out[i];
			event->iat_buckets_in[i] = stats->iat_buckets_in[i];
		}
		event->syn_count_out = stats->syn_count_out;
		event->syn_count_in = stats->syn_count_in;
		event->fin_count_out = stats->fin_count_out;
		event->fin_count_in = stats->fin_count_in;
		event->rst_count_out = stats->rst_count_out;
		event->rst_count_in = stats->rst_count_in;
		event->ip_ttl_min_out = stats->ip_ttl_min_out;
		event->ip_ttl_max_out = stats->ip_ttl_max_out;
		event->ip_ttl_min_in = stats->ip_ttl_min_in;
		event->ip_ttl_max_in = stats->ip_ttl_max_in;
		event->ip_ttl_min = stats->ip_ttl_min;
		event->ip_ttl_max = stats->ip_ttl_max;
		event->tcp_flags_or_sent = stats->tcp_flags_or_sent;
		event->tcp_flags_or_recv = stats->tcp_flags_or_recv;
		event->tcp_header_observed_sent = stats->tcp_header_observed_sent;
		event->tcp_header_observed_recv = stats->tcp_header_observed_recv;
		event->tcp_win_max_sent = stats->tcp_win_max_sent;
		event->tcp_win_max_recv = stats->tcp_win_max_recv;
		event->retrans_skb_count = stats->retrans_skb_count;
		event->retrans_skb_bytes = stats->retrans_skb_bytes;
		event->ip_pkt_len_min = stats->ip_pkt_len_min;
		event->ip_pkt_len_max = stats->ip_pkt_len_max;
		event->syn_count = stats->syn_count;
		event->fin_count = stats->fin_count;
		event->rst_count = stats->rst_count;
		event->traffic_accounting_available = stats->traffic_accounting_available;
		event->packet_timing_available = stats->packet_timing_available;
		event->tcp_metrics_available = stats->tcp_metrics_available;
	}
}

static void fill_event(struct flow_event *event, struct flow_key *key, struct flow_stats *stats, __u32 event_type, __u64 now, __u64 netns_ino)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	fill_event_fields(event, key, stats, event_type, now);
	event->netns_ino = netns_ino;
	event->pid = (__u32)pid_tgid;
	event->tgid = (__u32)(pid_tgid >> 32);
}

static int emit_flow_event(struct flow_key *key, struct flow_stats *stats, __u32 event_type, __u64 now, __u64 netns_ino)
{
	struct flow_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		increment_drop(DROP_RINGBUF_RESERVE_FAILED);
		return -1;
	}
	fill_event(event, key, stats, event_type, now, netns_ino);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static int emit_flow_event_no_pid(struct flow_key *key, struct flow_stats *stats, __u32 event_type, __u64 now, __u64 netns_ino)
{
	struct flow_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		increment_drop(DROP_RINGBUF_RESERVE_FAILED);
		return -1;
	}
	fill_event_fields(event, key, stats, event_type, now);
	event->netns_ino = netns_ino;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

// Record the connection's local endpoint -> canonical flow_key mapping so the
// cgroup_skb packet hooks can find this entry despite kube-proxy DNAT rewriting
// the destination on the wire. Idempotent; safe to call on every create.
static void index_local_ep(struct flow_key *key)
{
	struct local_ep ep = {};
	struct flow_key *prev;

	ep.ip = key->src_ip;
	ep.port = key->src_port;
	// v1alpha7 diagnostic. BPF_ANY overwrites a slot a live neighbour owns and
	// returns SUCCESS -- which is why this aliasing ran for weeks with
	// map_update_failed pinned at 0. Count it, so the ambiguity is observable
	// for as long as the index survives as a fallback. Entry-creation path
	// only, never per-packet.
	prev = bpf_map_lookup_elem(&local_ep_to_key, &ep);
	if (prev && (prev->dst_ip != key->dst_ip || prev->dst_port != key->dst_port))
		increment_drop(DROP_LOCAL_EP_ALIAS_OVERWRITE);
	if (bpf_map_update_elem(&local_ep_to_key, &ep, key, BPF_ANY) != 0)
		increment_drop(DROP_MAP_UPDATE_FAILED);
}

// Return this CPU's zeroed flow_stats template (see flow_stats_init_scratch).
// The returned pointer is scratch: fill it and hand it to bpf_map_update_elem
// in the same call path; it is never a live flow's stats.
static struct flow_stats *zeroed_stats_template(void)
{
	__u32 zero = 0;
	struct flow_stats *init;

	init = bpf_map_lookup_elem(&flow_stats_init_scratch, &zero);
	if (!init)
		return 0;
	__builtin_memset(init, 0, sizeof(*init));
	return init;
}

static struct flow_stats *ensure_stats(struct flow_key *key, __u64 now)
{
	struct flow_stats *init;
	struct flow_stats *stats;

	stats = bpf_map_lookup_elem(&flow_stats_map, key);
	if (stats)
		return stats;

	init = zeroed_stats_template();
	if (!init) {
		increment_drop(DROP_MAP_UPDATE_FAILED);
		return 0;
	}
	init->start_ns = now;
	init->last_seen_ns = now;
	init->last_emit_ns = now;
	init->cgroup_id = bpf_get_current_cgroup_id();
	// This path is only reached from tcp_sendmsg/tcp_recvmsg, i.e. a socket
	// that is already carrying data. Marking it established keeps the
	// v1alpha6 write barrier from silently muting a flow whose ESTABLISHED
	// tracepoint we never saw -- its accounting must stay exactly v1alpha5.
	init->established = 1;
	if (bpf_map_update_elem(&flow_stats_map, key, init, BPF_ANY) != 0) {
		increment_drop(DROP_MAP_UPDATE_FAILED);
		return 0;
	}
	index_local_ep(key);
	return bpf_map_lookup_elem(&flow_stats_map, key);
}

static void update_sent(struct flow_key *key, __u64 bytes, __u64 now, __u64 netns_ino)
{
	struct flow_stats *stats;

	if (bytes == 0)
		return;
	stats = ensure_stats(key, now);
	if (!stats)
		return;

	if (stats->cgroup_id == 0)
		stats->cgroup_id = bpf_get_current_cgroup_id();
	if (stats->netns_ino == 0)
		stats->netns_ino = netns_ino;
	__sync_fetch_and_add(&stats->bytes_sent, bytes);
	__sync_fetch_and_add(&stats->packets_sent, 1);
	stats->last_seen_ns = now;
	stats->traffic_accounting_available = 1;
	if (now - stats->last_emit_ns >= EBPF_EMIT_INTERVAL_NS) {
		emit_flow_event(key, stats, EVENT_STATS, now, stats->netns_ino);
		stats->last_emit_ns = now;
	}
}

static void update_recv(struct flow_key *key, __u64 bytes, __u64 now, __u64 netns_ino)
{
	struct flow_stats *stats;

	if (bytes == 0)
		return;
	stats = ensure_stats(key, now);
	if (!stats)
		return;

	if (stats->cgroup_id == 0)
		stats->cgroup_id = bpf_get_current_cgroup_id();
	if (netns_ino != 0 && stats->netns_ino == 0)
		stats->netns_ino = netns_ino;
	__sync_fetch_and_add(&stats->bytes_recv, bytes);
	__sync_fetch_and_add(&stats->packets_recv, 1);
	stats->last_seen_ns = now;
	stats->traffic_accounting_available = 1;
	if (now - stats->last_emit_ns >= EBPF_EMIT_INTERVAL_NS) {
		emit_flow_event(key, stats, EVENT_STATS, now, stats->netns_ino);
		stats->last_emit_ns = now;
	}
}

static int packet_size_bucket(__u64 size)
{
	if (size <= 63)
		return 0;
	if (size <= 127)
		return 1;
	if (size <= 255)
		return 2;
	if (size <= 511)
		return 3;
	if (size <= 1023)
		return 4;
	if (size <= 1500)
		return 5;
	return 6;
}

// NetFlow-v2 edge buckets over ntohs(ip.tot_len). Bucket edges MUST stay in
// sync with features.NetFlowV2IPSizeBucket (pkg/features/features.go), which
// is the unit-tested Go mirror of this function.
static int nf_ip_size_bucket(__u16 tot_len)
{
	if (tot_len <= 128)
		return 0;
	if (tot_len <= 256)
		return 1;
	if (tot_len <= 512)
		return 2;
	if (tot_len <= 1024)
		return 3;
	if (tot_len <= 1514)
		return 4;
	return 5;
}

static int iat_bucket(__u64 iat_us)
{
	if (iat_us < 100)
		return 0;
	if (iat_us <= 1000)
		return 1;
	if (iat_us <= 10000)
		return 2;
	if (iat_us <= 100000)
		return 3;
	if (iat_us <= 1000000)
		return 4;
	return 5;
}

// Phase-A packet metadata, filled by key_from_skb exclusively from bytes it
// already loads for key construction (the IPv4 header and TCP ports): TTL and
// tot_len come for free from the IPv4 header, tcp_hdr_off records where the
// TCP header starts (IHL in bytes). The TCP byte-12..15 load (flags/window)
// deliberately does NOT happen here: it is phase-B work, done in
// update_packet_stats only after the canonical local_ep_to_key lookup hit, so
// packet_ep_miss traffic never pays that extra helper call.
// ip_tot_len is converted to host byte order; ip_tot_len==0 means the header
// carried an implausible total length (< 20) and IP-length stats are skipped.
struct skb_pkt_meta {
	__u16 ip_tot_len;
	__u16 tcp_hdr_off;
	__u8 ip_ttl;
	__u8 _pad[3];
};

// Raw TCP header bytes 12..15: data-offset/reserved byte, flag byte, and the
// advertised window (network byte order). Loaded only on the phase-B path.
struct tcp_flags_window {
	__u8 doff_res;
	__u8 flags;
	__u16 window;
};

static int key_from_skb(struct __sk_buff *skb, struct flow_key *key, int ingress, struct skb_pkt_meta *meta)
{
	struct ipv4_header ip = {};
	struct tcp_ports ports = {};
	__u16 tot_len;
	__u32 ihl_bytes;

	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) != 0)
		return -1;
	if ((ip.ihl_version >> 4) != 4) {
		increment_drop(DROP_UNSUPPORTED_FAMILY);
		return -1;
	}
	if (ip.protocol != IPPROTO_TCP) {
		increment_drop(DROP_UNSUPPORTED_FAMILY);
		return -1;
	}

	ihl_bytes = (ip.ihl_version & 0x0f) * 4;
	if (ihl_bytes < sizeof(ip))
		return -1;
	if (bpf_skb_load_bytes(skb, ihl_bytes, &ports, sizeof(ports)) != 0)
		return -1;
	if (meta) {
		__builtin_memset(meta, 0, sizeof(*meta));
		meta->ip_ttl = ip.ttl;
		meta->tcp_hdr_off = ihl_bytes;
		// ip.tot_len is network byte order on the wire.
		tot_len = bpf_ntohs(ip.tot_len);
		if (tot_len >= sizeof(ip))
			meta->ip_tot_len = tot_len;
	}

	__builtin_memset(key, 0, sizeof(*key));
	if (ingress) {
		// Ingress packets are normalized back to the same client-to-server
		// orientation used by egress, so both handshake directions share one flow_stats entry.
		key->src_ip = ip.daddr;
		key->dst_ip = ip.saddr;
		key->src_port = bpf_ntohs(ports.dest);
		key->dst_port = bpf_ntohs(ports.source);
	} else {
		key->src_ip = ip.saddr;
		key->dst_ip = ip.daddr;
		key->src_port = bpf_ntohs(ports.source);
		key->dst_port = bpf_ntohs(ports.dest);
	}
	key->protocol = IPPROTO_TCP;
	key->direction = DIRECTION_UNKNOWN;
	return 0;
}

static int tcp_payload_meta(struct __sk_buff *skb, __u32 *payload_offset, __u32 *payload_len)
{
	struct ipv4_header ip = {};
	__u8 tcp_off_res = 0;
	__u32 ihl_bytes;
	__u32 tcp_header_len;
	__u32 offset;

	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) != 0)
		return -1;
	if ((ip.ihl_version >> 4) != 4 || ip.protocol != IPPROTO_TCP)
		return -1;

	ihl_bytes = (ip.ihl_version & 0x0f) * 4;
	if (ihl_bytes < sizeof(ip))
		return -1;
	if (bpf_skb_load_bytes(skb, ihl_bytes + 12, &tcp_off_res, sizeof(tcp_off_res)) != 0)
		return -1;
	tcp_header_len = (tcp_off_res >> 4) * 4;
	if (tcp_header_len < 20)
		return -1;

	offset = ihl_bytes + tcp_header_len;
	if (skb->len <= offset) {
		*payload_offset = offset;
		*payload_len = 0;
		return 0;
	}
	*payload_offset = offset;
	*payload_len = skb->len - offset;
	return 0;
}

static void capture_tls_payload(struct __sk_buff *skb, struct tls_handshake_event *event, __u32 payload_offset, __u32 payload_len)
{
	__u32 limit = payload_len;
	__u32 i;

	if (limit > TLS_CAPTURE_MAX_BYTES)
		limit = TLS_CAPTURE_MAX_BYTES;
#pragma clang loop unroll(disable)
	for (i = 0; i < TLS_CAPTURE_MAX_BYTES; i++) {
		if (i >= limit)
			break;
		if (bpf_skb_load_bytes(skb, payload_offset + i, &event->data[i], 1) != 0)
			break;
		event->captured_len = i + 1;
	}
}

static void maybe_emit_tls_handshake(struct __sk_buff *skb, struct flow_key *key, struct flow_stats *stats, __u8 direction, __u8 expected_type)
{
	struct tls_handshake_event *event;
	__u8 *client_inspected = 0;
	__u8 *server_seen = 0;
	__u8 one = 1;
	__u32 payload_offset = 0;
	__u32 payload_len = 0;
	__u8 first = 0;
	__u8 handshake_type = 0;

	if (!tls_inspect_enabled())
		return;
	if (direction == DIRECTION_SEND) {
		if (!stats)
			return;
		client_inspected = &stats->client_hello_inspected;
		if (*client_inspected)
			return;
	} else if (direction == DIRECTION_RECV) {
		if (!stats)
			increment_drop(DROP_TLS_SERVER_HELLO_NO_STATS);
		server_seen = bpf_map_lookup_elem(&tls_server_hello_seen_map, key);
		if (server_seen && *server_seen)
			return;
	} else {
		return;
	}
	if (tcp_payload_meta(skb, &payload_offset, &payload_len) != 0)
		return;
	if (payload_len == 0)
		return;

	if (bpf_skb_load_bytes(skb, payload_offset, &first, sizeof(first)) != 0)
		return;
	if (first != 0x16) {
		if (direction == DIRECTION_SEND)
			*client_inspected = 1;
		else if (bpf_map_update_elem(&tls_server_hello_seen_map, key, &one, BPF_ANY) != 0)
			increment_drop(DROP_MAP_UPDATE_FAILED);
		return;
	}

	if (payload_len >= 6) {
		if (bpf_skb_load_bytes(skb, payload_offset + 5, &handshake_type, sizeof(handshake_type)) != 0)
			return;
		if (handshake_type != expected_type) {
			if (direction == DIRECTION_SEND)
				*client_inspected = 1;
			else if (bpf_map_update_elem(&tls_server_hello_seen_map, key, &one, BPF_ANY) != 0)
				increment_drop(DROP_MAP_UPDATE_FAILED);
			return;
		}
	}

	event = bpf_ringbuf_reserve(&tls_handshake_events, sizeof(*event), 0);
	if (direction == DIRECTION_SEND)
		*client_inspected = 1;
	if (!event) {
		increment_drop(DROP_TLS_BUFFER_RESERVE_FAILED);
		return;
	}

	event->key = *key;
	event->key.direction = direction;
	event->timestamp_ns = bpf_ktime_get_ns();
	event->payload_len = payload_len;
	event->captured_len = 0;
	capture_tls_payload(skb, event, payload_offset, payload_len);
	if (direction == DIRECTION_RECV) {
		if (bpf_map_update_elem(&tls_server_hello_seen_map, key, &one, BPF_ANY) != 0)
			increment_drop(DROP_MAP_UPDATE_FAILED);
	}
	bpf_ringbuf_submit(event, 0);
}

// NOTE: BPF-to-BPF calls pass at most 5 register arguments, so `now` is taken
// inside the function body instead of being a sixth parameter.
static void update_packet_stats(struct __sk_buff *skb, struct flow_key *key, __u64 packet_len, int ingress, struct skb_pkt_meta *meta)
{
	struct flow_stats *stats;
	__u64 *last_packet_ns;
	__u64 *first_packet_ns;
	__u64 now = bpf_ktime_get_ns();
	__u64 cgroup_id;
	__u64 iat_us;
	struct flow_config *cfg;
	struct tcp_flags_window tcpfw = {};
	int tcp_hdr_ok = 0;
	__u16 win;
	int pkt_bucket;
	int nf_idx;
	int iat_idx;
	// v1alpha5 per-direction destinations. See the single split below.
	__u64 *dir_pkt_buckets;
	__u64 *dir_iat_buckets;
	__u32 *dir_syn_count;
	__u32 *dir_fin_count;
	__u32 *dir_rst_count;
	__u8 *dir_ttl_min;
	__u8 *dir_ttl_max;

	stats = bpf_map_lookup_elem(&flow_stats_map, key);
	if (!stats)
		return;

	// ------------------------------------------------------------------
	// THE direction split. This is the ONLY place in the collector where a
	// v1alpha5 per-direction field is selected, and it branches on the very
	// same `ingress` argument that selects real_packets_sent/recv further
	// down (exported as observed_skb_packets_out/in). Every v1alpha5 write
	// below goes through these pointers, so the whole feature has ONE
	// direction predicate -- the function's own `ingress` parameter -- and no
	// way for a new field to disagree with the skb packet counts about what
	// "out" and "in" mean. (`ingress` is tested in two places in this
	// function: here, and in the pre-existing real_packets_*/last_packet_ns_*
	// block below, which v1alpha5 deliberately does not touch.)
	// ------------------------------------------------------------------
	if (ingress) {
		dir_pkt_buckets = stats->pkt_size_buckets_in;
		dir_iat_buckets = stats->iat_buckets_in;
		dir_syn_count = &stats->syn_count_in;
		dir_fin_count = &stats->fin_count_in;
		dir_rst_count = &stats->rst_count_in;
		dir_ttl_min = &stats->ip_ttl_min_in;
		dir_ttl_max = &stats->ip_ttl_max_in;
	} else {
		dir_pkt_buckets = stats->pkt_size_buckets_out;
		dir_iat_buckets = stats->iat_buckets_out;
		dir_syn_count = &stats->syn_count_out;
		dir_fin_count = &stats->fin_count_out;
		dir_rst_count = &stats->rst_count_out;
		dir_ttl_min = &stats->ip_ttl_min_out;
		dir_ttl_max = &stats->ip_ttl_max_out;
	}

	// ------------------------------------------------------------------
	// Phase B, hoisted above the v1alpha6 barrier. The TCP byte-12..15 load
	// is unchanged and still happens at most once per packet; only its
	// position moved, because the flag COUNTS it feeds are the one field
	// family allowed to move before the connection is established. Everything
	// else this load supplies (the flag OR-masks, the header-observed
	// witness, the window maximum) stays below the barrier and is therefore
	// still written only for established flows, exactly as in v1alpha5.
	// ------------------------------------------------------------------
	cfg = get_flow_config();
	if (meta && cfg && cfg->collect_header_aggregates && meta->tcp_hdr_off != 0 &&
	    bpf_skb_load_bytes(skb, meta->tcp_hdr_off + 12, &tcpfw, sizeof(tcpfw)) == 0) {
		tcp_hdr_ok = 1;
		// v1alpha5 semantics, unchanged: counts of PACKETS BEARING each flag,
		// per direction, atomically so a one-shot SYN/RST can never be lost
		// to a cross-CPU race. A packet carrying several flags increments
		// each corresponding counter.
		if (tcpfw.flags & TCP_FLAG_SYN)
			__sync_fetch_and_add(dir_syn_count, 1);
		if (tcpfw.flags & TCP_FLAG_FIN)
			__sync_fetch_and_add(dir_fin_count, 1);
		if (tcpfw.flags & TCP_FLAG_RST)
			__sync_fetch_and_add(dir_rst_count, 1);
	}

	// ==================================================================
	// v1alpha6 PRE-ESTABLISHMENT WRITE BARRIER -- the single short-circuit.
	//
	// Above this line: the six directional flag counters, and nothing else.
	// Below this line: every other field, reached only once the connection
	// has reached ESTABLISHED (or was adopted mid-flight by ensure_stats).
	//
	// This is what makes v1alpha6 "A-double-prime": a refused or unanswered
	// connect now leaves flag evidence on its session_summary row, while
	// every other field on every row -- successful or failed -- keeps exactly
	// the value v1alpha5 would have produced. Anything that needs to run for
	// a not-yet-established flow MUST be placed above this barrier, and
	// placing anything else there breaks that guarantee.
	// ==================================================================
	if (!stats->established)
		return;

	if (stats->cgroup_id == 0) {
		cgroup_id = bpf_skb_cgroup_id(skb);
		if (cgroup_id == 0)
			cgroup_id = bpf_get_current_cgroup_id();
		stats->cgroup_id = cgroup_id;
	}

	pkt_bucket = packet_size_bucket(packet_len);
	if (pkt_bucket >= 0 && pkt_bucket < 7) {
		__sync_fetch_and_add(&stats->pkt_size_buckets[pkt_bucket], 1);
		// Same packet, same bucket index, same call site: this is what makes
		// out[i] + in[i] == pkt_size_buckets[i] an exact identity.
		__sync_fetch_and_add(&dir_pkt_buckets[pkt_bucket], 1);
	}
	// flow_pkt_len (pkt_size_min/max) keeps its skb->len semantics.
	if (stats->pkt_size_min == 0 || packet_len < stats->pkt_size_min)
		stats->pkt_size_min = packet_len;
	if (packet_len > stats->pkt_size_max)
		stats->pkt_size_max = packet_len;

	// Phase B: this point is reached only for canonical-key hits (the caller
	// resolved local_ep_to_key and the flow_stats lookup above succeeded), so
	// everything below — including the only TCP byte-12..15 load — is never
	// paid by packet_ep_miss traffic. The config gates skip the updates in
	// the BPF program itself; a disabled feature is never just Go-side
	// nulling.
	if (meta && cfg && cfg->collect_header_aggregates) {
		// TTL / IP-length envelopes reuse phase-A bytes (no extra loads).
		if (meta->ip_ttl != 0) {
			if (stats->ip_ttl_min == 0 || meta->ip_ttl < stats->ip_ttl_min)
				stats->ip_ttl_min = meta->ip_ttl;
			if (meta->ip_ttl > stats->ip_ttl_max)
				stats->ip_ttl_max = meta->ip_ttl;
			// v1alpha5: identical rule, per direction. Same best-effort
			// concurrent-extremum caveat as the mixed pair.
			if (*dir_ttl_min == 0 || meta->ip_ttl < *dir_ttl_min)
				*dir_ttl_min = meta->ip_ttl;
			if (meta->ip_ttl > *dir_ttl_max)
				*dir_ttl_max = meta->ip_ttl;
		}
		if (meta->ip_tot_len != 0) {
			if (stats->ip_pkt_len_min == 0 || meta->ip_tot_len < stats->ip_pkt_len_min)
				stats->ip_pkt_len_min = meta->ip_tot_len;
			if (meta->ip_tot_len > stats->ip_pkt_len_max)
				stats->ip_pkt_len_max = meta->ip_tot_len;
		}
		// The ONLY TCP byte-12..15 load in the packet path. On success mark
		// the direction header-observed regardless of the flag/window VALUES
		// (a NULL scan segment has flags==0 and must still count as
		// observed). The flag OR is a 32-bit atomic fetch-or (BPF ISA v3,
		// -mcpu=v3; kernel >= 5.12 x86_64 JIT / >= 5.17 arm64 JIT, target
		// 6.8): a plain |= is a read-modify-write and a cross-CPU race could
		// permanently lose a one-shot SYN/RST/FIN bit. The window max stays
		// a best-effort extremum (see flow_stats comment).
		// Reuses the single hoisted load above -- no second read.
		if (tcp_hdr_ok) {
			win = bpf_ntohs(tcpfw.window);
			if (ingress) {
				stats->tcp_header_observed_recv = 1;
				__sync_fetch_and_or(&stats->tcp_flags_or_recv, (__u32)tcpfw.flags);
				if (win > stats->tcp_win_max_recv)
					stats->tcp_win_max_recv = win;
			} else {
				stats->tcp_header_observed_sent = 1;
				__sync_fetch_and_or(&stats->tcp_flags_or_sent, (__u32)tcpfw.flags);
				if (win > stats->tcp_win_max_sent)
					stats->tcp_win_max_sent = win;
			}
		}
	}
	if (meta && cfg && cfg->collect_netflow_v2_histogram && meta->ip_tot_len != 0) {
		nf_idx = nf_ip_size_bucket(meta->ip_tot_len);
		if (nf_idx >= 0 && nf_idx < 6)
			__sync_fetch_and_add(&stats->nf_ip_size_buckets[nf_idx], 1);
	}

	if (ingress) {
		__sync_fetch_and_add(&stats->real_packets_recv, 1);
		last_packet_ns = &stats->last_packet_ns_recv;
		first_packet_ns = &stats->first_packet_ns_recv;
	} else {
		__sync_fetch_and_add(&stats->real_packets_sent, 1);
		last_packet_ns = &stats->last_packet_ns_sent;
		first_packet_ns = &stats->first_packet_ns_sent;
	}
	if (*first_packet_ns == 0)
		*first_packet_ns = now;

	if (*last_packet_ns != 0 && now > *last_packet_ns) {
		iat_us = (now - *last_packet_ns) / 1000;
		iat_idx = iat_bucket(iat_us);
		if (iat_idx >= 0 && iat_idx < 6) {
			__sync_fetch_and_add(&stats->iat_buckets[iat_idx], 1);
			// iat_us was measured against *last_packet_ns, which is already
			// the previous packet IN THIS DIRECTION (last_packet_ns_sent /
			// last_packet_ns_recv). The mixed array has therefore always been
			// the sum of the two within-direction histograms; splitting the
			// destination reproduces it exactly, bucket by bucket.
			__sync_fetch_and_add(&dir_iat_buckets[iat_idx], 1);
		}
		if (iat_us > 1000000)
			__sync_fetch_and_add(&stats->idle_gap_count, 1);
		if (iat_us > 0 && iat_us < 10000)
			__sync_fetch_and_add(&stats->burst_count, 1);
		stats->packet_timing_available = 1;
	}
	*last_packet_ns = now;

	stats->last_seen_ns = now;
	if (now - stats->last_emit_ns >= EBPF_EMIT_INTERVAL_NS) {
		emit_flow_event_no_pid(key, stats, EVENT_STATS, now, stats->netns_ino);
		stats->last_emit_ns = now;
	}
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct flow_key key = {};
	struct flow_stats *init;
	struct flow_stats *stats;
	__u64 cgid;
	__u64 now = bpf_ktime_get_ns();
	__u64 netns_ino = netns_ino_from_sock((struct sock *)ctx->skaddr);

	if (ctx->protocol != IPPROTO_TCP) {
		increment_drop(DROP_UNSUPPORTED_FAMILY);
		return 0;
	}
	if (ctx->family == AF_INET) {
		key.src_ip = ctx->saddr;
		key.dst_ip = ctx->daddr;
	} else if (ctx->family == AF_INET6) {
		__u8 saddr6[16] = {};
		__u8 daddr6[16] = {};

		__builtin_memcpy(saddr6, ctx->saddr_v6, sizeof(saddr6));
		__builtin_memcpy(daddr6, ctx->daddr_v6, sizeof(daddr6));
		if (v4_from_mapped(saddr6, &key.src_ip) != 0 ||
		    v4_from_mapped(daddr6, &key.dst_ip) != 0) {
			increment_drop(DROP_UNSUPPORTED_V6);
			return 0;
		}
	} else {
		increment_drop(DROP_UNSUPPORTED_FAMILY);
		return 0;
	}
	key.src_port = ctx->sport;
	key.dst_port = ctx->dport;
	key.protocol = IPPROTO_TCP;
	key.direction = DIRECTION_UNKNOWN;

	// v1alpha6: create the entry (and its local-endpoint index) as soon as the
	// connection leaves CLOSED, so the handshake packets -- and, for a refused
	// or unanswered connect, the ONLY packets there will ever be -- have an
	// entry to be counted against. No ringbuf event is emitted here: the Go
	// sessionizer must keep learning about a connection from CONNECT/CLOSE
	// exactly as in v1alpha5, which is what keeps conn_start_time and the
	// window-validity logic byte-for-byte unchanged.
	//
	// The entry is born with established=0, so update_packet_stats' write
	// barrier lets ONLY the six directional flag counters move until the
	// ESTABLISHED transition below opens it up.
	if (ctx->newstate == TCP_SYN_SENT || ctx->newstate == TCP_SYN_RECV) {
		// PORT-ZERO HAZARD (measured, not theoretical). tcp_v4_connect calls
		// tcp_set_state(sk, TCP_SYN_SENT) -- which fires this tracepoint --
		// BEFORE inet_hash_connect() picks the ephemeral source port; the
		// kernel's own comment there reads "sport may be zero". An
		// application that binds before connecting (busybox nc) already has a
		// port here; one that just calls connect() (busybox wget, and most
		// libraries) does not. Creating an entry keyed on port 0 would index
		// a key no packet can ever resolve to, so refuse it and let the
		// tcp_connect kprobe below -- which runs after the port is assigned
		// and before the SYN is transmitted -- create the entry instead.
		if (key.src_port == 0) {
			increment_drop(DROP_DEGENERATE_KEY);
			return 0;
		}
		if (bpf_map_lookup_elem(&flow_stats_map, &key))
			return 0; // already tracked; never re-create
		init = zeroed_stats_template();
		if (!init) {
			increment_drop(DROP_MAP_UPDATE_FAILED);
			return 0;
		}
		init->start_ns = now;
		init->last_seen_ns = now;
		init->last_emit_ns = now;
		init->cgroup_id = sk_cgroup_id((struct sock *)ctx->skaddr);
		if (init->cgroup_id == 0)
			init->cgroup_id = bpf_get_current_cgroup_id();
		init->netns_ino = netns_ino;
		init->established = 0;
		if (bpf_map_update_elem(&flow_stats_map, &key, init, BPF_ANY) != 0) {
			increment_drop(DROP_MAP_UPDATE_FAILED);
			return 0;
		}
		index_local_ep(&key);
		return 0;
	}

	if (ctx->newstate == TCP_ESTABLISHED) {
		// IDEMPOTENT: an entry created at SYN_SENT/SYN_RECV is ADOPTED, never
		// overwritten -- a blind re-create here would discard the handshake
		// flag counts we just went to the trouble of collecting, and would
		// also reset start_ns mid-connection.
		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		if (stats) {
			stats->established = 1;
			stats->last_seen_ns = now;
			// socket-owned cgroup: see the fresh-create path below.
			cgid = sk_cgroup_id((struct sock *)ctx->skaddr);
			if (cgid == 0)
				cgid = bpf_get_current_cgroup_id();
			if (cgid != 0)
				stats->cgroup_id = cgid;
			if (netns_ino != 0)
				stats->netns_ino = netns_ino;
			stats->syn_count = 1;
			stats->tcp_metrics_available = 1;
			index_local_ep(&key);
			emit_flow_event(&key, stats, EVENT_CONNECT, now, netns_ino);
			return 0;
		}

		init = zeroed_stats_template();
		if (!init) {
			increment_drop(DROP_MAP_UPDATE_FAILED);
			return 0;
		}
		init->start_ns = now;
		init->last_seen_ns = now;
		init->last_emit_ns = now;
		// socket-owned cgroup: ESTABLISHED fires in softirq on SYN-ACK for the active connector,
		// so bpf_get_current_cgroup_id() may be an arbitrary co-located task. Attribute to the
		// socket owner; fall back to current only for unowned (host-network) sockets.
		init->cgroup_id = sk_cgroup_id((struct sock *)ctx->skaddr);
		if (init->cgroup_id == 0)
			init->cgroup_id = bpf_get_current_cgroup_id();
		init->netns_ino = netns_ino;
		// UNCHANGED v1alpha4 semantics: the legacy syn_count stays a
		// per-connection 1 written here. The v1alpha5 syn_count_out/in are a
		// different, packet-level quantity written only at cgroup_skb.
		init->syn_count = 1;
		init->tcp_metrics_available = 1;
		init->established = 1;
		if (bpf_map_update_elem(&flow_stats_map, &key, init, BPF_ANY) != 0) {
			increment_drop(DROP_MAP_UPDATE_FAILED);
			return 0;
		}
		index_local_ep(&key);
		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		emit_flow_event(&key, stats, EVENT_CONNECT, now, netns_ino);
		return 0;
	}

	if (ctx->newstate == TCP_CLOSE) {
		struct local_ep ep = {};
		struct flow_key *owner;

		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		// v1alpha6 write barrier, event-path half. Before v1alpha6 a refused
		// or unanswered connect had NO entry here, so this block never ran for
		// one and its record carried fin_count=0 / tcp_metrics_available=false.
		// Early entry creation would silently start writing all three on those
		// records -- existing fields changing value on existing rows. Gate them
		// on established so a never-established connection's record keeps
		// exactly its v1alpha5 shape, plus the six flag counters and nothing
		// else.
		if (stats && stats->established) {
			stats->close_seen = 1;
			stats->fin_count += 1;
			stats->tcp_metrics_available = 1;
		}
		emit_flow_event(&key, stats, EVENT_CLOSE, now, netns_ino);
		bpf_map_delete_elem(&flow_stats_map, &key);
		// v1alpha7: retract the index entry ONLY if it still points at THIS
		// connection. The index key is (local ip, local port), which on a
		// listening socket is shared with every other live connection to the
		// same port; the old unconditional delete took the slot away from all
		// of them and their subsequent packets went to DROP_PACKET_EP_MISS.
		ep.ip = key.src_ip;
		ep.port = key.src_port;
		owner = bpf_map_lookup_elem(&local_ep_to_key, &ep);
		if (owner && owner->dst_ip == key.dst_ip &&
		    owner->dst_port == key.dst_port)
			bpf_map_delete_elem(&local_ep_to_key, &ep);
		return 0;
	}

	return 0;
}

// v1alpha6: the reliable early-creation point for ACTIVE connects.
//
// The inet_sock_set_state(TCP_SYN_SENT) tracepoint fires before the ephemeral
// source port exists (see the PORT-ZERO HAZARD note above), so for the common
// connect()-without-bind path it cannot produce a usable key. tcp_connect() is
// entered after inet_hash_connect() has assigned and hashed the port, and it
// is what builds and transmits the SYN -- so a kprobe on its entry is the last
// moment at which the flow key is complete and the first packet has not yet
// left. Creating the entry here is what makes the handshake countable for
// every client, not just the ones that happen to bind first.
//
// Idempotent and established=0, exactly like the tracepoint path: this only
// ever creates, never overwrites, and the ESTABLISHED transition adopts.
SEC("kprobe/tcp_connect")
int handle_tcp_connect(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct flow_key key;
	struct flow_stats *init;
	__u64 now;

	// key_from_sock rejects degenerate (port-0) keys for us.
	if (key_from_sock(sk, &key, DIRECTION_UNKNOWN) != 0)
		return 0;
	if (bpf_map_lookup_elem(&flow_stats_map, &key))
		return 0;
	init = zeroed_stats_template();
	if (!init) {
		increment_drop(DROP_MAP_UPDATE_FAILED);
		return 0;
	}
	now = bpf_ktime_get_ns();
	init->start_ns = now;
	init->last_seen_ns = now;
	init->last_emit_ns = now;
	init->cgroup_id = sk_cgroup_id(sk);
	if (init->cgroup_id == 0)
		init->cgroup_id = bpf_get_current_cgroup_id();
	init->netns_ino = netns_ino_from_sock(sk);
	init->established = 0;
	if (bpf_map_update_elem(&flow_stats_map, &key, init, BPF_ANY) != 0) {
		increment_drop(DROP_MAP_UPDATE_FAILED);
		return 0;
	}
	index_local_ep(&key);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int handle_tcp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	__u64 size = (__u64)PT_REGS_PARM3(ctx);
	struct flow_key key;

	if (key_from_sock(sk, &key, DIRECTION_UNKNOWN) != 0)
		return 0;
	update_sent(&key, size, bpf_ktime_get_ns(), netns_ino_from_sock(sk));
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int handle_tcp_recvmsg_entry(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct flow_key key;

	if (key_from_sock(sk, &key, DIRECTION_UNKNOWN) != 0)
		return 0;
	if (bpf_map_update_elem(&recv_args_map, &pid_tgid, &key, BPF_ANY) != 0)
		increment_drop(DROP_MAP_UPDATE_FAILED);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int handle_tcp_recvmsg_return(struct pt_regs *ctx)
{
	int ret = (int)PT_REGS_RC(ctx);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct flow_key *key;

	key = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
	if (!key) {
		increment_drop(DROP_RECV_ARG_MISSED);
		return 0;
	}
	if (ret > 0)
		update_recv(key, (__u64)ret, bpf_ktime_get_ns(), 0);
	bpf_map_delete_elem(&recv_args_map, &pid_tgid);
	return 0;
}

// Resolve the wire packet to the flow_stats entry the accounting hooks created.
//
// v1alpha7: try the WIRE TUPLE ITSELF first, and only fall back to the
// local-endpoint index. The wire tuple is an exact 4-tuple, so a hit is
// unambiguous. The index is keyed on (local ip, local port) ALONE -- it cannot
// tell two connections apart when they share a local endpoint, which is every
// connection to a listening socket. index_local_ep writes it with BPF_ANY, so
// concurrent server-side connections overwrite one another and their packet
// stats land on whichever neighbour last won the slot.
//
// The direct lookup works whenever nothing rewrote the destination between the
// socket and this hook. For a pod-netns socket that is always: kube-proxy's nat
// table exists only in the host netns, so DNAT happens after the packet has
// left. The index is retained for the one case the direct lookup cannot serve
// -- a host-netns socket to a ClusterIP, where nat OUTPUT rewrites the
// destination before ip_finish_output runs this program -- and, on a fallback,
// keeps exactly the pre-v1alpha7 behaviour rather than losing the packet.
//
// Cost is unchanged on the hit path: one lookup here plus the one
// update_packet_stats does, same as the index lookup it replaces.
static struct flow_key *canonical_key_from_skb(struct flow_key *skbkey)
{
	struct local_ep ep = {};
	struct flow_key *canon;

	if (bpf_map_lookup_elem(&flow_stats_map, skbkey))
		return skbkey;
	increment_drop(DROP_PACKET_DIRECT_MISS);

	ep.ip = skbkey->src_ip;
	ep.port = skbkey->src_port;
	canon = bpf_map_lookup_elem(&local_ep_to_key, &ep);
	if (!canon)
		increment_drop(DROP_PACKET_EP_MISS);
	return canon;
}

SEC("cgroup_skb/ingress")
int handle_cgroup_skb_ingress(struct __sk_buff *skb)
{
	struct flow_key key;
	struct flow_key *canon;
	struct flow_stats *stats;
	struct skb_pkt_meta meta = {};

	if (key_from_skb(skb, &key, 1, &meta) == 0) {
		canon = canonical_key_from_skb(&key);
		if (canon)
			update_packet_stats(skb, canon, skb->len, 1, &meta);
		// TLS handshake dedup/emit deliberately keeps the post-NAT tuple key.
		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		maybe_emit_tls_handshake(skb, &key, stats, DIRECTION_RECV, 0x02);
	}
	return CGROUP_SKB_PASS;
}

SEC("cgroup_skb/egress")
int handle_cgroup_skb_egress(struct __sk_buff *skb)
{
	struct flow_key key;
	struct flow_key *canon;
	struct flow_stats *stats;
	struct skb_pkt_meta meta = {};

	if (key_from_skb(skb, &key, 0, &meta) == 0) {
		canon = canonical_key_from_skb(&key);
		if (canon)
			update_packet_stats(skb, canon, skb->len, 0, &meta);
		// TLS handshake dedup/emit deliberately keeps the post-NAT tuple key.
		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		maybe_emit_tls_handshake(skb, &key, stats, DIRECTION_SEND, 0x01);
	}
	return CGROUP_SKB_PASS;
}

// LOCAL egress retransmissions only. The flow key is built from the socket
// (skaddr) exactly like the tcp_sendmsg/tcp_recvmsg accounting hooks, so it is
// the pre-DNAT canonical key: for a client talking to a Service the key's dst
// is the ClusterIP tuple, i.e. the same flow_stats entry every other socket
// hook updates — no kube-proxy DNAT reconciliation is needed here. IPv4 and
// IPv4-mapped IPv6 sockets are supported via key_from_sock; genuine IPv6 is
// dropped there (DROP_UNSUPPORTED_V6), unchanged from the rest of the
// collector. Only flow_stats_map is updated — no per-retransmit ringbuf event
// is ever emitted; the totals ride the existing STATS cadence. A retransmit
// for a flow with no flow_stats entry (evicted, or raced with CLOSE) is
// counted in DROP_RETRANS_FLOW_MISS instead of being attributed anywhere.
SEC("tracepoint/tcp/tcp_retransmit_skb")
int handle_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	struct flow_key key;
	struct flow_stats *stats;
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	unsigned int skb_len = 0;

	if (key_from_sock((struct sock *)ctx->skaddr, &key, DIRECTION_UNKNOWN) != 0)
		return 0;
	stats = bpf_map_lookup_elem(&flow_stats_map, &key);
	if (!stats) {
		increment_drop(DROP_RETRANS_FLOW_MISS);
		return 0;
	}
	__sync_fetch_and_add(&stats->retrans_skb_count, 1);
	if (skb) {
		// CO-RE read of skb->len (offset resolved from BTF by name).
		bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len);
		if (skb_len > 0)
			__sync_fetch_and_add(&stats->retrans_skb_bytes, (__u64)skb_len);
	}
	return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";
