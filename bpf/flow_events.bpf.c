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
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0

#define AF_INET 2
#define IPPROTO_TCP 6

#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

#define EVENT_CONNECT 1
#define EVENT_CLOSE 2
#define EVENT_STATS 3
#define EVENT_DROP 4

#define DIRECTION_UNKNOWN 0
#define DIRECTION_SEND 1
#define DIRECTION_RECV 2

#define DROP_MAP_UPDATE_FAILED 0
#define DROP_RINGBUF_RESERVE_FAILED 1
#define DROP_UNSUPPORTED_FAMILY 2
#define DROP_RECV_ARG_MISSED 3
#define DROP_TLS_BUFFER_RESERVE_FAILED 4
#define DROP_TLS_SERVER_HELLO_NO_STATS 5
#define DROP_COUNTERS_LEN 6

#define FLOW_STATS_MAX_ENTRIES 65536
#define RECV_ARGS_MAX_ENTRIES 16384
#define EBPF_EMIT_INTERVAL_NS 5000000000ULL
#define CGROUP_SKB_PASS 1
#define TLS_CAPTURE_MAX_BYTES 1024

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
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
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
	__u32 syn_count;
	__u32 fin_count;
	__u32 rst_count;
	__u8 close_seen;
	__u8 client_hello_inspected;
	__u8 server_hello_inspected;
	__u8 traffic_accounting_available;
	__u8 packet_timing_available;
	__u8 tcp_metrics_available;
	__u8 _pad1[2];
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
	__u32 syn_count;
	__u32 fin_count;
	__u32 rst_count;
	__u8 traffic_accounting_available;
	__u8 packet_timing_available;
	__u8 tcp_metrics_available;
	__u8 _pad2;
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

struct flow_config {
	__u8 tls_handshake_inspect_enabled;
	__u8 _pad[7];
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

static void increment_drop(__u32 idx)
{
	__u64 *counter;

	counter = bpf_map_lookup_elem(&drop_counters, &idx);
	if (counter)
		__sync_fetch_and_add(counter, 1);
}

static int tls_inspect_enabled(void)
{
	__u32 idx = 0;
	struct flow_config *cfg;

	cfg = bpf_map_lookup_elem(&config_map, &idx);
	return cfg && cfg->tls_handshake_inspect_enabled;
}

static int key_from_sock(struct sock *sk, struct flow_key *key, __u8 direction)
{
	__u16 family = 0;
	__u16 dport = 0;

	if (!sk)
		return -1;

	bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
	if (family != AF_INET) {
		increment_drop(DROP_UNSUPPORTED_FAMILY);
		return -1;
	}

	__builtin_memset(key, 0, sizeof(*key));
	bpf_probe_read_kernel(&key->src_ip, sizeof(key->src_ip), &sk->__sk_common.skc_rcv_saddr);
	bpf_probe_read_kernel(&key->dst_ip, sizeof(key->dst_ip), &sk->__sk_common.skc_daddr);
	bpf_probe_read_kernel(&key->src_port, sizeof(key->src_port), &sk->__sk_common.skc_num);
	bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
	key->dst_port = bpf_ntohs(dport);
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

static struct flow_stats *ensure_stats(struct flow_key *key, __u64 now)
{
	struct flow_stats init = {};
	struct flow_stats *stats;

	stats = bpf_map_lookup_elem(&flow_stats_map, key);
	if (stats)
		return stats;

	init.start_ns = now;
	init.last_seen_ns = now;
	init.last_emit_ns = now;
	init.cgroup_id = bpf_get_current_cgroup_id();
	if (bpf_map_update_elem(&flow_stats_map, key, &init, BPF_ANY) != 0) {
		increment_drop(DROP_MAP_UPDATE_FAILED);
		return 0;
	}
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

static int key_from_skb(struct __sk_buff *skb, struct flow_key *key, int ingress)
{
	struct ipv4_header ip = {};
	struct tcp_ports ports = {};
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

static void update_packet_stats(struct __sk_buff *skb, struct flow_key *key, __u64 packet_len, int ingress, __u64 now)
{
	struct flow_stats *stats;
	__u64 *last_packet_ns;
	__u64 cgroup_id;
	__u64 iat_us;
	int pkt_bucket;
	int iat_idx;

	stats = bpf_map_lookup_elem(&flow_stats_map, key);
	if (!stats)
		return;
	if (stats->cgroup_id == 0) {
		cgroup_id = bpf_skb_cgroup_id(skb);
		if (cgroup_id == 0)
			cgroup_id = bpf_get_current_cgroup_id();
		stats->cgroup_id = cgroup_id;
	}

	pkt_bucket = packet_size_bucket(packet_len);
	if (pkt_bucket >= 0 && pkt_bucket < 7)
		__sync_fetch_and_add(&stats->pkt_size_buckets[pkt_bucket], 1);
	if (stats->pkt_size_min == 0 || packet_len < stats->pkt_size_min)
		stats->pkt_size_min = packet_len;
	if (packet_len > stats->pkt_size_max)
		stats->pkt_size_max = packet_len;

	if (ingress) {
		__sync_fetch_and_add(&stats->real_packets_recv, 1);
		last_packet_ns = &stats->last_packet_ns_recv;
	} else {
		__sync_fetch_and_add(&stats->real_packets_sent, 1);
		last_packet_ns = &stats->last_packet_ns_sent;
	}

	if (*last_packet_ns != 0 && now > *last_packet_ns) {
		iat_us = (now - *last_packet_ns) / 1000;
		iat_idx = iat_bucket(iat_us);
		if (iat_idx >= 0 && iat_idx < 6)
			__sync_fetch_and_add(&stats->iat_buckets[iat_idx], 1);
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
	struct flow_stats init = {};
	struct flow_stats *stats;
	__u64 now = bpf_ktime_get_ns();
	__u64 netns_ino = netns_ino_from_sock((struct sock *)ctx->skaddr);

	if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP) {
		increment_drop(DROP_UNSUPPORTED_FAMILY);
		return 0;
	}

	key.src_ip = ctx->saddr;
	key.dst_ip = ctx->daddr;
	key.src_port = ctx->sport;
	key.dst_port = ctx->dport;
	key.protocol = IPPROTO_TCP;
	key.direction = DIRECTION_UNKNOWN;

	if (ctx->newstate == TCP_ESTABLISHED) {
		init.start_ns = now;
		init.last_seen_ns = now;
		init.last_emit_ns = now;
		init.cgroup_id = bpf_get_current_cgroup_id();
		init.netns_ino = netns_ino;
		init.syn_count = 1;
		init.tcp_metrics_available = 1;
		if (bpf_map_update_elem(&flow_stats_map, &key, &init, BPF_ANY) != 0) {
			increment_drop(DROP_MAP_UPDATE_FAILED);
			return 0;
		}
		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		emit_flow_event(&key, stats, EVENT_CONNECT, now, netns_ino);
		return 0;
	}

	if (ctx->newstate == TCP_CLOSE) {
		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		if (stats) {
			stats->close_seen = 1;
			stats->fin_count += 1;
			stats->tcp_metrics_available = 1;
		}
		emit_flow_event(&key, stats, EVENT_CLOSE, now, netns_ino);
		bpf_map_delete_elem(&flow_stats_map, &key);
		return 0;
	}

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

SEC("cgroup_skb/ingress")
int handle_cgroup_skb_ingress(struct __sk_buff *skb)
{
	struct flow_key key;
	struct flow_stats *stats;

	if (key_from_skb(skb, &key, 1) == 0) {
		update_packet_stats(skb, &key, skb->len, 1, bpf_ktime_get_ns());
		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		maybe_emit_tls_handshake(skb, &key, stats, DIRECTION_RECV, 0x02);
	}
	return CGROUP_SKB_PASS;
}

SEC("cgroup_skb/egress")
int handle_cgroup_skb_egress(struct __sk_buff *skb)
{
	struct flow_key key;
	struct flow_stats *stats;

	if (key_from_skb(skb, &key, 0) == 0) {
		update_packet_stats(skb, &key, skb->len, 0, bpf_ktime_get_ns());
		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		maybe_emit_tls_handshake(skb, &key, stats, DIRECTION_SEND, 0x01);
	}
	return CGROUP_SKB_PASS;
}

char __license[] SEC("license") = "Dual BSD/GPL";
