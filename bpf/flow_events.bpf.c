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
#define DROP_COUNTERS_LEN 4

#define FLOW_STATS_MAX_ENTRIES 65536
#define RECV_ARGS_MAX_ENTRIES 16384
#define EBPF_EMIT_INTERVAL_NS 5000000000ULL

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
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct flow_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u8 direction;
	__u16 _pad0;
	__u64 cgroup_id;
};

struct flow_stats {
	__u64 start_ns;
	__u64 last_seen_ns;
	__u64 last_emit_ns;
	__u64 bytes_sent;
	__u64 bytes_recv;
	__u64 packets_sent;
	__u64 packets_recv;
	__u32 syn_count;
	__u32 fin_count;
	__u32 rst_count;
	__u8 close_seen;
	__u8 traffic_accounting_available;
	__u8 tcp_metrics_available;
	__u8 _pad1;
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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FLOW_STATS_MAX_ENTRIES);
	__type(key, struct flow_key);
	__type(value, struct flow_stats);
} flow_stats_map SEC(".maps");

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
	key->cgroup_id = bpf_get_current_cgroup_id();
	return 0;
}

static void fill_event(struct flow_event *event, struct flow_key *key, struct flow_stats *stats, __u32 event_type, __u64 now)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = now;
	event->event_type = event_type;
	event->pid = (__u32)pid_tgid;
	event->tgid = (__u32)(pid_tgid >> 32);
	event->cgroup_id = key->cgroup_id;
	event->netns_ino = 0;
	event->family = AF_INET;
	event->protocol = IPPROTO_TCP;
	event->src_ipv4 = key->src_ip;
	event->dst_ipv4 = key->dst_ip;
	event->src_port = key->src_port;
	event->dst_port = key->dst_port;
	if (stats) {
		event->bytes_sent = stats->bytes_sent;
		event->bytes_recv = stats->bytes_recv;
		event->packets_sent = stats->packets_sent;
		event->packets_recv = stats->packets_recv;
		event->syn_count = stats->syn_count;
		event->fin_count = stats->fin_count;
		event->rst_count = stats->rst_count;
		event->traffic_accounting_available = stats->traffic_accounting_available;
		event->tcp_metrics_available = stats->tcp_metrics_available;
	}
}

static int emit_flow_event(struct flow_key *key, struct flow_stats *stats, __u32 event_type, __u64 now)
{
	struct flow_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		increment_drop(DROP_RINGBUF_RESERVE_FAILED);
		return -1;
	}
	fill_event(event, key, stats, event_type, now);
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
	if (bpf_map_update_elem(&flow_stats_map, key, &init, BPF_ANY) != 0) {
		increment_drop(DROP_MAP_UPDATE_FAILED);
		return 0;
	}
	return bpf_map_lookup_elem(&flow_stats_map, key);
}

static void update_sent(struct flow_key *key, __u64 bytes, __u64 now)
{
	struct flow_stats *stats;

	if (bytes == 0)
		return;
	stats = ensure_stats(key, now);
	if (!stats)
		return;

	__sync_fetch_and_add(&stats->bytes_sent, bytes);
	__sync_fetch_and_add(&stats->packets_sent, 1);
	stats->last_seen_ns = now;
	stats->traffic_accounting_available = 1;
	if (now - stats->last_emit_ns >= EBPF_EMIT_INTERVAL_NS) {
		emit_flow_event(key, stats, EVENT_STATS, now);
		stats->last_emit_ns = now;
	}
}

static void update_recv(struct flow_key *key, __u64 bytes, __u64 now)
{
	struct flow_stats *stats;

	if (bytes == 0)
		return;
	stats = ensure_stats(key, now);
	if (!stats)
		return;

	__sync_fetch_and_add(&stats->bytes_recv, bytes);
	__sync_fetch_and_add(&stats->packets_recv, 1);
	stats->last_seen_ns = now;
	stats->traffic_accounting_available = 1;
	if (now - stats->last_emit_ns >= EBPF_EMIT_INTERVAL_NS) {
		emit_flow_event(key, stats, EVENT_STATS, now);
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
	key.cgroup_id = bpf_get_current_cgroup_id();

	if (ctx->newstate == TCP_ESTABLISHED) {
		init.start_ns = now;
		init.last_seen_ns = now;
		init.last_emit_ns = now;
		init.syn_count = 1;
		init.tcp_metrics_available = 1;
		if (bpf_map_update_elem(&flow_stats_map, &key, &init, BPF_ANY) != 0) {
			increment_drop(DROP_MAP_UPDATE_FAILED);
			return 0;
		}
		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		emit_flow_event(&key, stats, EVENT_CONNECT, now);
		return 0;
	}

	if (ctx->newstate == TCP_CLOSE) {
		stats = bpf_map_lookup_elem(&flow_stats_map, &key);
		if (stats) {
			stats->close_seen = 1;
			stats->fin_count += 1;
			stats->tcp_metrics_available = 1;
		}
		emit_flow_event(&key, stats, EVENT_CLOSE, now);
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
	update_sent(&key, size, bpf_ktime_get_ns());
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
		update_recv(key, (__u64)ret, bpf_ktime_get_ns());
	bpf_map_delete_elem(&recv_args_map, &pid_tgid);
	return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";
