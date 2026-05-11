// SPDX-License-Identifier: Apache-2.0

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define BPF_MAP_TYPE_RINGBUF 27

#define AF_INET 2
#define IPPROTO_TCP 6

#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

#define EVENT_CONNECT 1
#define EVENT_CLOSE 2
#define EVENT_STATS 3

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct flow_event {
	__u64 timestamp_ns;
	__u32 event_type;
	__u32 pid;
	__u32 tgid;
	__u32 _pad0;
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
};

typedef struct flow_event flow_event;

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

static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	__u32 event_type = 0;
	__u64 pid_tgid;
	struct flow_event *event;

	if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP)
		return 0;

	if (ctx->newstate == TCP_ESTABLISHED) {
		event_type = EVENT_CONNECT;
	} else if (ctx->newstate == TCP_CLOSE) {
		event_type = EVENT_CLOSE;
	} else {
		return 0;
	}

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	event->timestamp_ns = bpf_ktime_get_ns();
	event->event_type = event_type;
	event->pid = (__u32)pid_tgid;
	event->tgid = (__u32)(pid_tgid >> 32);
	event->_pad0 = 0;
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->netns_ino = 0;
	event->family = ctx->family;
	event->protocol = (__u8)ctx->protocol;
	event->_pad1 = 0;
	event->src_ipv4 = ctx->saddr;
	event->dst_ipv4 = ctx->daddr;
	event->src_port = ctx->sport;
	event->dst_port = ctx->dport;
	event->bytes_sent = 0;
	event->bytes_recv = 0;
	event->packets_sent = 0;
	event->packets_recv = 0;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";
