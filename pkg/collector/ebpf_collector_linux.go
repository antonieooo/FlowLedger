//go:build linux

package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// -mcpu=v3 is required for the 32-bit atomic OR (__sync_fetch_and_or) on the
// per-direction TCP flag masks. Minimum kernel for BPF ISA v3 atomics:
// Linux >= 5.12 (x86_64 JIT), >= 5.17 (arm64 JIT); deployment target is 6.8.
//go:generate go tool bpf2go -no-strip -target amd64,arm64 flowEvents ../../bpf/flow_events.bpf.c -- -g -mcpu=v3

const (
	defaultEBPFFlowMapMaxEntries = 65536
	defaultEBPFStatsEmitInterval = 5 * time.Second
)

type EBPFOptions struct {
	FlowMapMaxEntries         uint32
	StatsEmitInterval         time.Duration
	EnableTrafficAccounting   bool
	EnableTCPBasicMetrics     bool
	EnablePacketTiming        bool
	EnablePacketHistogram     bool
	EnableTLSHandshakeInspect bool
	// EnableHeaderAggregates gates the v1alpha3 TCP/IP header aggregates
	// (TTL/flags/window/IP-length envelopes) inside the BPF program via
	// flow_config.collect_header_aggregates: when false the kernel skips the
	// updates AND the phase-B TCP byte-12..15 load — not just Go-side
	// nulling. Disabled fields surface as null/unobserved.
	EnableHeaderAggregates bool
	// EnableNetFlowV2Histogram gates the NetFlow-v2 IP-size histogram inside
	// the BPF program via flow_config.collect_netflow_v2_histogram; same
	// kernel-side-skip semantics as EnableHeaderAggregates.
	EnableNetFlowV2Histogram bool
	// OnRetransAttach, when non-nil, is called exactly once with the
	// tcp/tcp_retransmit_skb tracepoint attach outcome (metrics hook).
	OnRetransAttach func(attached bool)

	// MapStatsInterval is the period of the low-frequency map occupancy
	// sampler (flow_stats/local_ep/tls_seen/recv_args entry counts). 0 means
	// the 15s default; a negative value disables sampling. The walk runs in
	// its own goroutine and NEVER on the packet/event hot path.
	MapStatsInterval time.Duration
	// OnMapOccupancy, when non-nil, receives each round of occupancy samples
	// (only maps whose walk succeeded that round).
	OnMapOccupancy func(samples []EBPFMapOccupancy)
	// OnMapWalkError, when non-nil, is called once per failed map walk. A
	// walk failure only skips that map's sample for the round — the
	// collector keeps running and retries next round.
	OnMapWalkError func(mapName string, err error)
}

const defaultMapStatsInterval = 15 * time.Second

type EBPFCollector struct {
	opts EBPFOptions
}

func NewEBPFCollector() *EBPFCollector {
	return NewEBPFCollectorWithOptions(EBPFOptions{
		FlowMapMaxEntries:         defaultEBPFFlowMapMaxEntries,
		StatsEmitInterval:         defaultEBPFStatsEmitInterval,
		EnableTrafficAccounting:   true,
		EnableTCPBasicMetrics:     true,
		EnablePacketTiming:        true,
		EnablePacketHistogram:     true,
		EnableTLSHandshakeInspect: true,
	})
}

func NewEBPFCollectorWithOptions(opts EBPFOptions) *EBPFCollector {
	if opts.FlowMapMaxEntries == 0 {
		opts.FlowMapMaxEntries = defaultEBPFFlowMapMaxEntries
	}
	if opts.StatsEmitInterval <= 0 {
		opts.StatsEmitInterval = defaultEBPFStatsEmitInterval
	}
	return &EBPFCollector{opts: opts}
}

func (c *EBPFCollector) Run(ctx context.Context) (<-chan FlowEvent, <-chan error) {
	events := make(chan FlowEvent)
	errs := make(chan error, 8)

	go func() {
		var wg sync.WaitGroup
		defer close(events)
		defer close(errs)
		defer wg.Wait()

		if err := rlimit.RemoveMemlock(); err != nil {
			errs <- fmt.Errorf("remove memlock limit: %w", err)
			return
		}

		spec, err := loadFlowEvents()
		if err != nil {
			errs <- fmt.Errorf("load ebpf spec: %w", err)
			return
		}
		if flowStatsMap, ok := spec.Maps["flow_stats_map"]; ok && c.opts.FlowMapMaxEntries > 0 {
			flowStatsMap.MaxEntries = c.opts.FlowMapMaxEntries
		}

		var objs flowEventsObjects
		if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
			errs <- fmt.Errorf("load ebpf objects: %w", err)
			return
		}
		defer objs.Close()
		if err := configureBPF(&objs, c.opts); err != nil {
			errs <- fmt.Errorf("configure ebpf objects: %w", err)
			return
		}

		tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleInetSockSetState, nil)
		if err != nil {
			errs <- fmt.Errorf("attach sock/inet_sock_set_state tracepoint: %w", err)
			return
		}
		defer tp.Close()
		log.Print("ebpf collector attached tracepoint sock/inet_sock_set_state")

		// v1alpha6: create the flow entry at tcp_connect, the last point at
		// which the flow key is complete (the ephemeral source port has been
		// assigned) and the SYN has not yet been transmitted. The
		// inet_sock_set_state(SYN_SENT) tracepoint fires too early for that
		// -- the port is still 0 unless the application bound one -- so
		// without this kprobe the handshake of an ordinary connect() client
		// is uncountable. Best-effort: tcp_connect is a stable, long-lived
		// symbol, but if it cannot be attached the collector keeps running
		// with v1alpha5 coverage rather than failing closed.
		connKP, err := link.Kprobe("tcp_connect", objs.HandleTcpConnect, nil)
		if err != nil {
			log.Printf("ebpf collector could not attach tcp_connect kprobe (%v); "+
				"failed/refused connections will carry no directional flag counts", err)
		} else {
			defer connKP.Close()
			log.Print("ebpf collector attached tcp_connect kprobe (early flow entry)")
		}

		var sendKP, recvKP, recvRetKP link.Link
		if c.opts.EnableTrafficAccounting {
			sendKP, err = link.Kprobe("tcp_sendmsg", objs.HandleTcpSendmsg, nil)
			if err != nil {
				errs <- fmt.Errorf("attach tcp_sendmsg kprobe: %w", err)
				return
			}
			defer sendKP.Close()

			recvKP, err = link.Kprobe("tcp_recvmsg", objs.HandleTcpRecvmsgEntry, nil)
			if err != nil {
				errs <- fmt.Errorf("attach tcp_recvmsg kprobe: %w", err)
				return
			}
			defer recvKP.Close()

			recvRetKP, err = link.Kretprobe("tcp_recvmsg", objs.HandleTcpRecvmsgReturn, nil)
			if err != nil {
				errs <- fmt.Errorf("attach tcp_recvmsg kretprobe: %w", err)
				return
			}
			defer recvRetKP.Close()
			log.Printf("ebpf collector attached tcp send/recv accounting hooks flow_map_max_entries=%d stats_emit_interval=%s", c.opts.FlowMapMaxEntries, c.opts.StatsEmitInterval)
		} else {
			log.Print("ebpf traffic accounting disabled; only lifecycle tracepoint events will be collected")
		}

		// v1alpha3 P2: local retransmission counters. Best-effort: on kernels
		// without the tracepoint (or without BTF for the CO-RE skb->len read)
		// the collector keeps running, every event carries
		// local_retrans_available=false, and the failure is logged and
		// surfaced through OnRetransAttach — a 0 never impersonates
		// "confirmed no retransmissions".
		retransAttached := false
		if c.opts.EnableTCPBasicMetrics {
			retransTP, retransErr := link.Tracepoint("tcp", "tcp_retransmit_skb", objs.HandleTcpRetransmitSkb, nil)
			if retransErr != nil {
				log.Printf("attach tcp/tcp_retransmit_skb tracepoint failed; local retransmission metrics disabled (local_retrans_available=false): %v", retransErr)
			} else {
				defer retransTP.Close()
				retransAttached = true
				log.Print("ebpf collector attached tcp/tcp_retransmit_skb tracepoint")
			}
			// The callback fires only when an attach was actually attempted,
			// so a config-disabled hook is not misreported as a failure.
			if c.opts.OnRetransAttach != nil {
				c.opts.OnRetransAttach(retransAttached)
			}
		} else {
			log.Print("ebpf tcp basic metrics disabled; tcp/tcp_retransmit_skb tracepoint not attached")
		}

		var ingressCG, egressCG link.Link
		if c.opts.EnablePacketHistogram || c.opts.EnablePacketTiming || c.opts.EnableTLSHandshakeInspect ||
			c.opts.EnableHeaderAggregates || c.opts.EnableNetFlowV2Histogram {
			if !isCgroupV2Root("/sys/fs/cgroup") {
				log.Print("ebpf cgroup_skb packet features require cgroup v2; skipping packet histogram/timing hooks")
			} else {
				ingressCG, err = link.AttachCgroup(link.CgroupOptions{
					Path:    "/sys/fs/cgroup",
					Attach:  ebpf.AttachCGroupInetIngress,
					Program: objs.HandleCgroupSkbIngress,
				})
				if err != nil {
					log.Printf("attach cgroup_skb ingress failed; packet histogram/timing disabled: %v", err)
				} else {
					egressCG, err = link.AttachCgroup(link.CgroupOptions{
						Path:    "/sys/fs/cgroup",
						Attach:  ebpf.AttachCGroupInetEgress,
						Program: objs.HandleCgroupSkbEgress,
					})
					if err != nil {
						_ = ingressCG.Close()
						log.Printf("attach cgroup_skb egress failed; packet histogram/timing disabled: %v", err)
					} else {
						defer ingressCG.Close()
						defer egressCG.Close()
						log.Printf("ebpf collector attached cgroup_skb packet hooks packet_histogram=%t packet_timing=%t tls_handshake_inspect=%t", c.opts.EnablePacketHistogram, c.opts.EnablePacketTiming, c.opts.EnableTLSHandshakeInspect)
					}
				}
			}
		} else {
			log.Print("ebpf cgroup_skb packet histogram/timing hooks disabled")
		}

		c.startMapStatsSampler(ctx, &objs)

		reader, err := ringbuf.NewReader(objs.Events)
		if err != nil {
			errs <- fmt.Errorf("open ebpf events ringbuf: %w", err)
			return
		}
		defer reader.Close()
		log.Print("ebpf collector started ringbuf reader")

		var tlsReader *ringbuf.Reader
		if c.opts.EnableTLSHandshakeInspect {
			tlsReader, err = ringbuf.NewReader(objs.TlsHandshakeEvents)
			if err != nil {
				errs <- fmt.Errorf("open ebpf tls handshake ringbuf: %w", err)
				return
			}
			defer tlsReader.Close()
			wg.Add(1)
			go c.readTLSHandshakeEvents(ctx, tlsReader, events, errs, &wg)
			log.Print("ebpf collector started tls handshake ringbuf reader")
		}

		go func() {
			<-ctx.Done()
			_ = reader.Close()
			if tlsReader != nil {
				_ = tlsReader.Close()
			}
		}()

		previousDrops := map[uint32]uint64{}
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
					return
				}
				if ctx.Err() != nil {
					return
				}
				errs <- fmt.Errorf("read ebpf event: %w", err)
				continue
			}

			for _, drop := range readDropCounterDeltas(objs.DropCounters, previousDrops) {
				select {
				case <-ctx.Done():
					return
				case events <- drop:
				}
			}

			var raw rawEBPFEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
				errs <- fmt.Errorf("decode ebpf event: %w", err)
				continue
			}
			// bpf_ktime_get_ns is monotonic boot time; ledger records need wall-clock time.
			raw.TimestampNS = uint64(time.Now().UTC().UnixNano())

			ev, err := convertRawEBPFEventToFlowEvent(raw)
			if err != nil {
				errs <- fmt.Errorf("convert ebpf event: %w", err)
				continue
			}
			ev.LocalRetransAvailable = retransAttached
			if retransAttached {
				ev.LocalRetransSource = LocalRetransSourceTCPRetransmitSKB
			} else {
				// Not attached: counters cannot have been collected; make
				// sure stale zeros never masquerade as measurements.
				ev.LocalRetransSKBCount = 0
				ev.LocalRetransSKBBytes = 0
			}
			c.applyPacketFeatureOptions(&ev)

			select {
			case <-ctx.Done():
				return
			case events <- ev:
			}
		}
	}()

	return events, errs
}

// bpfFlowConfig must stay byte-identical to struct flow_config in
// bpf/flow_events.bpf.c (checked against BTF by TestFlowConfigLayoutMatchesBTF).
type bpfFlowConfig struct {
	TLSHandshakeInspectEnabled uint8
	CollectHeaderAggregates    uint8
	CollectNetFlowV2Histogram  uint8
	_                          [5]uint8
}

// buildBPFFlowConfig maps collector options onto the kernel-side feature
// gates. These bits act inside the BPF program: a 0 makes the kernel skip the
// corresponding updates (and the header-aggregate TCP load) entirely.
func buildBPFFlowConfig(opts EBPFOptions) bpfFlowConfig {
	cfg := bpfFlowConfig{}
	if opts.EnableTLSHandshakeInspect {
		cfg.TLSHandshakeInspectEnabled = 1
	}
	if opts.EnableHeaderAggregates {
		cfg.CollectHeaderAggregates = 1
	}
	if opts.EnableNetFlowV2Histogram {
		cfg.CollectNetFlowV2Histogram = 1
	}
	return cfg
}

func configureBPF(objs *flowEventsObjects, opts EBPFOptions) error {
	var key uint32
	return objs.ConfigMap.Update(key, buildBPFFlowConfig(opts), ebpf.UpdateAny)
}

// startMapStatsSampler launches the low-frequency map occupancy walker. It
// runs entirely off the packet/event hot path: a dedicated goroutine walks
// the four bounded maps every MapStatsInterval (default 15s) and reports
// entry counts through OnMapOccupancy. A failed walk is reported through
// OnMapWalkError and only skips that map for the round — it never stops the
// sampler or the collector.
func (c *EBPFCollector) startMapStatsSampler(ctx context.Context, objs *flowEventsObjects) {
	interval := c.opts.MapStatsInterval
	if interval == 0 {
		interval = defaultMapStatsInterval
	}
	if interval < 0 || (c.opts.OnMapOccupancy == nil && c.opts.OnMapWalkError == nil) {
		return
	}
	maps := []struct {
		name string
		m    *ebpf.Map
	}{
		{"flow_stats", objs.FlowStatsMap},
		{"local_ep", objs.LocalEpToKey},
		{"tls_seen", objs.TlsServerHelloSeenMap},
		{"recv_args", objs.RecvArgsMap},
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			samples := make([]EBPFMapOccupancy, 0, len(maps))
			for _, entry := range maps {
				if entry.m == nil {
					continue
				}
				count, err := countMapEntries(entry.m)
				if err != nil {
					if ctx.Err() != nil {
						// Shutdown race: maps are being closed; not a real
						// walk failure.
						return
					}
					if c.opts.OnMapWalkError != nil {
						c.opts.OnMapWalkError(entry.name, err)
					}
					continue
				}
				samples = append(samples, EBPFMapOccupancy{
					Name:       entry.name,
					Entries:    count,
					MaxEntries: uint64(entry.m.MaxEntries()),
				})
			}
			if len(samples) > 0 && c.opts.OnMapOccupancy != nil {
				c.opts.OnMapOccupancy(samples)
			}
		}
	}()
}

// countMapEntries walks a map's keys and counts them. For LRU/hash maps under
// concurrent kernel updates the count is a point-in-time sample (entries
// created or evicted mid-walk may be missed or double-seen), which is exactly
// good enough for occupancy monitoring.
func countMapEntries(m *ebpf.Map) (uint64, error) {
	var (
		key   []byte
		value []byte
		count uint64
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		count++
	}
	if err := iter.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

func (c *EBPFCollector) readTLSHandshakeEvents(ctx context.Context, reader *ringbuf.Reader, events chan<- FlowEvent, errs chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			errs <- fmt.Errorf("read ebpf tls handshake event: %w", err)
			continue
		}
		var raw rawTLSHandshakeEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			errs <- fmt.Errorf("decode ebpf tls handshake event: %w", err)
			continue
		}
		raw.TimestampNS = uint64(time.Now().UTC().UnixNano())
		ev := convertRawTLSHandshakeEventToFlowEvent(raw)
		select {
		case <-ctx.Done():
			return
		case events <- ev:
		}
	}
}

func (c *EBPFCollector) applyPacketFeatureOptions(ev *FlowEvent) {
	if !c.opts.EnablePacketHistogram {
		ev.PacketSizeHistogram = nil
		ev.PktSizeMin = nil
		ev.PktSizeMax = nil
		ev.RealPacketsSent = 0
		ev.RealPacketsRecv = 0
		ev.ObservedSKBPacketsSource = ""
	}
	// v1alpha3 header aggregates and the NetFlow-v2 histogram have their own
	// kernel-side gates (flow_config.collect_*); the BPF program already skips
	// the updates when disabled. This Go-side clearing is belt-and-suspenders
	// so stale kernel values can never leak: disabled features must surface
	// as null/unobserved, never 0.
	if !c.opts.EnableHeaderAggregates {
		ev.IPTTLMin = nil
		ev.IPTTLMax = nil
		ev.TCPFlagsOut = 0
		ev.TCPFlagsIn = 0
		ev.TCPHeaderObservedOut = false
		ev.TCPHeaderObservedIn = false
		ev.TCPWindowMaxOut = nil
		ev.TCPWindowMaxIn = nil
		ev.IPPktLenMin = nil
		ev.IPPktLenMax = nil
	}
	if !c.opts.EnableNetFlowV2Histogram {
		ev.NetFlowV2IPSizeHistogram = nil
	}
	if !c.opts.EnablePacketTiming {
		ev.IATHistogram = nil
		ev.IdleGapCount = 0
		ev.BurstCount = 0
		ev.PacketTimingAvailable = false
		ev.DirectionDurationOutNS = 0
		ev.DirectionDurationInNS = 0
		ev.DirectionDurationOutObserved = false
		ev.DirectionDurationInObserved = false
	}
}

func isCgroupV2Root(path string) bool {
	if _, err := os.Stat(path + "/cgroup.controllers"); err != nil {
		return false
	}
	return true
}

func readDropCounterDeltas(dropCounters *ebpf.Map, previous map[uint32]uint64) []FlowEvent {
	if dropCounters == nil {
		return nil
	}
	var out []FlowEvent
	for idx, reason := range map[uint32]string{
		0: "map_update_failed",
		1: "ringbuf_reserve_failed",
		2: "unsupported_family",
		3: "recv_arg_missed",
		4: "tls_buffer_reserve_failed",
		5: "tls_server_hello_no_stats",
		6: "unsupported_ipv6",
		7: "packet_ep_miss",
		8: "retrans_flow_miss",
		9: "degenerate_key",
	} {
		var total uint64
		if err := dropCounters.Lookup(idx, &total); err != nil {
			continue
		}
		delta := total - previous[idx]
		previous[idx] = total
		if delta == 0 {
			continue
		}
		out = append(out, FlowEvent{
			TimestampNS: uint64(time.Now().UTC().UnixNano()),
			EventType:   "DROP",
			DropReason:  reason,
			DropCount:   delta,
		})
	}
	return out
}
