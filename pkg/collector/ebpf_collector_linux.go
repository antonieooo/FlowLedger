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

//go:generate go tool bpf2go -no-strip -target amd64,arm64 flowEvents ../../bpf/flow_events.bpf.c -- -g

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
}

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

		var ingressCG, egressCG link.Link
		if c.opts.EnablePacketHistogram || c.opts.EnablePacketTiming || c.opts.EnableTLSHandshakeInspect {
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

type bpfFlowConfig struct {
	TLSHandshakeInspectEnabled uint8
	_                          [7]uint8
}

func configureBPF(objs *flowEventsObjects, opts EBPFOptions) error {
	cfg := bpfFlowConfig{}
	if opts.EnableTLSHandshakeInspect {
		cfg.TLSHandshakeInspectEnabled = 1
	}
	var key uint32
	return objs.ConfigMap.Update(key, cfg, ebpf.UpdateAny)
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
	}
	if !c.opts.EnablePacketTiming {
		ev.IATHistogram = nil
		ev.IdleGapCount = 0
		ev.BurstCount = 0
		ev.PacketTimingAvailable = false
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
