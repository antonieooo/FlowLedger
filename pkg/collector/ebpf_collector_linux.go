//go:build linux

package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -target amd64,arm64 flowEvents ../../bpf/flow_events.bpf.c -- -g

type EBPFCollector struct{}

func NewEBPFCollector() *EBPFCollector {
	return &EBPFCollector{}
}

func (c *EBPFCollector) Run(ctx context.Context) (<-chan FlowEvent, <-chan error) {
	events := make(chan FlowEvent)
	errs := make(chan error, 8)

	go func() {
		defer close(events)
		defer close(errs)

		if err := rlimit.RemoveMemlock(); err != nil {
			errs <- fmt.Errorf("remove memlock limit: %w", err)
			return
		}

		var objs flowEventsObjects
		if err := loadFlowEventsObjects(&objs, nil); err != nil {
			errs <- fmt.Errorf("load ebpf objects: %w", err)
			return
		}
		defer objs.Close()

		tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleInetSockSetState, nil)
		if err != nil {
			errs <- fmt.Errorf("attach sock/inet_sock_set_state tracepoint: %w", err)
			return
		}
		defer tp.Close()

		reader, err := ringbuf.NewReader(objs.Events)
		if err != nil {
			errs <- fmt.Errorf("open ebpf events ringbuf: %w", err)
			return
		}
		defer reader.Close()

		go func() {
			<-ctx.Done()
			_ = reader.Close()
		}()

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

			var raw rawEBPFEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
				errs <- fmt.Errorf("decode ebpf event: %w", err)
				continue
			}

			ev, err := convertRawEBPFEventToFlowEvent(raw)
			if err != nil {
				errs <- fmt.Errorf("convert ebpf event: %w", err)
				continue
			}

			select {
			case <-ctx.Done():
				return
			case events <- ev:
			}
		}
	}()

	return events, errs
}
