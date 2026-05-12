//go:build !linux

package collector

import (
	"context"
	"errors"
	"time"
)

type EBPFCollector struct{}

type EBPFOptions struct {
	FlowMapMaxEntries       uint32
	StatsEmitInterval       time.Duration
	EnableTrafficAccounting bool
	EnableTCPBasicMetrics   bool
	EnablePacketTiming      bool
	EnablePacketHistogram   bool
}

func NewEBPFCollector() *EBPFCollector {
	return &EBPFCollector{}
}

func NewEBPFCollectorWithOptions(EBPFOptions) *EBPFCollector {
	return &EBPFCollector{}
}

func (c *EBPFCollector) Run(ctx context.Context) (<-chan FlowEvent, <-chan error) {
	events := make(chan FlowEvent)
	errs := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errs)
		errs <- errors.New("ebpf collector is a v0 stub; use --mode mock for local validation")
		<-ctx.Done()
	}()
	return events, errs
}
