//go:build !linux

package collector

import (
	"context"
	"testing"
)

func TestEBPFCollectorUnsupportedNonLinux(t *testing.T) {
	_, errs := NewEBPFCollector().Run(context.Background())
	if err := <-errs; err == nil {
		t.Fatal("expected unsupported eBPF collector error")
	}
}
