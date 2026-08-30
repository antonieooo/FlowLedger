//go:build linux && (386 || amd64)

package collector

import (
	"testing"

	"github.com/cilium/ebpf/btf"
)

// v1alpha6's `established` gate is deliberately KERNEL-INTERNAL: it lives in
// struct flow_stats only, carved out of that struct's existing tail padding.
// If it ever leaks into struct flow_event it becomes a ledger field, and
// v1alpha6's whole claim ("no new field, only a new fill time") is void.
func TestEstablishedGateIsKernelInternal(t *testing.T) {
	spec, err := loadFlowEvents()
	if err != nil {
		t.Fatalf("loadFlowEvents: %v", err)
	}
	var flowStats, flowEvent *btf.Struct
	if err := spec.Types.TypeByName("flow_stats", &flowStats); err != nil {
		t.Fatalf("BTF lookup of struct flow_stats: %v", err)
	}
	if err := spec.Types.TypeByName("flow_event", &flowEvent); err != nil {
		t.Fatalf("BTF lookup of struct flow_event: %v", err)
	}

	has := func(s *btf.Struct, name string) bool {
		for _, m := range s.Members {
			if m.Name == name {
				return true
			}
		}
		return false
	}
	if !has(flowStats, "established") {
		t.Errorf("struct flow_stats has no `established` member — the v1alpha6 write barrier has nothing to gate on")
	}
	if has(flowEvent, "established") {
		t.Errorf("struct flow_event exposes `established`: v1alpha6 must not add a ledger field")
	}

	// Carved out of padding, so neither struct may have grown. flow_event in
	// particular must be byte-identical to v1alpha5 — rawEBPFEvent and every
	// hand-computed offset in ebpf_event_test.go still assume 600.
	if flowStats.Size != 600 {
		t.Errorf("flow_stats = %d bytes, want 600 (v1alpha6 must reuse padding, not grow)", flowStats.Size)
	}
	if flowEvent.Size != 600 {
		t.Errorf("flow_event = %d bytes, want 600 (unchanged from v1alpha5)", flowEvent.Size)
	}
}
