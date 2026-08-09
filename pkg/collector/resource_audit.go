//go:build 386 || amd64 || arm64

package collector

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// EBPFStructAudit is the BTF-reported size of one kernel-shared struct.
type EBPFStructAudit struct {
	Name      string `json:"name"`
	SizeBytes uint32 `json:"size_bytes"`
}

// EBPFMapAudit describes one non-ringbuf map's static resource bounds.
// RawPayloadUpperBoundBytes is max_entries × (key + value) — the raw payload
// ceiling only; kernel per-entry bookkeeping (hash buckets, LRU lists) comes
// on top and is not included.
type EBPFMapAudit struct {
	Name                      string `json:"name"`
	Type                      string `json:"type"`
	MaxEntries                uint32 `json:"max_entries"`
	KeySizeBytes              uint32 `json:"key_size_bytes"`
	ValueSizeBytes            uint32 `json:"value_size_bytes"`
	RawPayloadUpperBoundBytes uint64 `json:"raw_payload_upper_bound_bytes"`
}

// EBPFRingbufAudit describes one ring buffer. NominalEventCapacity is how
// many fixed-size records of EventStruct fit when the buffer is full,
// accounting for the kernel's 8-byte per-record header and 8-byte record
// alignment; variable-sized producers (none today) would change this.
type EBPFRingbufAudit struct {
	Name                 string `json:"name"`
	SizeBytes            uint32 `json:"size_bytes"`
	EventStruct          string `json:"event_struct"`
	EventSizeBytes       uint32 `json:"event_size_bytes"`
	NominalEventCapacity uint32 `json:"nominal_event_capacity"`
}

// EBPFResourceReport is a static, read-only audit of the compiled BPF
// object's resource envelope: BTF struct sizes, map bounds, and ring buffer
// capacities. It is computed purely from the object file embedded in this
// binary — nothing is loaded into the kernel and no cluster is contacted.
type EBPFResourceReport struct {
	Structs  []EBPFStructAudit  `json:"structs"`
	Maps     []EBPFMapAudit     `json:"maps"`
	Ringbufs []EBPFRingbufAudit `json:"ringbufs"`
}

// ringbufEventStructs maps each ring buffer to the fixed-size struct its
// producers reserve.
var ringbufEventStructs = map[string]string{
	"events":               "flow_event",
	"tls_handshake_events": "tls_handshake_event",
}

// auditedStructNames are the kernel-shared structs worth reporting; unknown
// names are skipped silently so the audit keeps working across schema
// versions.
var auditedStructNames = []string{
	"flow_key",
	"flow_stats",
	"flow_event",
	"flow_config",
	"local_ep",
	"tls_handshake_event",
}

// AuditEBPFResources parses the embedded BPF object (CollectionSpec only — no
// program load, no map creation, no kernel or cluster interaction) and
// returns its static resource envelope.
func AuditEBPFResources() (*EBPFResourceReport, error) {
	spec, err := loadFlowEvents()
	if err != nil {
		return nil, fmt.Errorf("parse embedded BPF object: %w", err)
	}
	if spec.Types == nil {
		return nil, fmt.Errorf("embedded BPF object carries no BTF")
	}

	report := &EBPFResourceReport{}

	structSizes := map[string]uint32{}
	for _, name := range auditedStructNames {
		var s *btf.Struct
		if err := spec.Types.TypeByName(name, &s); err != nil {
			continue
		}
		structSizes[name] = s.Size
		report.Structs = append(report.Structs, EBPFStructAudit{Name: name, SizeBytes: s.Size})
	}

	mapNames := make([]string, 0, len(spec.Maps))
	for name := range spec.Maps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	for _, name := range mapNames {
		ms := spec.Maps[name]
		if ms.Type == ebpf.RingBuf {
			eventStruct := ringbufEventStructs[name]
			eventSize := structSizes[eventStruct]
			capacity := uint32(0)
			if eventSize > 0 {
				// 8-byte kernel record header, records rounded up to 8.
				recordBytes := (8 + eventSize + 7) &^ 7
				capacity = ms.MaxEntries / recordBytes
			}
			report.Ringbufs = append(report.Ringbufs, EBPFRingbufAudit{
				Name:                 name,
				SizeBytes:            ms.MaxEntries, // ringbuf max_entries is its size in bytes
				EventStruct:          eventStruct,
				EventSizeBytes:       eventSize,
				NominalEventCapacity: capacity,
			})
			continue
		}
		report.Maps = append(report.Maps, EBPFMapAudit{
			Name:                      name,
			Type:                      ms.Type.String(),
			MaxEntries:                ms.MaxEntries,
			KeySizeBytes:              ms.KeySize,
			ValueSizeBytes:            ms.ValueSize,
			RawPayloadUpperBoundBytes: uint64(ms.MaxEntries) * uint64(ms.KeySize+ms.ValueSize),
		})
	}
	return report, nil
}
