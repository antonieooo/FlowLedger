// ebpf-resource-audit prints the static resource envelope of the BPF object
// compiled into FlowLedger: BTF struct sizes, map max_entries and raw payload
// upper bounds, ring buffer sizes and nominal event capacities.
//
// It is strictly READ-ONLY: the embedded object is parsed in userspace only —
// no BPF program is loaded, no map is created, and no kubeconfig, kubelet, or
// cluster API is ever touched. Safe to run anywhere the binary runs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"FlowLedger/pkg/collector"
)

func main() {
	jsonOut := flag.Bool("json", false, "emit the report as JSON instead of a table")
	flag.Parse()

	report, err := collector.AuditEBPFResources()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ebpf-resource-audit: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "ebpf-resource-audit: encode: %v\n", err)
			os.Exit(1)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "== BTF struct sizes")
	fmt.Fprintln(w, "STRUCT\tSIZE(B)")
	for _, s := range report.Structs {
		fmt.Fprintf(w, "%s\t%d\n", s.Name, s.SizeBytes)
	}
	fmt.Fprintln(w, "\n== Maps (raw payload upper bound = max_entries × (key+value); kernel per-entry overhead excluded)")
	fmt.Fprintln(w, "MAP\tTYPE\tMAX_ENTRIES\tKEY(B)\tVALUE(B)\tPAYLOAD_UPPER_BOUND")
	for _, m := range report.Maps {
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\n",
			m.Name, m.Type, m.MaxEntries, m.KeySizeBytes, m.ValueSizeBytes,
			humanBytes(m.RawPayloadUpperBoundBytes))
	}
	fmt.Fprintln(w, "\n== Ring buffers (nominal capacity assumes fixed-size records incl. 8B kernel header, 8B alignment)")
	fmt.Fprintln(w, "RINGBUF\tSIZE\tEVENT_STRUCT\tEVENT(B)\tNOMINAL_CAPACITY")
	for _, r := range report.Ringbufs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\n",
			r.Name, humanBytes(uint64(r.SizeBytes)), r.EventStruct, r.EventSizeBytes, r.NominalEventCapacity)
	}
	w.Flush()
}

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
