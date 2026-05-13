package ledger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"FlowLedger/pkg/experiment"
	"FlowLedger/pkg/features"
	"FlowLedger/pkg/identity"
	"FlowLedger/pkg/sessionizer"
)

func TestLedgerWriterJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	record := Record{
		RecordType: "session_summary",
		FlowID:     "flow-1",
		NodeName:   "node-a",
		SrcIP:      "10.1.1.10",
		SrcPort:    40000,
		DstIP:      "10.1.1.20",
		DstPort:    443,
		Protocol:   "tcp",
	}
	if err := w.Write(record); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got Record
	if err := json.Unmarshal(b[:len(b)-1], &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got.FlowID != "flow-1" || got.RecordType != "session_summary" || got.DstPort != 443 {
		t.Fatalf("unexpected record: %#v", got)
	}
}

func TestBuildRecordV1Alpha2Fields(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	ratio := 2.0
	session := sessionizer.FlowSession{
		RecordType:           "session_summary",
		FlowID:               "flow-1",
		NodeName:             "node-a",
		StartTime:            now,
		EndTime:              now.Add(time.Second),
		DurationMS:           1000,
		SrcIP:                "10.1.1.10",
		SrcPort:              40000,
		DstIP:                "1.1.1.1",
		DstPort:              443,
		Protocol:             "tcp",
		IPFamily:             "ipv4",
		BytesOut:             200,
		BytesIn:              100,
		PacketsOut:           2,
		PacketsIn:            1,
		CloseReason:          "fin",
		HandshakeSeen:        true,
		TLSVersion:           "1.3",
		ALPN:                 "h2",
		JA4:                  "t13d1516h2_8daaf6152771_e5627efa2ab1",
		TLSParseStatus:       "parsed",
		ServerHelloSeen:      true,
		TLSVersionNegotiated: "1.2",
		ALPNNegotiated:       "h2",
		JA4S:                 "t1201h2_c02f_0b08e3dcc50f",
		TLSServerParseStatus: "parsed",
		FeatureSnapshot: features.Snapshot{
			BytesTotal:                 300,
			PacketsTotal:               3,
			ByteRatioOutIn:             &ratio,
			PktSizeHistogram:           features.EmptyPacketSizeHistogram(),
			TrafficAccountingAvailable: true,
		},
	}
	resolved := identity.ResolvedFlow{
		Src: identity.EndpointIdentity{
			Namespace:  "default",
			PodName:    "api",
			Confidence: "high",
			Method:     "pod_ip",
		},
		Dst: identity.EndpointIdentity{
			External:   true,
			Confidence: "low",
			Method:     "external",
		},
		MappingMethod: "external",
	}

	record := BuildRecordWithContext(session, resolved, experiment.Labels{
		ExperimentID:  "exp-1",
		ScenarioLabel: "baseline",
	}, BuildContext{
		ClusterID:      "kind-thesis",
		AgentID:        "node-a/pod-a",
		CollectionMode: "mock",
		HookSource:     "mock",
	})
	if record.SchemaVersion != features.SchemaVersion || record.FeatureSetVersion != features.FeatureSetVersion {
		t.Fatalf("unexpected schema/feature versions: %#v", record)
	}
	if record.PayloadCollected || record.ProtocolGuess != "tls" || !record.IsTLSLike || !record.ReviewRequired {
		t.Fatalf("unexpected reserved/model fields: %#v", record)
	}
	if record.Direction != "egress" || record.BytesTotal != 300 || record.ByteRatioOutIn == nil || *record.ByteRatioOutIn != 2 {
		t.Fatalf("unexpected derived fields: %#v", record)
	}

	b, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatalf("json.Unmarshal map: %v", err)
	}
	for _, forbidden := range []string{"payload", "raw_payload", "http_path", "http_headers", "http_body"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("record contains forbidden field %q: %s", forbidden, b)
		}
	}
	if record.JA4 == "" || record.JA4S == "" || !record.ServerHelloSeen || record.TLSVersionNegotiated != "1.2" {
		t.Fatalf("missing TLS client/server fields: %#v", record)
	}
	if strings.Contains(string(b), "http_path") || strings.Contains(string(b), "http_headers") || strings.Contains(string(b), "http_body") {
		t.Fatalf("record contains forbidden HTTP payload metadata: %s", b)
	}
}

func TestLedgerWriterRotatesBySize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flows.jsonl")
	w, err := NewWriterWithOptions(WriterOptions{Path: path, MaxBytes: 1})
	if err != nil {
		t.Fatalf("NewWriterWithOptions: %v", err)
	}

	for _, flowID := range []string{"flow-1", "flow-2"} {
		if err := w.Write(Record{RecordType: "session_summary", FlowID: flowID}); err != nil {
			t.Fatalf("Write(%s): %v", flowID, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rotated, err := filepath.Glob(filepath.Join(dir, "flows-*.jsonl"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(rotated) != 1 {
		t.Fatalf("rotated files = %v, want 1 file", rotated)
	}
	assertJSONLLines(t, rotated[0], 1)
	assertJSONLLines(t, path, 1)
}

func assertJSONLLines(t *testing.T, path string, wantLines int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	defer f.Close()

	var lines int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines++
		var got Record
		if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
			t.Fatalf("json.Unmarshal(%s line %d): %v", path, lines, err)
		}
		if got.FlowID == "" {
			t.Fatalf("missing flow_id in %s line %d", path, lines)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("Scan(%s): %v", path, err)
	}
	if lines != wantLines {
		t.Fatalf("%s lines = %d, want %d", path, lines, wantLines)
	}
}
