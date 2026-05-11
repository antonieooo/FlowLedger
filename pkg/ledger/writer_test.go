package ledger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
