package failure

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordsWhyTheCollectorCouldNotWitnessAnything(t *testing.T) {
	dir := t.TempDir()
	cause := errors.New("load the execve probe: operation not permitted; needs CAP_BPF (or root)")

	path, err := Write(dir, "ebpf-attach", cause, "sess-kernel")
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}

	var parsed map[string]interface{}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	// The reader requires kind, phase, errorClass, message, and a
	// parseable capturedAt; anything short of that is dropped as
	// malformed and the failure would go unrecorded.
	for _, field := range []string{"kind", "phase", "errorClass", "message", "capturedAt"} {
		if _, ok := parsed[field].(string); !ok {
			t.Errorf("field %s missing or not a string: %v", field, parsed[field])
		}
	}
	if parsed["kind"] != "capture_failed" {
		t.Errorf("kind = %v", parsed["kind"])
	}
	if parsed["source"] != "kernel" {
		t.Errorf("source = %v, want kernel so the gap says which collector failed", parsed["source"])
	}
	if parsed["phase"] != "ebpf-attach" {
		t.Errorf("phase = %v", parsed["phase"])
	}
	if !strings.Contains(parsed["message"].(string), "CAP_BPF") {
		t.Errorf("message = %v; it has to say what privilege was missing", parsed["message"])
	}
	if parsed["sessionId"] != "sess-kernel" {
		t.Errorf("sessionId = %v", parsed["sessionId"])
	}
	if filepath.Ext(path) != ".json" {
		t.Errorf("record path %s is not a .json file", path)
	}
}

func TestASessionlessFailureRecordsNullRatherThanAnEmptyString(t *testing.T) {
	path, err := Write(t.TempDir(), "ebpf-unsupported", errors.New("no eBPF here"), "")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["sessionId"] != nil {
		t.Errorf("sessionId = %v, want null", parsed["sessionId"])
	}
}

func TestMessageKeepsOneLineAndDropsControlCharacters(t *testing.T) {
	cause := errors.New("first line\x07here\nsecond line should not appear")
	path, err := Write(t.TempDir(), "ebpf-attach", cause, "s")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	message := parsed["message"].(string)
	if strings.Contains(message, "second line") {
		t.Errorf("message = %q, want the first line only", message)
	}
	if strings.ContainsRune(message, '\x07') {
		t.Errorf("message = %q still carries a control character", message)
	}
}

func TestALongMessageIsCappedRatherThanTruncatingTheRecord(t *testing.T) {
	path, err := Write(t.TempDir(), "ebpf-attach", errors.New(strings.Repeat("x", 900)), "s")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	message := parsed["message"].(string)
	if len(message) != maxMessageChars {
		t.Errorf("message length = %d, want %d", len(message), maxMessageChars)
	}
	if !strings.HasSuffix(message, "...") {
		t.Errorf("a capped message must say it was capped: %q", message[len(message)-10:])
	}
}
