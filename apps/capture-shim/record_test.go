// apps/capture-shim/record_test.go
//
// Capture records written here become events in a signed evidence bundle,
// so their shape and their file permissions both matter. The v2 fields
// (capturedAt, capturedAtSource, sessionId) are what let the normalizer
// scope a bundle to one session and timestamp events with the capture
// time rather than the bundle production time.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readRecord(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("record is not valid JSON: %v", err)
	}
	return record
}

func TestWriteCaptureRecordWritesV2Schema(t *testing.T) {
	captureDir := filepath.Join(t.TempDir(), "captures")
	t.Setenv("DEPOSE_CAPTURE_DIR", captureDir)

	before := time.Now().UTC().Add(-time.Second)
	path, err := writeCaptureRecord("terraform", []string{"destroy", "-auto-approve"})
	if err != nil {
		t.Fatalf("writeCaptureRecord: %v", err)
	}
	after := time.Now().UTC().Add(time.Second)

	record := readRecord(t, path)

	if got := record["captureSchemaVersion"]; got != float64(2) {
		t.Errorf("captureSchemaVersion = %v, want 2", got)
	}
	if got := record["capturedAtSource"]; got != "recorded" {
		t.Errorf("capturedAtSource = %v, want \"recorded\"", got)
	}
	// The shim runs outside any agent session, so it must say so rather
	// than inventing an association. Unattributed records stay out of a
	// bundle unless the producer opts in.
	if got, ok := record["sessionId"]; !ok || got != nil {
		t.Errorf("sessionId = %v, want null", got)
	}

	capturedAt, ok := record["capturedAt"].(string)
	if !ok {
		t.Fatalf("capturedAt missing or not a string: %v", record["capturedAt"])
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", capturedAt)
	if err != nil {
		t.Fatalf("capturedAt %q is not ISO 8601 UTC: %v", capturedAt, err)
	}
	if parsed.Before(before) || parsed.After(after) {
		t.Errorf("capturedAt %v is outside the window [%v, %v]", parsed, before, after)
	}
}

func TestWriteCaptureRecordPreservesArgv(t *testing.T) {
	captureDir := filepath.Join(t.TempDir(), "captures")
	t.Setenv("DEPOSE_CAPTURE_DIR", captureDir)

	path, err := writeCaptureRecord("rm", []string{"-rf", "/data/training"})
	if err != nil {
		t.Fatalf("writeCaptureRecord: %v", err)
	}

	record := readRecord(t, path)
	argv, ok := record["argv"].([]any)
	if !ok {
		t.Fatalf("argv missing or not an array: %v", record["argv"])
	}
	// argv[0] is the name the shim was invoked as, not the resolved path.
	want := []string{"rm", "-rf", "/data/training"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
	for i, w := range want {
		if argv[i] != w {
			t.Errorf("argv[%d] = %v, want %q", i, argv[i], w)
		}
	}
	if record["source"] != "shell-shim" {
		t.Errorf("source = %v, want \"shell-shim\"", record["source"])
	}
}

func TestWriteCaptureRecordUsesRestrictivePermissions(t *testing.T) {
	captureDir := filepath.Join(t.TempDir(), "captures")
	t.Setenv("DEPOSE_CAPTURE_DIR", captureDir)

	path, err := writeCaptureRecord("psql", []string{"-c", "DROP TABLE users"})
	if err != nil {
		t.Fatalf("writeCaptureRecord: %v", err)
	}

	// Records hold argv and an env subset, so they must not be world-readable.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat record: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("record mode = %04o, want 0600", perm)
	}

	dirInfo, err := os.Stat(captureDir)
	if err != nil {
		t.Fatalf("stat capture dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("capture dir mode = %04o, want 0700", perm)
	}
}

func TestWriteCaptureRecordCreatesMissingCaptureDir(t *testing.T) {
	captureDir := filepath.Join(t.TempDir(), "nested", "captures")
	t.Setenv("DEPOSE_CAPTURE_DIR", captureDir)

	if _, err := writeCaptureRecord("aws", []string{"s3", "rb", "--force"}); err != nil {
		t.Fatalf("writeCaptureRecord into a missing dir: %v", err)
	}
	if _, err := os.Stat(captureDir); err != nil {
		t.Errorf("capture dir was not created: %v", err)
	}
}

func TestGenerateULIDIsAValidCrockfordULID(t *testing.T) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		ulid := generateULID()
		if len(ulid) != 26 {
			t.Fatalf("ULID %q has length %d, want 26", ulid, len(ulid))
		}
		for _, ch := range ulid {
			// I, L, O and U are excluded from the Crockford alphabet. The
			// TypeScript normalizer rejects filenames that are not valid
			// ULIDs, so a shim record with a stray character never lands
			// in a bundle.
			if !containsRune(alphabet, ch) {
				t.Fatalf("ULID %q contains %q, which is outside the Crockford alphabet", ulid, ch)
			}
		}
		if seen[ulid] {
			t.Fatalf("generateULID returned a duplicate: %q", ulid)
		}
		seen[ulid] = true
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
