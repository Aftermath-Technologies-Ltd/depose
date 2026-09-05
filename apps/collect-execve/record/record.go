// Package record writes kernel-witnessed execve records into the DEPOSE
// capture store, in the shape packages/core reads back
// (ExecveRecordPayload in payloads-capture.ts).
//
// The store is a flat directory of ULID-named JSON files with 0600
// permissions. The reader tells record kinds apart by the `kind` field,
// so this package only has to get that field and the ULID right.
package record

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Kind is the discriminator packages/core dispatches on.
const Kind = "execve"

// SchemaVersion is the capture record schema this collector writes.
const SchemaVersion = 3

// Execve is one kernel-witnessed exec, enriched from /proc.
//
// Argv, Exe, and Cwd come from procfs after the fact, so they are empty
// when the process had already exited. An empty Argv is evidence in its
// own right (an exec happened and could not be characterized) and is
// never filled in with a guess.
type Execve struct {
	Kind     string   `json:"kind"`
	PID      int      `json:"pid"`
	PPID     int      `json:"ppid"`
	Ancestry []int    `json:"ancestry"`
	Comm     string   `json:"comm"`
	Exe      string   `json:"exe"`
	Argv     []string `json:"argv"`
	Cwd      string   `json:"cwd"`
	// MonoNs is CLOCK_MONOTONIC nanoseconds at exec, as a decimal string:
	// the wire form is a string so a value past 2^53 survives a JSON
	// round trip through the TypeScript reader.
	MonoNs               string  `json:"monoNs"`
	CapturedAt           string  `json:"capturedAt"`
	SessionID            *string `json:"sessionId"`
	Source               string  `json:"source"`
	CaptureSchemaVersion int     `json:"captureSchemaVersion"`
}

// New builds a record with the constant fields filled in.
//
// Returns a record ready for Write; the caller supplies everything the
// kernel and procfs provided.
func New(pid, ppid int, ancestry []int, comm, exe string, argv []string, cwd string, monoNs uint64, capturedAt time.Time, sessionID string) Execve {
	var session *string
	if sessionID != "" {
		session = &sessionID
	}
	if ancestry == nil {
		ancestry = []int{}
	}
	if argv == nil {
		argv = []string{}
	}
	return Execve{
		Kind:                 Kind,
		PID:                  pid,
		PPID:                 ppid,
		Ancestry:             ancestry,
		Comm:                 comm,
		Exe:                  exe,
		Argv:                 argv,
		Cwd:                  cwd,
		MonoNs:               fmt.Sprint(monoNs),
		CapturedAt:           capturedAt.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		SessionID:            session,
		Source:               "kernel",
		CaptureSchemaVersion: SchemaVersion,
	}
}

// Write stores one record as <dir>/<ulid>.json with 0600 permissions.
//
// @param dir - The capture store directory; created 0700 if absent.
// @param r - The record to write.
// @returns The path written, or an error naming the directory to fix.
func Write(dir string, r Execve) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create capture directory %s: %w; set DEPOSE_CAPTURE_DIR to a writable path", dir, err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode execve record: %w", err)
	}
	id, err := NewULID(time.Now())
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write capture record %s: %w", path, err)
	}
	return path, nil
}

// crockford is the ULID alphabet (Crockford base32, no I, L, O, or U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a ULID for the given time: 10 characters of timestamp
// in milliseconds then 16 characters of randomness, matching the ids
// packages/core generates so the reader can use the filename as the
// event id.
//
// @param at - The record's time.
// @returns The 26-character ULID, or an error if the system CSPRNG fails.
func NewULID(at time.Time) (string, error) {
	ms := uint64(at.UnixMilli())
	out := make([]byte, 26)
	for i := 9; i >= 0; i-- {
		out[i] = crockford[ms&0x1f]
		ms >>= 5
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes for a capture record id: %w", err)
	}
	for i, b := range buf {
		out[10+i] = crockford[b&0x1f]
	}
	return string(out), nil
}
