// Package failure writes the capture_failed record the collector leaves
// when it cannot witness anything.
//
// The shape matches CaptureFailedPayload in packages/core, so the merge
// turns it into a gap event with reason capture_failed and the bundle
// says "kernel witnessing was asked for and did not happen" instead of
// looking like a session where nothing ran outside the hook.
package failure

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/record"
)

// maxMessageChars caps the recorded message, matching the hook's own cap.
const maxMessageChars = 300

// Payload is the capture_failed record shape.
type Payload struct {
	Kind                 string  `json:"kind"`
	Phase                string  `json:"phase"`
	ErrorClass           string  `json:"errorClass"`
	Message              string  `json:"message"`
	MonoNs               string  `json:"monoNs"`
	CapturedAt           string  `json:"capturedAt"`
	SessionID            *string `json:"sessionId"`
	ToolName             *string `json:"toolName"`
	Source               string  `json:"source"`
	CaptureSchemaVersion int     `json:"captureSchemaVersion"`
}

// Write records why the collector could not run.
//
// @param dir - The capture store.
// @param phase - Where it gave up, e.g. "ebpf-attach".
// @param cause - The error to record; only its first line is kept.
// @param sessionID - The session the collector was serving, may be empty.
// @returns The path written, or an error if the store is unwritable.
func Write(dir, phase string, cause error, sessionID string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create capture directory %s: %w", dir, err)
	}
	var session *string
	if sessionID != "" {
		session = &sessionID
	}
	now := time.Now()
	payload := Payload{
		Kind:                 "capture_failed",
		Phase:                phase,
		ErrorClass:           errorClass(cause),
		Message:              sanitize(cause.Error()),
		MonoNs:               fmt.Sprint(uint64(now.UnixNano())),
		CapturedAt:           now.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		SessionID:            session,
		ToolName:             nil,
		Source:               "kernel",
		CaptureSchemaVersion: record.SchemaVersion,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode capture_failed record: %w", err)
	}
	id, err := record.NewULID(now)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write capture_failed record %s: %w", path, err)
	}
	return path, nil
}

// errorClass names the failure without leaking a wrapped chain into
// signed evidence. Go errors have no class, so the phase carries the
// detail and this stays a stable label.
func errorClass(cause error) string {
	if cause == nil {
		return "Error"
	}
	return "CollectorError"
}

// sanitize keeps the first line, strips control characters, and caps the
// length, matching sanitizeErrorMessage in packages/capture-claude.
func sanitize(message string) string {
	first := message
	if idx := strings.IndexAny(first, "\r\n"); idx >= 0 {
		first = first[:idx]
	}
	var b strings.Builder
	for _, r := range first {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > maxMessageChars {
		return out[:maxMessageChars-3] + "..."
	}
	return out
}
