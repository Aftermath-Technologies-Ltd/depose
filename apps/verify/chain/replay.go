// Package chain, IRONROOT hash chain replay for verification.
package chain

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/canonical"
)

// Event represents a minimal event for chain verification.
type Event struct {
	ID            string          `json:"id"`
	WallTs        string          `json:"wallTs"`
	MonoNs        int             `json:"monoNs"`
	SessionID     string          `json:"sessionId"`
	AgentID       string          `json:"agentId"`
	ParentEventID *string         `json:"parentEventId"`
	Type          string          `json:"type"`
	Payload       json.RawMessage `json:"payload"`
	PayloadHash   string          `json:"payloadHash"`
	ChainHash     string          `json:"chainHash,omitempty"`
}

// EventMetadata is the set of fields included in chain hash computation.
type EventMetadata struct {
	ID            string          `json:"id"`
	WallTs        string          `json:"wallTs"`
	MonoNs        int             `json:"monoNs"`
	SessionID     string          `json:"sessionId"`
	AgentID       string          `json:"agentId"`
	ParentEventID *string         `json:"parentEventId"`
	Type          string          `json:"type"`
	PayloadHash   string          `json:"payloadHash"`
}

// ReplayResult holds the outcome of chain replay.
type ReplayResult struct {
	RootHash          string
	EventCount        int
	HashMismatches    []HashMismatch
	PayloadMismatches []PayloadMismatch
}

// HashMismatch records a chain hash mismatch at a specific event.
type HashMismatch struct {
	Index    int
	EventID  string
	Expected string
	Computed string
}

// PayloadMismatch records a recomputed payloadHash that does not match
// the value stored on the event. Detecting this is what closes the
// payload-tamper hole: without re-deriving payloadHash from the
// payload bytes, an attacker could rewrite payload content and leave
// the chain hash intact.
type PayloadMismatch struct {
	Index    int
	EventID  string
	Expected string
	Computed string
}

// ReplayChain reads events.jsonl and replays the IRONROOT hash chain.
//
// Chain construction (verbatim from BUILD_PLAN.md §6):
//
//	chainHash[0] = SHA-256( zero32 || payloadHash[0] || eventMetadata[0] )
//	chainHash[i] = SHA-256( chainHash[i-1] || payloadHash[i] || eventMetadata[i] )
//	rootHash     = chainHash[N-1]
//
// Returns the computed root hash and any mismatches.
func ReplayChain(bundleDir string) (*ReplayResult, error) {
	path := filepath.Join(bundleDir, "events.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open events.jsonl: %w", err)
	}
	defer f.Close()

	var events []Event
	scanner := bufio.NewScanner(f)
	// Increase buffer size for large lines
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var evt Event
		if err := json.Unmarshal(line, &evt); err != nil {
			return nil, fmt.Errorf("parse event: %w", err)
		}
		events = append(events, evt)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read events.jsonl: %w", err)
	}

	if len(events) == 0 {
		return &ReplayResult{RootHash: "", EventCount: 0}, nil
	}

	// Sort events by id (ULID) for deterministic replay
	// (they should already be sorted, but we verify)
	sortEventsByID(events)

	var prevHash [32]byte // zero32 for first event
	var mismatches []HashMismatch
	var payloadMismatches []PayloadMismatch

	for i, evt := range events {
		// ── Recompute payloadHash from the actual payload bytes ──
		// Without this step, payloadHash is trusted from disk and the
		// chain replay only proves the recorded payloadHash is
		// internally consistent, not that the recorded payload
		// canonicalizes to that hash. An attacker can then rewrite
		// payload content without touching payloadHash and the chain
		// still validates. We close that hole here by re-canonicalizing
		// the payload through the JCS marshaller and SHA-256'ing it.
		computedPayloadHash, err := recomputePayloadHash(evt.Payload)
		if err != nil {
			return nil, fmt.Errorf("recompute payloadHash for event %s: %w", evt.ID, err)
		}
		if computedPayloadHash != evt.PayloadHash {
			payloadMismatches = append(payloadMismatches, PayloadMismatch{
				Index:    i,
				EventID:  evt.ID,
				Expected: evt.PayloadHash,
				Computed: computedPayloadHash,
			})
		}

		// Compute eventMetadata as canonical JSON of the metadata fields.
		// Go's json.Marshal on structs uses field declaration order, which may
		// not match the TypeScript canonical-json (alphabetical key sort).
		// Use a map to guarantee alphabetical key ordering, matching the
		// TypeScript canonicalJson implementation (sorted keys, minified).
		// Dereference *string so canonical.Marshal sees a plain
		// string (or nil) rather than an unsupported *string type.
		var parentEventID interface{}
		if evt.ParentEventID != nil {
			parentEventID = *evt.ParentEventID
		}

		metadataMap := map[string]interface{}{
			"id":            evt.ID,
			"wallTs":        evt.WallTs,
			"monoNs":        evt.MonoNs,
			"sessionId":     evt.SessionID,
			"agentId":       evt.AgentID,
			"parentEventId": parentEventID,
			"type":          evt.Type,
			"payloadHash":   evt.PayloadHash,
		}

		metadataJSON, err := canonical.Marshal(metadataMap)
		if err != nil {
			return nil, fmt.Errorf("marshal metadata for event %s: %w", evt.ID, err)
		}

		// Compute chainHash[i] = SHA-256(prevHash || payloadHash || metadataJSON)
		//
		// IMPORTANT: payloadHash is used as a UTF-8 string (not hex-decoded bytes)
		// to match the TypeScript implementation which uses hash.update(payloadHash, 'utf-8').
		h := sha256.New()
		h.Write(prevHash[:])
		h.Write([]byte(evt.PayloadHash))
		h.Write(metadataJSON)
		computedHash := h.Sum(nil)

		computedHex := fmt.Sprintf("%x", computedHash)

		if evt.ChainHash != "" && evt.ChainHash != computedHex {
			mismatches = append(mismatches, HashMismatch{
				Index:    i,
				EventID:  evt.ID,
				Expected: evt.ChainHash,
				Computed: computedHex,
			})
		}

		copy(prevHash[:], computedHash)
	}

	rootHash := fmt.Sprintf("%x", prevHash)

	return &ReplayResult{
		RootHash:          rootHash,
		EventCount:        len(events),
		HashMismatches:    mismatches,
		PayloadMismatches: payloadMismatches,
	}, nil
}

// recomputePayloadHash canonicalizes the event's payload (RFC 8785 JCS)
// and returns SHA-256 over the canonical bytes as a lowercase hex string.
// Matches the TypeScript producer's `sha256(payload)` helper:
//
//	sha256(value) = hex(SHA-256(utf8(canonicalJson(value))))
func recomputePayloadHash(rawPayload json.RawMessage) (string, error) {
	if len(rawPayload) == 0 {
		// Treat a missing payload as null for determinism, matches
		// canonicalJson(undefined/null) = "null" on the TS side.
		sum := sha256.Sum256([]byte("null"))
		return hex.EncodeToString(sum[:]), nil
	}
	var value interface{}
	dec := json.NewDecoder(bytes.NewReader(rawPayload))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	canonicalBytes, err := canonical.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonicalize payload: %w", err)
	}
	sum := sha256.Sum256(canonicalBytes)
	return hex.EncodeToString(sum[:]), nil
}

// sortEventsByID sorts events by their ULID id field.
func sortEventsByID(events []Event) {
	for i := 1; i < len(events); i++ {
		for j := i; j > 0 && events[j].ID < events[j-1].ID; j-- {
			events[j], events[j-1] = events[j-1], events[j]
		}
	}
}

// hexDecode decodes a hex string to bytes.
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length hex string")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("invalid hex char in %q", s)
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}