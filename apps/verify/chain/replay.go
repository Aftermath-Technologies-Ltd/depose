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
	"regexp"
	"strconv"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/canonical"
)

// Event represents a minimal event for chain verification.
//
// MonoNs is kept as the raw JSON token: schema 3 writes it as a decimal
// string, schema 2 wrote a number, and the chain metadata must be
// re-canonicalized with exactly the form the producer hashed.
type Event struct {
	ID            string          `json:"id"`
	WallTs        string          `json:"wallTs"`
	MonoNs        json.RawMessage `json:"monoNs"`
	SessionID     string          `json:"sessionId"`
	AgentID       string          `json:"agentId"`
	ParentEventID *string         `json:"parentEventId"`
	Type          string          `json:"type"`
	Payload       json.RawMessage `json:"payload"`
	PayloadHash   string          `json:"payloadHash"`
	ChainHash     string          `json:"chainHash,omitempty"`
}

// ReplayResult holds the outcome of chain replay.
type ReplayResult struct {
	RootHash          string
	EventCount        int
	HashMismatches    []HashMismatch
	PayloadMismatches []PayloadMismatch
	// NumericMonoNs counts events whose monoNs was written as a JSON
	// number rather than a decimal string. Schema 3 requires strings.
	NumericMonoNs int
}

// monoNsPattern is the schema 3 wire form: a non-negative decimal
// integer string with no leading zeros.
var monoNsPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// MonoNsValue decodes a monoNs token to int64 and reports whether it was
// a string. A string must match monoNsPattern and fit int64; a number
// must be a non-negative integer.
func MonoNsValue(raw json.RawMessage) (value int64, isString bool, err error) {
	if len(raw) == 0 {
		return 0, false, fmt.Errorf("monoNs is missing")
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, true, fmt.Errorf("monoNs is not a JSON string: %w", err)
		}
		if !monoNsPattern.MatchString(s) {
			return 0, true, fmt.Errorf("monoNs %q is not a non-negative decimal integer", s)
		}
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, true, fmt.Errorf("monoNs %q does not fit int64", s)
		}
		return v, true, nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false, fmt.Errorf("monoNs is neither a string nor a number: %w", err)
	}
	v, err := n.Int64()
	if err != nil || v < 0 {
		return 0, false, fmt.Errorf("monoNs %s is not a non-negative integer", n.String())
	}
	return v, false, nil
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
// Chain construction (docs/bundle-format.md#hash-chain):
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

	// The chain is defined over ascending id order and the producer
	// writes the file in that order. Re-sorting here would let an
	// out-of-order file replay to the sealed root while the file on disk
	// says something else; the file must be in order as written.
	for i := 1; i < len(events); i++ {
		if events[i].ID < events[i-1].ID {
			return nil, fmt.Errorf("events.jsonl is not sorted by id at line %d: %s follows %s", i+1, events[i].ID, events[i-1].ID)
		}
	}

	var prevHash [32]byte // zero32 for first event
	var mismatches []HashMismatch
	var payloadMismatches []PayloadMismatch
	numericMonoNs := 0

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

		monoValue, monoIsString, err := MonoNsValue(evt.MonoNs)
		if err != nil {
			return nil, fmt.Errorf("event %s: %w", evt.ID, err)
		}
		var monoNs interface{} = json.Number(strconv.FormatInt(monoValue, 10))
		if monoIsString {
			monoNs = strconv.FormatInt(monoValue, 10)
		} else {
			numericMonoNs++
		}

		metadataMap := map[string]interface{}{
			"id":            evt.ID,
			"wallTs":        evt.WallTs,
			"monoNs":        monoNs,
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
		NumericMonoNs:     numericMonoNs,
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
