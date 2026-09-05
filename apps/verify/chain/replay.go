// Package chain, IRONROOT hash chain replay for verification.
package chain

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	Correlation   *Correlation    `json:"correlation,omitempty"`
}

// Correlation holds the cross-links the merge writes outside the payload.
// These are not covered by chainHash, only by the signed files map over
// events.jsonl, so the verifier treats them as claims to be checked
// against the signed payload fields rather than as evidence themselves.
// See docs/bundle-format.md#intent-and-effect.
type Correlation struct {
	LinkedShellCommandPreID string `json:"linkedShellCommandPreId,omitempty"`
	LinkedEffectID          string `json:"linkedEffectId,omitempty"`
	LinkedIntentID          string `json:"linkedIntentId,omitempty"`
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
	// ChainHashes are the recomputed chain hashes in file order, hex.
	ChainHashes []string
	// EventIDs are the event ids in file order.
	EventIDs []string
	// Payloads are the raw payload bytes in file order.
	Payloads []json.RawMessage
	// Events are the parsed events in file order, for checks that need
	// more than the chain fields.
	Events []Event
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
	chainHashes := make([]string, 0, len(events))
	eventIDs := make([]string, 0, len(events))
	payloads := make([]json.RawMessage, 0, len(events))

	for i, evt := range events {
		// ── Recompute payloadHash from the actual payload bytes ──
		// Without this step, payloadHash is trusted from disk and the
		// chain replay only proves the recorded payloadHash is
		// internally consistent, not that the recorded payload
		// canonicalizes to that hash. An attacker can then rewrite
		// payload content without touching payloadHash and the chain
		// still validates. We close that hole here by re-canonicalizing
		// the payload through the JCS marshaller and SHA-256'ing it.
		computedPayloadHash, err := RecomputePayloadHash(evt.Payload)
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
		chainHashes = append(chainHashes, computedHex)
		eventIDs = append(eventIDs, evt.ID)
		payloads = append(payloads, evt.Payload)
	}

	rootHash := fmt.Sprintf("%x", prevHash)

	return &ReplayResult{
		RootHash:          rootHash,
		EventCount:        len(events),
		HashMismatches:    mismatches,
		PayloadMismatches: payloadMismatches,
		NumericMonoNs:     numericMonoNs,
		ChainHashes:       chainHashes,
		EventIDs:          eventIDs,
		Payloads:          payloads,
		Events:            events,
	}, nil
}
