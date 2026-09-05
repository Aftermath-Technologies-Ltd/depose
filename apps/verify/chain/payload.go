// Package chain, re-deriving payloadHash from the payload bytes.
//
// Without this step payloadHash is trusted from disk, and the chain
// replay only proves the recorded hash is internally consistent, not
// that the recorded payload canonicalizes to it. An attacker could then
// rewrite payload content without touching payloadHash and the chain
// would still validate.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/canonical"
)

// RecomputePayloadHash canonicalizes the event's payload (RFC 8785 JCS)
// and returns SHA-256 over the canonical bytes as a lowercase hex string.
// Matches the TypeScript producer's `sha256(payload)` helper:
//
//	sha256(value) = hex(SHA-256(utf8(canonicalJson(value))))
func RecomputePayloadHash(rawPayload json.RawMessage) (string, error) {
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
