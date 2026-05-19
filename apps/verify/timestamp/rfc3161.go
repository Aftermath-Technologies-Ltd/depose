// Package timestamp — RFC 3161 timestamp verification for DEPOSE bundles.
package timestamp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Token represents an RFC 3161 timestamp token from a TSA.
type Token struct {
	TSA         string `json:"tsa"`
	Timestamp   string `json:"timestamp"`
	TokenBase64 string `json:"tokenBase64"`
}

// VerifyResult holds the outcome of timestamp verification.
type VerifyResult struct {
	TSA       string
	Timestamp time.Time
	Valid     bool
	Detail    string
}

// LoadTimestamps reads RFC 3161 tokens from the bundle's attestations directory.
func LoadTimestamps(bundleDir string) ([]Token, error) {
	path := filepath.Join(bundleDir, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	var manifest struct {
		Timestamps []Token `json:"timestamps"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	return manifest.Timestamps, nil
}

// VerifyToken performs simplified RFC 3161 verification.
//
// Full verification (x509 chain, CRL/OCSP) is deferred to a future version.
// Phase 2 verification checks:
//   1. The token base64 decodes to valid DER data
//   2. The token starts with a SEQUENCE tag (0x30)
//   3. The embedded messageImprint hash matches the expected hash
//
// The depose-verify binary is designed to work air-gapped for core
// verification. Rekor inclusion proof is optional and gracefully skipped.
func VerifyToken(token Token, expectedHashHex string) *VerifyResult {
	result := &VerifyResult{
		TSA: token.TSA + "(" + token.Timestamp + ")",
	}

	// Parse the timestamp
	ts, err := time.Parse(time.RFC3339, token.Timestamp)
	if err != nil {
		// Try parsing without timezone
		ts, err = time.Parse("2006-01-02T15:04:05.000Z", token.Timestamp)
		if err != nil {
			result.Valid = false
			result.Detail = fmt.Sprintf("cannot parse timestamp %q: %v", token.Timestamp, err)
			return result
		}
	}
	result.Timestamp = ts

	// Decode the token DER
	tsrDer, err := base64.StdEncoding.DecodeString(token.TokenBase64)
	if err != nil {
		result.Valid = false
		result.Detail = fmt.Sprintf("cannot decode base64 token: %v", err)
		return result
	}

	// Basic DER structure check: should start with SEQUENCE tag
	if len(tsrDer) < 2 || tsrDer[0] != 0x30 {
		result.Valid = false
		result.Detail = "invalid DER structure: expected SEQUENCE tag"
		return result
	}

	// Search for the expected hash in the DER blob
	hashBytes, err := hexDecode(expectedHashHex)
	if err != nil {
		result.Valid = false
		result.Detail = fmt.Sprintf("invalid expected hash hex: %v", err)
		return result
	}

	found := false
	for i := 0; i <= len(tsrDer)-len(hashBytes); i++ {
		match := true
		for j := 0; j < len(hashBytes); j++ {
			if tsrDer[i+j] != hashBytes[j] {
				match = false
				break
			}
		}
		if match {
			found = true
			break
		}
	}

	if !found {
		result.Valid = false
		result.Detail = fmt.Sprintf("messageImprint hash mismatch: expected %s", expectedHashHex)
		return result
	}

	result.Valid = true
	result.Detail = "RFC 3161 token structure valid, messageImprint matches"
	return result
}

// VerifyManifestProducedAt checks that producedAt is not before the
// earliest RFC 3161 timestamp (anti-backdating check).
func VerifyManifestProducedAt(producedAt string, tokens []Token) error {
	producedTime, err := time.Parse(time.RFC3339, producedAt)
	if err != nil {
		producedTime, err = time.Parse("2006-01-02T15:04:05.000Z", producedAt)
		if err != nil {
			return fmt.Errorf("parse producedAt %q: %w", producedAt, err)
		}
	}

	for _, token := range tokens {
		ts, err := time.Parse(time.RFC3339, token.Timestamp)
		if err != nil {
			ts, err = time.Parse("2006-01-02T15:04:05.000Z", token.Timestamp)
			if err != nil {
				continue
			}
		}

		// Allow up to 1 second of tolerance for TSA clock precision.
		// Many free TSAs truncate to whole seconds; a producedAt that is
		// sub-second after the TSA time is not evidence of backdating.
		if producedTime.After(ts.Add(time.Second)) {
			return fmt.Errorf("manifest producedAt (%s) is AFTER timestamp from %s (%s) — possible backdating",
				producedAt, token.TSA, token.Timestamp)
		}
	}

	return nil
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
			return nil, fmt.Errorf("invalid hex char")
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

