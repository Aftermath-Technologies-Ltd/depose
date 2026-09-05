// Package cmd, RFC 3161 timestamp checks: token validity and the
// anti-backdating comparison against manifest.producedAt.
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/manifest"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/timestamp"
)

// checkTimestamps verifies every RFC 3161 token in manifest.timestamps
// against SHA-256 of the unsigned manifest, then checks producedAt is
// not after any token's time. Skipped in dev-unsigned mode.
func checkTimestamps(ctx *checkContext) []CheckResult {
	m := ctx.manifest
	if m.Producer.Mode == "dev-unsigned" {
		return one(CheckResult{Name: "timestamp-verify", Status: StatusSkipped, Detail: "dev-unsigned bundles carry no timestamp"})
	}
	// The TSA was asked to timestamp SHA-256(canonical JSON of the
	// unsigned manifest), the same bytes the signature covers. A token
	// obtained later by `depose anchor` commits to those same bytes, so
	// both kinds verify the same way.
	unsigned, err := manifest.StripSignatureFields(ctx.rawManifest)
	if err != nil {
		return one(CheckResult{Name: "timestamp-verify", Status: StatusFail, Detail: fmt.Sprintf("cannot derive unsigned manifest: %v", err)})
	}
	sum := sha256.Sum256(unsigned)
	tokens := append(manifestTokens(m), anchorTokens(ctx)...)
	if len(tokens) == 0 {
		if m.AnchorStatus != "" {
			return one(CheckResult{
				Name:   "timestamp-verify",
				Status: StatusSkipped,
				Detail: fmt.Sprintf("bundle is sealed with anchorStatus=%q and carries no token yet; see anchor-status", m.AnchorStatus),
			})
		}
		return one(CheckResult{Name: "timestamp-verify", Status: StatusFail, Detail: "No RFC 3161 timestamps found"})
	}

	results := []CheckResult{verifyTokensResult(tokens, hex.EncodeToString(sum[:]))}
	results = append(results, backdatingResult(m.ProducedAt, tokens))
	return results
}

// anchorTokens are the tokens a later `depose anchor` added, read from
// attestations/anchor.json. They are verified alongside the manifest's
// own; whether the anchor is the producer's act is anchor-status's job.
func anchorTokens(ctx *checkContext) []timestamp.Token {
	doc, _, err := loadAnchor(ctx.bundlePath)
	if err != nil || doc == nil {
		return nil
	}
	tokens := make([]timestamp.Token, 0, len(doc.Timestamps))
	for _, t := range doc.Timestamps {
		tokens = append(tokens, timestamp.Token{TSA: t.Tsa, Timestamp: t.Timestamp, TokenBase64: t.TokenBase64})
	}
	return tokens
}

func manifestTokens(m *manifest.Manifest) []timestamp.Token {
	tokens := make([]timestamp.Token, len(m.Timestamps))
	for i, mt := range m.Timestamps {
		tokens[i] = timestamp.Token{TSA: mt.TSA, Timestamp: mt.Timestamp, TokenBase64: mt.TokenBase64}
	}
	return tokens
}

func verifyTokensResult(tokens []timestamp.Token, expectedHashHex string) CheckResult {
	allValid := true
	details := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		vr := timestamp.VerifyToken(tok, expectedHashHex)
		if !vr.Valid {
			allValid = false
			details = append(details, fmt.Sprintf("%s: INVALID, %s", vr.TSA, vr.Detail))
		} else {
			details = append(details, fmt.Sprintf("%s: valid", vr.TSA))
		}
	}
	if !allValid {
		return CheckResult{Name: "timestamp-verify", Status: StatusFail, Detail: fmt.Sprintf("Timestamp validation failed: %s", strings.Join(details, "; "))}
	}
	return CheckResult{Name: "timestamp-verify", Status: StatusPass, Detail: fmt.Sprintf("%d timestamp(s) valid: %s", len(tokens), strings.Join(details, "; "))}
}

// backdatingResult is the anti-backdating check: producedAt must not be
// after any TSA time (with the whole-second tolerance).
func backdatingResult(producedAt string, tokens []timestamp.Token) CheckResult {
	if err := timestamp.VerifyManifestProducedAt(producedAt, tokens); err != nil {
		return CheckResult{Name: "timestamp-backdating", Status: StatusFail, Detail: err.Error()}
	}
	return CheckResult{Name: "timestamp-backdating", Status: StatusPass, Detail: "producedAt is not after any TSA timestamp"}
}
