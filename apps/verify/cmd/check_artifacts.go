// Package cmd, artifact checks: events.jsonl byte pin, ruleset hash,
// required-file presence, and the Rekor placeholder.
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/timestamp"
)

// checkEventsJsonl re-hashes the literal bytes of events.jsonl and
// compares to manifest.eventsJsonlSha256, on top of the per-event chain.
// Adding, removing, reordering, or reformatting a line fails here.
func checkEventsJsonl(ctx *checkContext) []CheckResult {
	m := ctx.manifest
	data, err := os.ReadFile(filepath.Join(ctx.bundlePath, "events.jsonl"))
	if err != nil {
		return one(CheckResult{Name: "artifact-events-jsonl", Status: StatusFail, Detail: fmt.Sprintf("Cannot read events.jsonl: %v", err)})
	}
	sum := sha256.Sum256(data)
	computed := hex.EncodeToString(sum[:])
	switch {
	case m.EventsJsonlSha256 == "" && m.Producer.Mode == "signed":
		return one(CheckResult{Name: "artifact-events-jsonl", Status: StatusFail, Detail: fmt.Sprintf("signed bundle missing manifest.eventsJsonlSha256 (computed sha256=%s...)", computed[:16])})
	case m.EventsJsonlSha256 == "":
		return one(CheckResult{Name: "artifact-events-jsonl", Status: StatusWarn, Detail: fmt.Sprintf("events.jsonl sha256=%s... is not pinned by this dev-unsigned manifest", computed[:16])})
	case !strings.EqualFold(computed, m.EventsJsonlSha256):
		return one(CheckResult{Name: "artifact-events-jsonl", Status: StatusFail, Detail: fmt.Sprintf("events.jsonl sha256 mismatch: manifest=%s..., computed=%s...", truncHex(m.EventsJsonlSha256, 16), computed[:16])})
	default:
		return one(CheckResult{Name: "artifact-events-jsonl", Status: StatusPass, Detail: fmt.Sprintf("events.jsonl (%d bytes) matches manifest.eventsJsonlSha256 %s...", len(data), computed[:16])})
	}
}

// checkRuleset re-hashes rules/destructive.yaml against
// manifest.rulesetHash, so an auditor can reconstruct which rules
// produced counts.destructiveOperations.
func checkRuleset(ctx *checkContext) []CheckResult {
	m := ctx.manifest
	data, err := os.ReadFile(filepath.Join(ctx.bundlePath, "rules", "destructive.yaml"))
	if err != nil {
		return one(CheckResult{Name: "ruleset-integrity", Status: StatusFail, Detail: fmt.Sprintf("Cannot read rules/destructive.yaml: %v", err)})
	}
	if m.RulesetHash == "" {
		return one(CheckResult{Name: "ruleset-integrity", Status: StatusFail, Detail: "manifest.rulesetHash is empty, cannot verify embedded ruleset"})
	}
	sum := sha256.Sum256(data)
	computed := hex.EncodeToString(sum[:])
	if computed != m.RulesetHash {
		return one(CheckResult{Name: "ruleset-integrity", Status: StatusFail, Detail: fmt.Sprintf("rules/destructive.yaml hash mismatch: manifest=%s..., computed=%s...", truncHex(m.RulesetHash, 16), computed[:16])})
	}
	return one(CheckResult{Name: "ruleset-integrity", Status: StatusPass, Detail: fmt.Sprintf("rules/destructive.yaml (%d bytes) matches manifest.rulesetHash %s...", len(data), computed[:16])})
}

// requiredPaths must exist in every bundle regardless of mode.
var requiredPaths = []string{
	"manifest.json",
	"events.jsonl",
	"attestations/signatures.json",
	"rules/destructive.yaml",
	"verify.txt",
}

// checkBundleCompleteness verifies the required files are present.
func checkBundleCompleteness(ctx *checkContext) []CheckResult {
	var missing []string
	for _, p := range requiredPaths {
		if _, err := os.Stat(filepath.Join(ctx.bundlePath, filepath.FromSlash(p))); err != nil {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return one(CheckResult{Name: "bundle-completeness", Status: StatusFail, Detail: fmt.Sprintf("Missing required files: %s", strings.Join(missing, ", "))})
	}
	return one(CheckResult{Name: "bundle-completeness", Status: StatusPass, Detail: "All required files present"})
}

// checkRekor reports Rekor entries as not verified. Full verification
// needs the log's public key and network access; the bundle's integrity
// does not depend on it.
func checkRekor(ctx *checkContext) []CheckResult {
	m := ctx.manifest
	if len(m.Rekor) == 0 {
		return nil
	}
	skipped := 0
	for _, entry := range m.Rekor {
		if timestamp.VerifyRekorEntry(entry.UUID, entry.Body, entry.IntegratedTime).Skipped {
			skipped++
		}
	}
	return one(CheckResult{
		Name:   "rekor-verify",
		Status: StatusSkipped,
		Detail: fmt.Sprintf("Rekor verification not performed (%d entries); optional transparency log", skipped),
	})
}
