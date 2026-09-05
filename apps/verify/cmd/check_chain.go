// Package cmd, hash chain checks: per-event payload re-hash and IRONROOT
// chain replay.
package cmd

import (
	"fmt"
	"strings"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/chain"
)

// checkChain replays the chain over events.jsonl and reports two
// results: payload-hash (every payload canonicalizes to its recorded
// payloadHash) and chain-replay (the replayed chain ends at
// manifest.rootHash). In dev-unsigned mode an empty rootHash means no
// chain was built, which is reported as skipped rather than failed.
func checkChain(ctx *checkContext) []CheckResult {
	m := ctx.manifest
	if m.RootHash == "" {
		if m.Producer.Mode == "dev-unsigned" {
			// The chain is not anchored, but the events still parse, and
			// the checks that read the timeline rather than the chain
			// (intent-effect, file-continuity) are worth running on a
			// development bundle. A parse failure here is not reported
			// separately: artifact-events-jsonl already covers it.
			if replay, err := chain.ReplayChain(ctx.bundlePath); err == nil {
				ctx.replay = replay
			}
			return one(CheckResult{Name: "chain-replay", Status: StatusSkipped, Detail: "dev-unsigned bundle carries no chain (rootHash empty)"})
		}
		return one(CheckResult{Name: "chain-replay", Status: StatusFail, Detail: "No root hash, signed bundle missing chain"})
	}

	replay, err := chain.ReplayChain(ctx.bundlePath)
	if err != nil {
		return one(CheckResult{Name: "chain-replay", Status: StatusFail, Detail: fmt.Sprintf("Chain replay error: %v", err)})
	}
	ctx.replay = replay

	results := []CheckResult{payloadHashResult(replay)}
	if m.SchemaVersion >= 3 && replay.NumericMonoNs > 0 {
		results = append(results, CheckResult{
			Name:   "chain-replay",
			Status: StatusFail,
			Detail: fmt.Sprintf("%d event(s) carry monoNs as a JSON number; schemaVersion %d requires a decimal string", replay.NumericMonoNs, m.SchemaVersion),
		})
		return results
	}
	switch {
	case len(replay.HashMismatches) > 0:
		details := make([]string, len(replay.HashMismatches))
		for i, mm := range replay.HashMismatches {
			details[i] = fmt.Sprintf("event[%d] %s: expected %s, got %s", mm.Index, mm.EventID, truncHex(mm.Expected, 16), truncHex(mm.Computed, 16))
		}
		results = append(results, CheckResult{
			Name:   "chain-replay",
			Status: StatusFail,
			Detail: fmt.Sprintf("Chain hash mismatch at %d event(s): %s", len(replay.HashMismatches), strings.Join(details, "; ")),
		})
	case replay.RootHash != m.RootHash:
		results = append(results, CheckResult{
			Name:   "chain-replay",
			Status: StatusFail,
			Detail: fmt.Sprintf("Root hash mismatch: manifest=%s, computed=%s", truncHex(m.RootHash, 16), truncHex(replay.RootHash, 16)),
		})
	default:
		results = append(results, CheckResult{
			Name:   "chain-replay",
			Status: StatusPass,
			Detail: fmt.Sprintf("Chain valid: %d events, root hash %s...", replay.EventCount, truncHex(replay.RootHash, 16)),
		})
	}
	return results
}

// payloadHashResult reports the payload re-hash separately so the
// failure mode (payload tamper) is obvious in the report.
func payloadHashResult(replay *chain.ReplayResult) CheckResult {
	if len(replay.PayloadMismatches) == 0 {
		return CheckResult{
			Name:   "payload-hash",
			Status: StatusPass,
			Detail: fmt.Sprintf("all %d event payloads re-hash to their recorded payloadHash", replay.EventCount),
		}
	}
	details := make([]string, len(replay.PayloadMismatches))
	for i, mm := range replay.PayloadMismatches {
		details[i] = fmt.Sprintf("event[%d] %s: stored=%s, recomputed=%s", mm.Index, mm.EventID, truncHex(mm.Expected, 16), truncHex(mm.Computed, 16))
	}
	return CheckResult{
		Name:   "payload-hash",
		Status: StatusFail,
		Detail: fmt.Sprintf("payloadHash mismatch at %d event(s), payload bytes do not canonicalize to the recorded hash: %s", len(replay.PayloadMismatches), strings.Join(details, "; ")),
	}
}
