// Package cmd, Merkle root and field-commitment checks.
package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/merkle"
)

// checkMerkleRoot recomputes the RFC 6962 tree head over the replayed
// chain hashes and compares it to manifest.merkleRoot. A bundle sealed
// before the tree existed carries no root; that is a downgrade (no
// disclosure proofs can be made from it), reported as WARN, not a
// tamper.
func checkMerkleRoot(ctx *checkContext) []CheckResult {
	m := ctx.manifest
	if m.RootHash == "" {
		if m.Producer.Mode == "dev-unsigned" {
			return one(CheckResult{Name: "merkle-root", Status: StatusSkipped, Detail: "dev-unsigned bundle carries no chain, so no tree"})
		}
		return nil // chain-replay already failed this bundle
	}
	if m.MerkleRoot == "" {
		return one(CheckResult{Name: "merkle-root", Status: StatusWarn, Detail: "manifest has no merkleRoot: this bundle predates the Merkle tree and cannot support verifiable disclosure"})
	}
	replay := ctx.replay
	if replay == nil {
		return one(CheckResult{Name: "merkle-root", Status: StatusFail, Detail: "chain replay did not run, so the tree cannot be rebuilt"})
	}
	leaves := make([][]byte, len(replay.ChainHashes))
	for i, h := range replay.ChainHashes {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return one(CheckResult{Name: "merkle-root", Status: StatusFail, Detail: fmt.Sprintf("chain hash %d is not hex: %v", i, err)})
		}
		leaves[i] = merkle.LeafHash(raw)
	}
	computed := hex.EncodeToString(merkle.Root(leaves))
	if computed != m.MerkleRoot {
		return one(CheckResult{Name: "merkle-root", Status: StatusFail, Detail: fmt.Sprintf("Merkle root mismatch: manifest=%s..., computed=%s...", truncHex(m.MerkleRoot, 16), computed[:16])})
	}
	return one(CheckResult{Name: "merkle-root", Status: StatusPass, Detail: fmt.Sprintf("RFC 6962 tree over %d leaves has head %s...", len(leaves), computed[:16])})
}

// checkCommitments opens every field commitment in the sealed events
// against commitments.json. In a full bundle every placeholder must have
// an opening and every opening must match; otherwise the bundle claims a
// value it cannot show.
func checkCommitments(ctx *checkContext) []CheckResult {
	if ctx.replay == nil {
		return nil
	}
	openings, present, err := loadCommitments(ctx.bundlePath)
	if err != nil {
		return one(CheckResult{Name: "commitments", Status: StatusFail, Detail: err.Error()})
	}
	report := openAll(ctx.replay.EventIDs, ctx.replay.Payloads, openings, !present)
	if len(report.problems) > 0 {
		return one(CheckResult{Name: "commitments", Status: StatusFail, Detail: fmt.Sprintf("%d problem(s): %s", len(report.problems), joinProblems(report.problems))})
	}
	if report.placeholders == 0 {
		return one(CheckResult{Name: "commitments", Status: StatusPass, Detail: "no committed fields in this bundle"})
	}
	return one(CheckResult{Name: "commitments", Status: StatusPass, Detail: fmt.Sprintf("all %d committed field(s) open to their recorded values", report.opened)})
}
