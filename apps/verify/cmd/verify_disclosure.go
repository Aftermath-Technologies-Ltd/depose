// Package cmd, disclosure-mode driver and cross-disclosure consistency.
package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/merkle"
)

// disclosureOrder is the documented check sequence for a disclosure
// bundle (docs/bundle-format.md#disclosure-bundles). The manifest,
// signature, and timestamp checks are the same functions the full
// bundle uses, run against the original manifest the disclosure carries.
var disclosureOrder = []checkStep{
	{checkSchemaVersion, true},
	{checkModeDeclaration, true},
	{checkModeContract, false},
	{checkKeyFingerprintPin, false},
	{checkRevocationList, false},
	{checkSignerIdentity, false},
	{checkSignatureVerify, true},
	{checkDisclosureParse, true},
	{checkDisclosureInclusion, false},
	{checkDisclosureCommitments, false},
	{checkTimestamps, false},
	{checkDisclosureFiles, false},
	{checkAttestationFilesStep, false},
}

// VerifyDisclosure runs the disclosure-mode checks on a directory that
// carries disclosure.json.
func VerifyDisclosure(dir string, opts ...VerifyOpts) *VerifyResult {
	var opt VerifyOpts
	if len(opts) > 0 {
		opt = opts[0]
	}
	result := &VerifyResult{Bundle: dir, Pass: true, Disclosure: true}

	m, raw, parse := checkManifestParse(dir)
	result.Checks = append(result.Checks, parse)
	if parse.Failed() {
		result.Pass = false
		return result
	}
	result.Mode = m.Producer.Mode
	doc, err := loadDisclosure(dir)
	if err != nil {
		result.Checks = append(result.Checks, CheckResult{Name: "disclosure-parse", Status: StatusFail, Detail: err.Error()})
		result.Pass = false
		return result
	}
	ctx := &checkContext{bundlePath: dir, manifest: m, rawManifest: raw, opts: opt, disclosure: doc}
	runChecks(ctx, result, disclosureOrder)
	if doc != nil {
		result.DisclosedEvents = len(doc.Disclosed)
		result.LeafCount = doc.LeafCount
	}
	return result
}

// VerifyConsistency checks that a later disclosure extends an earlier
// one: same bundle lineage, the earlier tree is a prefix of the later
// (equal roots when sizes match, an RFC 6962 consistency proof when the
// later tree is larger), and every event both disclose is byte-identical.
// Both disclosures are verified on their own first.
func VerifyConsistency(earlierDir, laterDir string, opts ...VerifyOpts) *VerifyResult {
	later := VerifyDisclosure(laterDir, opts...)
	earlier := VerifyDisclosure(earlierDir, opts...)
	result := &VerifyResult{Bundle: laterDir, Pass: later.Pass && earlier.Pass, Mode: later.Mode, Disclosure: true}
	result.Checks = append(result.Checks, CheckResult{
		Name:   "earlier-disclosure",
		Status: statusFor(earlier.Pass),
		Detail: fmt.Sprintf("%s: %s", earlierDir, summarize(earlier)),
	})
	result.Checks = append(result.Checks, CheckResult{
		Name:   "later-disclosure",
		Status: statusFor(later.Pass),
		Detail: fmt.Sprintf("%s: %s", laterDir, summarize(later)),
	})
	if !result.Pass {
		return result
	}
	e, errE := loadDisclosure(earlierDir)
	l, errL := loadDisclosure(laterDir)
	if errE != nil || errL != nil {
		result.Pass = false
		return result
	}
	result.Checks = append(result.Checks, consistencyResult(e, l))
	result.Checks = append(result.Checks, overlapResult(earlierDir, laterDir, e, l))
	for _, c := range result.Checks {
		if c.Failed() {
			result.Pass = false
		}
	}
	return result
}

func statusFor(pass bool) CheckStatus {
	if pass {
		return StatusPass
	}
	return StatusFail
}

func summarize(r *VerifyResult) string {
	failed := 0
	for _, c := range r.Checks {
		if c.Failed() {
			failed++
		}
	}
	if failed == 0 {
		return fmt.Sprintf("%d check(s) pass", len(r.Checks))
	}
	return fmt.Sprintf("%d of %d check(s) FAIL", failed, len(r.Checks))
}

// consistencyResult proves the earlier tree is a prefix of the later.
func consistencyResult(e, l *disclosureDoc) CheckResult {
	name := "tree-consistency"
	if e.LeafCount > l.LeafCount {
		return CheckResult{Name: name, Status: StatusFail, Detail: fmt.Sprintf("earlier disclosure has %d leaves, later has %d; the later tree must be at least as large", e.LeafCount, l.LeafCount)}
	}
	if e.LeafCount == l.LeafCount {
		if e.MerkleRoot != l.MerkleRoot {
			return CheckResult{Name: name, Status: StatusFail, Detail: "same leaf count but different roots; these disclosures come from different seals"}
		}
		return CheckResult{Name: name, Status: StatusPass, Detail: fmt.Sprintf("both disclosures cover the same %d-leaf tree with root %s...", e.LeafCount, truncHex(e.MerkleRoot, 16))}
	}
	if l.Consistency == nil {
		return CheckResult{Name: name, Status: StatusFail, Detail: fmt.Sprintf("later disclosure has %d leaves against the earlier %d but carries no consistency proof; produce it with --consistent-with", l.LeafCount, e.LeafCount)}
	}
	c := l.Consistency
	if c.EarlierLeafCount != e.LeafCount || c.EarlierRoot != e.MerkleRoot {
		return CheckResult{Name: name, Status: StatusFail, Detail: "the later disclosure's consistency proof targets a different earlier tree"}
	}
	rootE, err1 := hex.DecodeString(e.MerkleRoot)
	rootL, err2 := hex.DecodeString(l.MerkleRoot)
	proof, err3 := decodePath(c.Proof)
	if err1 != nil || err2 != nil || err3 != nil {
		return CheckResult{Name: name, Status: StatusFail, Detail: "consistency proof or roots are not valid hex"}
	}
	if !merkle.VerifyConsistency(e.LeafCount, l.LeafCount, rootE, rootL, proof) {
		return CheckResult{Name: name, Status: StatusFail, Detail: fmt.Sprintf("RFC 6962 consistency proof from %d to %d leaves does not verify", e.LeafCount, l.LeafCount)}
	}
	return CheckResult{Name: name, Status: StatusPass, Detail: fmt.Sprintf("the earlier %d-leaf tree is a prefix of the later %d-leaf tree (consistency proof verified)", e.LeafCount, l.LeafCount)}
}

// overlapResult requires events disclosed by both to be byte-identical.
func overlapResult(earlierDir, laterDir string, e, l *disclosureDoc) CheckResult {
	name := "disclosed-overlap"
	_, earlierLines, err := readDisclosedLines(earlierDir)
	if err != nil {
		return CheckResult{Name: name, Status: StatusFail, Detail: err.Error()}
	}
	_, laterLines, err := readDisclosedLines(laterDir)
	if err != nil {
		return CheckResult{Name: name, Status: StatusFail, Detail: err.Error()}
	}
	laterByIndex := make(map[int]string, len(l.Disclosed))
	for i, d := range l.Disclosed {
		if i < len(laterLines) {
			laterByIndex[d.Index] = laterLines[i]
		}
	}
	shared := 0
	for i, d := range e.Disclosed {
		line, ok := laterByIndex[d.Index]
		if !ok {
			continue
		}
		shared++
		if i < len(earlierLines) && earlierLines[i] != line {
			return CheckResult{Name: name, Status: StatusFail, Detail: fmt.Sprintf("event at index %d differs between the two disclosures", d.Index)}
		}
	}
	return CheckResult{Name: name, Status: StatusPass, Detail: fmt.Sprintf("%d event(s) disclosed by both are byte-identical", shared)}
}
