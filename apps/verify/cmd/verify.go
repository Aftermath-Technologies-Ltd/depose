// Package cmd, top-level verification orchestration for depose-verify.
//
// VerifyBundle runs the checks listed in checkOrder, in that order. Each
// check is one function returning one or more CheckResults; the driver
// records them and stops only where the spec says a failure makes the
// remaining checks meaningless (docs/bundle-format.md#verifier-checks):
// an unparseable manifest, an unsupported schema, an unrecognized mode,
// or an invalid signature. Everything else runs to completion so the
// report names every defect, not just the first.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/chain"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/manifest"
)

// checkContext is the state the checks share: the bundle location, the
// parsed manifest, the raw manifest bytes (for signature and timestamp
// verification), and the caller's options.
type checkContext struct {
	bundlePath  string
	manifest    *manifest.Manifest
	rawManifest []byte
	opts        VerifyOpts
	// replay is set by checkChain for the checks that build on it.
	replay *chain.ReplayResult
	// disclosure is set in disclosure mode.
	disclosure *disclosureDoc
	// disclosed is set by checkDisclosureInclusion for the commitment check.
	disclosed *disclosedEvents
}

// checkStep pairs a check with whether its failure ends the run.
type checkStep struct {
	run        func(*checkContext) []CheckResult
	stopOnFail bool
}

// checkOrder is the documented check sequence. Order is part of the
// contract; do not reorder without updating docs/bundle-format.md.
var checkOrder = []checkStep{
	{checkSchemaVersion, true},
	{checkModeDeclaration, true},
	{checkModeContract, false},
	{checkKeyFingerprintPin, false},
	{checkRevocationList, false},
	{checkSignerIdentity, false},
	{checkSignatureVerify, true},
	{checkChain, false},
	{checkIntentEffect, false},
	{checkFileContinuity, false},
	{checkMerkleRoot, false},
	{checkCommitments, false},
	{checkTimestamps, false},
	{checkEventsJsonl, false},
	{checkRuleset, false},
	{checkFilesMapStep, false},
	{checkAttestationFilesStep, false},
	{checkBundleCompleteness, false},
	{checkRekor, false},
}

// VerifyBundle runs all verification checks on a .depo bundle directory.
func VerifyBundle(bundlePath string, opts ...VerifyOpts) *VerifyResult {
	var opt VerifyOpts
	if len(opts) > 0 {
		opt = opts[0]
	}
	result := &VerifyResult{Bundle: bundlePath, Pass: true}

	m, raw, parse := checkManifestParse(bundlePath)
	result.Checks = append(result.Checks, parse)
	if parse.Failed() {
		result.Pass = false
		return result
	}
	result.Mode = m.Producer.Mode
	ctx := &checkContext{bundlePath: bundlePath, manifest: m, rawManifest: raw, opts: opt}
	runChecks(ctx, result, checkOrder)
	return result
}

// runChecks executes the steps in order, recording every result and
// stopping after a step whose failure makes the rest meaningless.
func runChecks(ctx *checkContext, result *VerifyResult, order []checkStep) {
	for _, step := range order {
		results := step.run(ctx)
		result.Checks = append(result.Checks, results...)
		failed := false
		for _, r := range results {
			if r.Failed() {
				failed = true
			}
		}
		if failed {
			result.Pass = false
			if step.stopOnFail {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "remaining-checks",
					Status: StatusSkipped,
					Detail: fmt.Sprintf("not run: %s failed, so nothing the manifest pins can be trusted", results[len(results)-1].Name),
				})
				return
			}
		}
	}
}

// checkManifestParse reads and parses manifest.json. It returns the
// manifest and its raw bytes for the later checks.
func checkManifestParse(bundlePath string) (*manifest.Manifest, []byte, CheckResult) {
	m, err := manifest.LoadManifest(bundlePath)
	if err != nil {
		return nil, nil, CheckResult{
			Name:   "manifest-parse",
			Status: StatusFail,
			Detail: fmt.Sprintf("Failed to parse manifest.json: %v", err),
		}
	}
	raw, err := os.ReadFile(filepath.Join(bundlePath, "manifest.json"))
	if err != nil {
		return nil, nil, CheckResult{
			Name:   "manifest-parse",
			Status: StatusFail,
			Detail: fmt.Sprintf("Cannot re-read manifest.json: %v", err),
		}
	}
	detail := fmt.Sprintf("Bundle %s, schema v%d, mode=%s, %d events",
		m.BundleID, m.SchemaVersion, m.Producer.Mode, m.Counts.Events)
	// Surface the producer's capture accounting. "We held capture records
	// and deliberately did not use them" is something a recipient should
	// read off the signed manifest, not have to infer from an absence.
	if m.Counts.CapturesAttributed > 0 || m.Counts.CapturesExcluded > 0 {
		detail += fmt.Sprintf(
			"\n         captures: %d attributed to this session, %d excluded as unattributable",
			m.Counts.CapturesAttributed, m.Counts.CapturesExcluded)
	}
	return m, raw, CheckResult{Name: "manifest-parse", Status: StatusPass, Detail: detail}
}

func one(r CheckResult) []CheckResult { return []CheckResult{r} }

func checkFilesMapStep(ctx *checkContext) []CheckResult {
	return one(checkFilesMap(ctx.bundlePath, ctx.manifest))
}

func checkAttestationFilesStep(ctx *checkContext) []CheckResult {
	return one(checkAttestationFiles(ctx.bundlePath, ctx.manifest))
}
