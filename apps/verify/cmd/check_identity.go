// Package cmd, recipient-supplied identity pins: the expected key
// fingerprint, the revocation catalog, and the Sigstore signer identity.
package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
)

// checkKeyFingerprintPin compares manifest.producer.keyFingerprint with
// --expected-key-fingerprint. This is the air-gapped trust path: the
// producer publishes the fingerprint out of band and the verifier
// refuses any bundle that does not match. Skipped when no expectation
// was given.
func checkKeyFingerprintPin(ctx *checkContext) []CheckResult {
	want := ctx.opts.ExpectedKeyFingerprint
	if want == "" {
		return nil
	}
	got := ctx.manifest.Producer.KeyFingerprint
	switch {
	case got == "":
		return one(CheckResult{Name: "key-fingerprint-pin", Status: StatusFail, Detail: fmt.Sprintf("--expected-key-fingerprint=%s, but manifest has no producer.keyFingerprint", want)})
	case !strings.EqualFold(got, want):
		return one(CheckResult{Name: "key-fingerprint-pin", Status: StatusFail, Detail: fmt.Sprintf("key fingerprint mismatch: manifest=%s..., expected=%s...", truncHex(got, 16), truncHex(want, 16))})
	default:
		return one(CheckResult{Name: "key-fingerprint-pin", Status: StatusPass, Detail: fmt.Sprintf("manifest key fingerprint matches expectation (%s...)", truncHex(got, 16))})
	}
}

// checkRevocationList loads the producer's key catalog and rejects the
// bundle if its key appears with status=revoked. Rotated keys are "old
// but valid"; revoked keys are "do not trust".
func checkRevocationList(ctx *checkContext) []CheckResult {
	path := ctx.opts.RevocationListPath
	if path == "" {
		return nil
	}
	fp := ctx.manifest.Producer.KeyFingerprint
	entry, err := lookupRevocation(path, fp)
	switch {
	case err != nil:
		return one(CheckResult{Name: "revocation-list", Status: StatusFail, Detail: fmt.Sprintf("Failed to load revocation list %q: %v", path, err)})
	case entry != nil && entry.Status == "revoked":
		return one(CheckResult{
			Name:   "revocation-list",
			Status: StatusFail,
			Detail: fmt.Sprintf("key fingerprint %s... is REVOKED in %s (reason: %q, revokedAt: %s)", truncHex(fp, 16), filepath.Base(path), entry.Reason, entry.RevokedAt),
		})
	default:
		detail := "key fingerprint not present in revocation list (accepted)"
		if entry != nil {
			detail = fmt.Sprintf("key fingerprint present, status=%s (accepted)", entry.Status)
		}
		return one(CheckResult{Name: "revocation-list", Status: StatusPass, Detail: detail})
	}
}
