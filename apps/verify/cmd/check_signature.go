// Package cmd, the manifest signature check.
package cmd

import (
	"fmt"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/manifest"
)

// checkSignatureVerify verifies every Ed25519 block in
// manifest.signatures against the canonical unsigned form of the
// manifest. Skipped in dev-unsigned mode, where mode-contract has
// already required signatures=[].
func checkSignatureVerify(ctx *checkContext) []CheckResult {
	m := ctx.manifest
	if m.Producer.Mode == "dev-unsigned" {
		return one(CheckResult{Name: "signature-verify", Status: StatusSkipped, Detail: "dev-unsigned bundles carry no signature"})
	}
	if len(m.Signatures) == 0 {
		return one(CheckResult{Name: "signature-verify", Status: StatusFail, Detail: "No signatures found, signed bundle missing signature"})
	}
	if err := manifest.VerifySignature(m, ctx.rawManifest); err != nil {
		return one(CheckResult{Name: "signature-verify", Status: StatusFail, Detail: fmt.Sprintf("Signature INVALID: %v", err)})
	}
	return one(CheckResult{Name: "signature-verify", Status: StatusPass, Detail: fmt.Sprintf("Ed25519 signature valid (%d signature(s))", len(m.Signatures))})
}
