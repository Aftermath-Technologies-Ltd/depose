// Package cmd, manifest-level checks: schema range, mode declaration, and
// the mode contract (what a declared mode requires of signatures and
// timestamps).
package cmd

import "fmt"

// checkSchemaVersion enforces the compatibility policy in
// docs/bundle-format.md#versioning: a verifier supports
// [SupportedSchemaMin, SupportedSchemaMax] and fails closed outside it.
func checkSchemaVersion(ctx *checkContext) []CheckResult {
	v := ctx.manifest.SchemaVersion
	if v < SupportedSchemaMin || v > SupportedSchemaMax {
		return one(CheckResult{
			Name:   "schema-version",
			Status: StatusFail,
			Detail: fmt.Sprintf("unsupported schemaVersion %d (this verifier supports [%d, %d])", v, SupportedSchemaMin, SupportedSchemaMax),
		})
	}
	return one(CheckResult{Name: "schema-version", Status: StatusPass, Detail: fmt.Sprintf("schemaVersion %d is supported", v)})
}

// checkModeDeclaration requires producer.mode to be a mode this verifier
// knows how to enforce.
func checkModeDeclaration(ctx *checkContext) []CheckResult {
	switch ctx.manifest.Producer.Mode {
	case "signed", "dev-unsigned":
		return one(CheckResult{Name: "mode-declaration", Status: StatusPass, Detail: fmt.Sprintf("producer.mode=%q recognized", ctx.manifest.Producer.Mode)})
	case "":
		return one(CheckResult{Name: "mode-declaration", Status: StatusFail, Detail: "producer.mode is missing, bundle predates the mode contract or has been stripped"})
	default:
		return one(CheckResult{Name: "mode-declaration", Status: StatusFail, Detail: fmt.Sprintf("producer.mode=%q is not a recognized mode (expected signed or dev-unsigned)", ctx.manifest.Producer.Mode)})
	}
}

// checkModeContract enforces the invariants of the declared mode:
// dev-unsigned must carry no signatures and no timestamps; signed must
// carry at least one of each.
func checkModeContract(ctx *checkContext) []CheckResult {
	m := ctx.manifest
	switch m.Producer.Mode {
	case "dev-unsigned":
		if len(m.Signatures) > 0 || len(m.Timestamps) > 0 {
			return one(CheckResult{
				Name:   "mode-contract",
				Status: StatusFail,
				Detail: fmt.Sprintf("dev-unsigned requires signatures=[] and timestamps=[]; got %d signature(s) and %d timestamp(s)", len(m.Signatures), len(m.Timestamps)),
			})
		}
		return one(CheckResult{Name: "mode-contract", Status: StatusPass, Detail: "dev-unsigned: signatures=[], timestamps=[] (as required)"})
	default:
		if len(m.Signatures) == 0 || len(m.Timestamps) == 0 {
			return one(CheckResult{
				Name:   "mode-contract",
				Status: StatusFail,
				Detail: fmt.Sprintf("signed requires at least one signature and at least one timestamp; got %d signature(s) and %d timestamp(s)", len(m.Signatures), len(m.Timestamps)),
			})
		}
		return one(CheckResult{Name: "mode-contract", Status: StatusPass, Detail: "signed: signatures and timestamps both present"})
	}
}
