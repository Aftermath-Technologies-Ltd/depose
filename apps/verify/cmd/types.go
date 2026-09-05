// Package cmd, shared types and constants for depose-verify.
package cmd

// Supported schemaVersion range. See docs/bundle-format.md §8 for
// the compatibility policy. Production bundles must declare a value
// in this inclusive range; anything else fails closed.
const (
	SupportedSchemaMin = 2
	SupportedSchemaMax = 3
)

// CheckStatus is the outcome of one check. A skipped or warned check is
// never rendered as PASS; the report shows exactly which state it is in.
type CheckStatus string

const (
	// StatusPass: the check ran and the bundle satisfied it.
	StatusPass CheckStatus = "PASS"
	// StatusFail: the check ran and the bundle did not satisfy it.
	StatusFail CheckStatus = "FAIL"
	// StatusSkipped: the check did not run, by mode contract or missing input.
	StatusSkipped CheckStatus = "SKIPPED"
	// StatusWarn: the check ran; the bundle is weaker than current
	// producers emit but not invalid (a downgrade, not a tamper).
	StatusWarn CheckStatus = "WARN"
)

// CheckResult represents the result of a single verification check.
type CheckResult struct {
	Name   string
	Status CheckStatus
	Detail string
}

// Failed reports whether the check counts against the bundle.
func (c CheckResult) Failed() bool { return c.Status == StatusFail }

// VerifyOpts configures optional pinning behavior the recipient
// asks for: pinning to a specific key fingerprint (air-gapped key
// flow) or to a Sigstore signer identity (keyless flow).
type VerifyOpts struct {
	// ExpectedKeyFingerprint, when non-empty, is the lowercase hex
	// SHA-256 of the SPKI DER bytes of the public signing key.
	// Verification fails if manifest.producer.keyFingerprint
	// disagrees (or is missing).
	ExpectedKeyFingerprint string
	// RevocationListPath, when non-empty, points at a producer key
	// catalog (the JSON file emitted by `depose key catalog --export`).
	// If the manifest's keyFingerprint appears in the catalog with
	// status="revoked", verification fails closed. Other statuses
	// (active, rotated) do not fail.
	RevocationListPath string
}

// keyCatalogEntry mirrors the shape of packages/chain/src/key-catalog.ts.
// Kept here (rather than in its own package) because this is the only
// consumer in Go; if other tools need it, lift it.
type keyCatalogEntry struct {
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	RevokedAt   string `json:"revokedAt,omitempty"`
}

type keyCatalog struct {
	SchemaVersion int               `json:"schemaVersion"`
	Entries       []keyCatalogEntry `json:"entries"`
}

// VerifyResult represents the overall verification result.
type VerifyResult struct {
	Pass bool
	// Mode is the declared producer.mode from the manifest ("signed"
	// or "dev-unsigned"). Empty if the manifest could not be parsed.
	Mode   string
	Bundle string
	Checks []CheckResult
	// Disclosure is true when the directory was verified as a disclosure
	// bundle rather than a full one.
	Disclosure bool
	// DisclosedEvents and LeafCount describe a disclosure's coverage.
	DisclosedEvents int
	LeafCount       int
}

// VerifyBundle runs all verification checks on a .depo bundle directory.
