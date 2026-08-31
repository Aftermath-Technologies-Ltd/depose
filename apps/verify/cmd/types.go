// Package cmd, shared types and constants for depose-verify.
package cmd

// Supported schemaVersion range. See docs/bundle-format.md §8 for
// the compatibility policy. Production bundles must declare a value
// in this inclusive range; anything else fails closed.
const (
	SupportedSchemaMin = 1
	SupportedSchemaMax = 2
)

// CheckResult represents the result of a single verification check.
type CheckResult struct {
	Name    string
	Pass    bool
	Detail  string
}

// VerifyOpts configures optional pinning behavior the recipient
// asks for: pinning to a specific key fingerprint (air-gapped key
// flow) or to a Sigstore signer identity (keyless flow).
type VerifyOpts struct {
	// ExpectedKeyFingerprint, when non-empty, is the lowercase hex
	// SHA-256 of the SPKI DER bytes of the public signing key.
	// Verification fails if manifest.producer.keyFingerprint
	// disagrees (or is missing).
	ExpectedKeyFingerprint string
	// SignerIdentityRegex, when non-empty, is a regex the Sigstore
	// signer cert identity must match. Currently a placeholder ,
	// the Sigstore code path is staged but not yet wired in.
	SignerIdentityRegex string
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
	Pass   bool
	// Mode is the declared producer.mode from the manifest ("signed"
	// or "dev-unsigned"). Empty if the manifest could not be parsed.
	Mode   string
	Bundle string
	Checks []CheckResult
}

// VerifyBundle runs all verification checks on a .depo bundle directory.
