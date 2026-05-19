// Package timestamp — Rekor transparency log verification (stub).
//
// Full Rekor verification requires network access to the Rekor API.
// The depose-verify binary works air-gapped for core verification,
// so Rekor is optional and gracefully skipped.
package timestamp

// RekorVerificationResult holds the outcome of Rekor verification.
type RekorVerificationResult struct {
	Skipped bool
	Detail  string
}

// VerifyRekorEntry is a stub — full Rekor verification is deferred.
// In air-gapped mode, Rekor verification is skipped with a clear note.
func VerifyRekorEntry(uuid string, body string, integratedTime int64) *RekorVerificationResult {
	return &RekorVerificationResult{
		Skipped: true,
		Detail:  "Rekor verification skipped (requires network). Optional transparency log — bundle integrity is independent of Rekor.",
	}
}