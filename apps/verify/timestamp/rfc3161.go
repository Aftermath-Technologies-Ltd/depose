// Package timestamp, RFC 3161 timestamp verification for DEPOSE bundles.
//
// This is the *real* verifier; earlier versions did a byte-substring
// scan over the DER blob, which a forger could pass by appending the
// expected hash to any DER. Now we:
//
//  1. ParseResponse the TimeStampResp bytes (digitorus/timestamp).
//  2. Reject any hashAlgorithm that is not SHA-256.
//  3. Compare TSTInfo.HashedMessage to the expected SHA-256.
//  4. Parse the embedded SignedData (pkcs7) and verify its signature
//     with the embedded TSA signing certificate, validating the
//     chain against a truststore of embedded RFC 3161 roots.
//
// The truststore is package-level state initialized once in init(),
// and contains the embedded FreeTSA root plus the system trust pool
// (used by DigiCert and Sectigo, which chain to public CAs). A
// `//go:build testroots` companion file may register synthetic
// roots for unit tests; production binaries do not include it.
package timestamp

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/digitorus/pkcs7"
	digitstamp "github.com/digitorus/timestamp"
)

// Token represents an RFC 3161 timestamp token from a TSA, as
// embedded in a DEPOSE manifest's `timestamps[]` array.
type Token struct {
	TSA         string `json:"tsa"`
	Timestamp   string `json:"timestamp"`
	TokenBase64 string `json:"tokenBase64"`
}

// VerifyResult holds the outcome of timestamp verification.
type VerifyResult struct {
	TSA       string
	Timestamp time.Time
	Valid     bool
	Detail    string
}

// trustPool is the verifier's truststore for TSA cert chain
// validation. It is built lazily on first use to allow test code
// (via a build-tagged file) to extend it before any verification
// runs.
var trustPool *x509.CertPool

func getTrustPool() *x509.CertPool {
	if trustPool != nil {
		return trustPool
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	// The roots of the TSAs DEPOSE anchors to, embedded so the answer
	// does not depend on the recipient's trust store. See roots.go.
	pool.AppendCertsFromPEM(FreeTSACARootPEM)
	pool.AppendCertsFromPEM(DigiCertTrustedRootG4PEM)
	for _, extra := range extraTestRoots {
		pool.AppendCertsFromPEM(extra)
	}
	trustPool = pool
	return trustPool
}

// extraTestRoots is overridden by a build-tagged file in unit tests
// (see roots_test.go). Production builds leave it empty.
var extraTestRoots [][]byte

// LoadTimestamps reads RFC 3161 tokens from the bundle's manifest.
func LoadTimestamps(bundleDir string) ([]Token, error) {
	path := filepath.Join(bundleDir, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	var manifest struct {
		Timestamps []Token `json:"timestamps"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	return manifest.Timestamps, nil
}

// VerifyToken performs full RFC 3161 verification:
//
//  1. Base64 decode + ParseResponse.
//  2. hashAlgorithm must be SHA-256 (reject MD5, SHA-1).
//  3. TSTInfo.HashedMessage must equal the expected SHA-256 bytes.
//  4. SignedData signature must verify against the embedded TSA
//     cert; the cert chain must validate against trustPool.
//
// Returns a VerifyResult with Valid=false and a Detail string on
// any failure. The forged-substring attack the previous verifier
// allowed is impossible here: an attacker would need to forge a
// PKCS7 signature using a key whose cert chains to a trusted RFC
// 3161 CA.
func VerifyToken(token Token, expectedHashHex string) *VerifyResult {
	result := &VerifyResult{
		TSA: fmt.Sprintf("%s(%s)", token.TSA, token.Timestamp),
	}

	expectedHash, err := hex.DecodeString(expectedHashHex)
	if err != nil {
		result.Detail = fmt.Sprintf("expected hash hex invalid: %v", err)
		return result
	}

	tsrBytes, err := base64.StdEncoding.DecodeString(token.TokenBase64)
	if err != nil {
		result.Detail = fmt.Sprintf("cannot base64-decode token: %v", err)
		return result
	}

	parsed, err := parseTSR(tsrBytes)
	if err != nil {
		result.Detail = fmt.Sprintf("parse RFC 3161 token: %v", err)
		return result
	}

	if parsed.HashAlgorithm != crypto.SHA256 {
		result.Detail = fmt.Sprintf(
			"unsupported hash algorithm %v (expected SHA-256)", parsed.HashAlgorithm)
		return result
	}

	if !bytesEqualConstantTime(parsed.HashedMessage, expectedHash) {
		result.Detail = fmt.Sprintf(
			"messageImprint mismatch: token hash %s != expected %s",
			hex.EncodeToString(parsed.HashedMessage), expectedHashHex)
		return result
	}

	// Signature + chain validation over the SignedData.
	if err := verifySignedData(parsed); err != nil {
		result.Detail = err.Error()
		return result
	}

	result.Timestamp = parsed.Time
	result.Valid = true
	result.Detail = fmt.Sprintf("RFC 3161 token cryptographically valid (%s, %d cert(s) in chain)",
		parsed.Time.UTC().Format(time.RFC3339), len(parsed.Certificates))
	return result
}

// parseTSR tries ParseResponse first (full TimeStampResp envelope)
// and falls back to Parse (bare TimeStampToken). Producers may emit
// either depending on the TSA endpoint.
//
// The bytes are checked for strict DER well-formedness first (der.go),
// and the library calls run under a recover guard: a panic inside a
// third-party parser becomes an error, never a crash.
func parseTSR(b []byte) (ts *digitstamp.Timestamp, err error) {
	if derErr := checkDER(b); derErr != nil {
		return nil, derErr
	}
	defer func() {
		if r := recover(); r != nil {
			ts = nil
			err = fmt.Errorf("TSR parser panicked on malformed input: %v", r)
		}
	}()
	if t, respErr := digitstamp.ParseResponse(b); respErr == nil {
		return t, nil
	}
	return digitstamp.Parse(b)
}

// verifySignedData parses the token's SignedData and verifies its
// signature and certificate chain at the token's own time, so an expired
// TSA cert that was valid when it signed still passes; that is the whole
// point of long-term RFC 3161 timestamps. Runs under a recover guard for
// the same reason parseTSR does.
func verifySignedData(parsed *digitstamp.Timestamp) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("SignedData parser panicked on malformed input: %v", r)
		}
	}()
	p7, parseErr := pkcs7.Parse(parsed.RawToken)
	if parseErr != nil {
		return fmt.Errorf("parse SignedData: %w", parseErr)
	}
	if verifyErr := p7.VerifyWithChainAtTime(getTrustPool(), parsed.Time); verifyErr != nil {
		return fmt.Errorf("SignedData signature/chain INVALID: %w", verifyErr)
	}
	return nil
}

// bytesEqualConstantTime is a length-checking constant-time compare.
// Hash compares are not a confidentiality-sensitive operation here,
// but constant-time is cheap and avoids surprising tooling.
func bytesEqualConstantTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// VerifyManifestProducedAt checks that producedAt is not after any
// RFC 3161 timestamp (anti-backdating check).
//
// We allow up to 1 second of tolerance because RFC 3161 TSAs
// typically truncate to whole-second precision in the genTime
// field. A producer that records producedAt as
// 21:39:00.367Z and then receives a TSA token reporting
// 21:39:00.000Z (the same wall-clock second, truncated) is not
// backdating; it's the TSA's reporting precision.
const backdateToleranceSeconds = 1

func VerifyManifestProducedAt(producedAt string, tokens []Token) error {
	producedTime, err := parseTimestamp(producedAt)
	if err != nil {
		return fmt.Errorf("parse producedAt %q: %w", producedAt, err)
	}

	for _, token := range tokens {
		ts, err := parseTimestamp(token.Timestamp)
		if err != nil {
			continue
		}
		// Backdating = producedAt > ts + tolerance.
		// The TSA truncates to whole seconds, so producedAt is
		// allowed to be at most 1 second after the reported time.
		if producedTime.After(ts.Add(backdateToleranceSeconds * time.Second)) {
			return fmt.Errorf(
				"manifest producedAt (%s) is AFTER timestamp from %s (%s), possible backdating",
				producedAt, token.TSA, token.Timestamp)
		}
	}

	return nil
}

func parseTimestamp(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02T15:04:05.000Z", s)
}
