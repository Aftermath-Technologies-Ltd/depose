package timestamp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// loadFreeTSAToken returns the test fixture token + its expected
// message hash. The fixture was produced by running:
//
//   openssl ts -query -data freetsa-message.txt -sha256 -cert ...
//   curl https://freetsa.org/tsr ...
//
// and committed under testdata/. It is a real, FreeTSA-signed
// timestamp over a known message.
func loadFreeTSAToken(t *testing.T) (Token, string) {
	t.Helper()
	tsrBytes, err := os.ReadFile(filepath.Join("testdata", "freetsa-token.tsr"))
	if err != nil {
		t.Fatalf("read fixture token: %v", err)
	}
	msgBytes, err := os.ReadFile(filepath.Join("testdata", "freetsa-message.txt"))
	if err != nil {
		t.Fatalf("read fixture message: %v", err)
	}
	hash := sha256.Sum256(msgBytes)
	return Token{
		TSA:         "FreeTSA",
		Timestamp:   "2026-05-19T21:14:36Z",
		TokenBase64: base64.StdEncoding.EncodeToString(tsrBytes),
	}, hex.EncodeToString(hash[:])
}

func TestVerifyToken_RealFreeTSAFixture(t *testing.T) {
	token, expectedHash := loadFreeTSAToken(t)
	res := VerifyToken(token, expectedHash)
	if !res.Valid {
		t.Fatalf("expected valid token, got Detail=%q", res.Detail)
	}
	if res.Timestamp.IsZero() {
		t.Errorf("expected non-zero Timestamp on valid token")
	}
}

func TestVerifyToken_HashMismatchFails(t *testing.T) {
	token, _ := loadFreeTSAToken(t)
	// Hash of an unrelated message — should not match the token's
	// HashedMessage field.
	otherHash := sha256.Sum256([]byte("not the original message"))
	res := VerifyToken(token, hex.EncodeToString(otherHash[:]))
	if res.Valid {
		t.Fatalf("expected hash mismatch to fail")
	}
}

// TestVerifyToken_SubstringScanForgeryFails is the canary for the
// security bug B1 fixed: the old verifier would happily PASS any
// DER blob that *contained* the expected hash bytes anywhere in
// its body. We construct exactly that — the expected hash appended
// to a SEQUENCE-prefixed garbage blob — and confirm the new
// verifier rejects it.
func TestVerifyToken_SubstringScanForgeryFails(t *testing.T) {
	_, expectedHash := loadFreeTSAToken(t)
	hashBytes, _ := hex.DecodeString(expectedHash)

	// 0x30 0x82 ... pretend SEQUENCE then random junk then the hash
	// embedded near the end.
	forged := append([]byte{0x30, 0x82, 0x00, 0x40}, make([]byte, 16)...)
	forged = append(forged, hashBytes...)
	forged = append(forged, make([]byte, 16)...)

	token := Token{
		TSA:         "forged-tsa",
		Timestamp:   "2026-05-19T21:14:36Z",
		TokenBase64: base64.StdEncoding.EncodeToString(forged),
	}
	res := VerifyToken(token, expectedHash)
	if res.Valid {
		t.Fatalf("forged token must NOT pass (this is the B1 regression test)")
	}
}

func TestVerifyToken_TamperedByteFails(t *testing.T) {
	token, expectedHash := loadFreeTSAToken(t)
	raw, _ := base64.StdEncoding.DecodeString(token.TokenBase64)
	// Flip a byte in the middle of the signature area. ParseResponse
	// reads the outer structure first; pkcs7 signature verification
	// is what should fail.
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	// Flip near the end where the signature octet string lives.
	idx := len(tampered) - 64
	tampered[idx] ^= 0xff
	token.TokenBase64 = base64.StdEncoding.EncodeToString(tampered)
	res := VerifyToken(token, expectedHash)
	if res.Valid {
		t.Fatalf("byte-flipped token must NOT pass")
	}
}

func TestVerifyManifestProducedAt_NoBackdating(t *testing.T) {
	tokens := []Token{
		{TSA: "FreeTSA", Timestamp: "2025-05-18T16:00:00Z"},
	}
	// producedAt equal to TSA time — fine.
	if err := VerifyManifestProducedAt("2025-05-18T16:00:00Z", tokens); err != nil {
		t.Errorf("equal times must pass: %v", err)
	}
	// producedAt strictly before TSA time — fine.
	if err := VerifyManifestProducedAt("2025-05-18T15:59:59Z", tokens); err != nil {
		t.Errorf("earlier produced time must pass: %v", err)
	}
	// producedAt one second after — must fail (tolerance reduced
	// from 1s to 0).
	if err := VerifyManifestProducedAt("2025-05-18T16:00:01Z", tokens); err == nil {
		t.Errorf("producedAt after TSA time must fail; got nil")
	}
}
