package timestamp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// The TSR parser sits on the trust boundary: a recipient feeds it bytes
// an adversary chose. The verifier delegates DER parsing to
// digitorus/timestamp and digitorus/pkcs7, so those are what get fuzzed,
// through the same entry points the verifier calls. The corpus is
// seeded with a real token from each supported TSA.

func seedTokens(t testing.TB) [][]byte {
	t.Helper()
	var seeds [][]byte
	for _, name := range []string{"freetsa-token.tsr", "digicert-token.tsr"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("read seed %s: %v", name, err)
		}
		seeds = append(seeds, b)
	}
	return seeds
}

func FuzzParseTSR(f *testing.F) {
	for _, s := range seedTokens(f) {
		f.Add(s)
	}
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{})
	expected := sha256.Sum256([]byte("fuzz"))
	expectedHex := hex.EncodeToString(expected[:])
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic or hang. Any error is acceptable.
		_, _ = parseTSR(data)
		res := VerifyToken(Token{TSA: "fuzz", TokenBase64: base64.StdEncoding.EncodeToString(data)}, expectedHex)
		if res.Valid {
			t.Fatalf("fuzz input must not verify as a valid token over an unrelated hash")
		}
	})
}

// TestVerifyToken_RealDigiCertFixture proves the second supported TSA
// verifies through the system trust pool, and that the corpus seed is
// a genuine token rather than an opaque blob.
func TestVerifyToken_RealDigiCertFixture(t *testing.T) {
	tsr, err := os.ReadFile(filepath.Join("testdata", "digicert-token.tsr"))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := os.ReadFile(filepath.Join("testdata", "digicert-message.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(msg)
	res := VerifyToken(Token{TSA: "DigiCert", TokenBase64: base64.StdEncoding.EncodeToString(tsr)}, hex.EncodeToString(sum[:]))
	if !res.Valid {
		t.Fatalf("DigiCert fixture must verify: %s", res.Detail)
	}
}
