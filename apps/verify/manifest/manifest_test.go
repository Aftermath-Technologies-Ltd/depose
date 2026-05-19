package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/depose/depose/apps/verify/canonical"
)

// TestVerifySignature_CRLFPEM exercises the stdlib PEM decoder
// against a CRLF-line-ended public key. The previous custom decoder
// silently broke on CRLF input.
func TestVerifySignature_CRLFPEM(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	// Convert LF to CRLF — the bug we're guarding against.
	pubPEMCRLF := strings.ReplaceAll(string(pubPEM), "\n", "\r\n")

	m := &Manifest{
		SchemaVersion: 1,
		BundleID:      "test-bundle",
		ProducedAt:    "2025-05-18T16:00:00Z",
		Producer: ProducerInfo{
			Tool:    "depose",
			Version: "0.1.0",
			Mode:    "signed",
		},
		Session: SessionInfo{
			AgentID:   "claude-code",
			SessionID: "test",
			StartedAt: "2025-05-18T15:30:00Z",
			EndedAt:   "2025-05-18T15:31:00Z",
		},
		RootHash:    "0000000000000000000000000000000000000000000000000000000000000000",
		Counts:      Counts{Events: 1, DestructiveOperations: 0, Gaps: 0, ArtifactsPre: 0, ArtifactsPost: 0},
		RulesetHash: "1111111111111111111111111111111111111111111111111111111111111111",
	}

	// Round-trip via JSON to produce raw bytes the verifier will see.
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	// StripSignatureFields produces the canonical bytes we sign.
	unsigned, err := StripSignatureFields(raw)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	sig := ed25519.Sign(priv, unsigned)

	m.Signatures = []SignatureBlock{
		{
			Scheme:       "ed25519",
			Signature:    base64.StdEncoding.EncodeToString(sig),
			PublicKey:    pubPEMCRLF,
			SignedFields: "manifest.json",
		},
	}
	rawSigned, err := canonical.Marshal(toMap(m))
	if err != nil {
		t.Fatalf("marshal signed: %v", err)
	}

	if err := VerifySignature(m, rawSigned); err != nil {
		t.Fatalf("verify with CRLF PEM should succeed: %v", err)
	}
}

func toMap(m *Manifest) map[string]interface{} {
	b, _ := json.Marshal(m)
	var out map[string]interface{}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	_ = d.Decode(&out)
	return out
}
