package timestamp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The embedded roots are trust anchors compiled into the verifier, so
// two things have to be true and stay true: they are the certificates
// they claim to be, and they are sufficient on their own. The second
// point is what CI caught: the DigiCert fixture verified on Linux and
// failed on macOS, because the chain was reaching a root through the
// host's trust store rather than through anything DEPOSE ships.

// digestOf returns the SHA-256 of a PEM certificate's DER bytes, which
// is the fingerprint every CA publishes and every trust store lists.
func digestOf(t *testing.T, pemBytes []byte) string {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("embedded root is not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func TestEmbeddedRootsAreTheCertificatesTheyClaimToBe(t *testing.T) {
	cases := []struct {
		name    string
		pem     []byte
		subject string
		digest  string
	}{
		{
			name:    "DigiCert Trusted Root G4",
			pem:     DigiCertTrustedRootG4PEM,
			subject: "DigiCert Trusted Root G4",
			// Matches Mozilla's CA bundle and DigiCert's published copy.
			digest: "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := digestOf(t, tc.pem); got != tc.digest {
				t.Fatalf("embedded root digest is %s, want %s; the trust anchor changed", got, tc.digest)
			}
			block, _ := pem.Decode(tc.pem)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cert.Subject.CommonName != tc.subject {
				t.Errorf("subject = %q, want %q", cert.Subject.CommonName, tc.subject)
			}
			if !cert.IsCA {
				t.Error("a trust anchor must be a CA certificate")
			}
			if time.Now().After(cert.NotAfter) {
				t.Errorf("embedded root expired on %s; bundles anchored to this TSA no longer verify", cert.NotAfter)
			}
		})
	}
}

// TestDigiCertChainVerifiesWithoutTheSystemPool reproduces the macOS
// failure: a pool holding only what DEPOSE embeds. On Linux the system
// pool happened to carry the root, which is why this passed there and
// not on a macOS runner.
func TestDigiCertChainVerifiesWithoutTheSystemPool(t *testing.T) {
	tsr, err := os.ReadFile(filepath.Join("testdata", "digicert-token.tsr"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := parseTSR(tsr)
	if err != nil {
		t.Fatalf("parse the fixture: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(DigiCertTrustedRootG4PEM) {
		t.Fatal("embedded DigiCert root did not load")
	}
	intermediates := x509.NewCertPool()
	var leaf *x509.Certificate
	for _, cert := range signed.Certificates {
		if !cert.IsCA {
			leaf = cert
			continue
		}
		intermediates.AddCert(cert)
	}
	if leaf == nil {
		t.Fatal("fixture carries no leaf certificate")
	}

	// The responder certificate has expired by now; what is under test is
	// whether the chain reaches an anchor DEPOSE ships, not whether it is
	// still valid today, so verification is pinned to the token's own time.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   leaf.NotBefore.Add(time.Hour),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		t.Fatalf("DigiCert chain must reach an embedded root without the system pool: %v", err)
	}
}

// TestFreeTSAChainVerifiesWithoutTheSystemPool is the same assertion for
// the other default TSA, whose root has never been in any trust store.
func TestFreeTSAChainVerifiesWithoutTheSystemPool(t *testing.T) {
	tsr, err := os.ReadFile(filepath.Join("testdata", "freetsa-token.tsr"))
	if err != nil {
		t.Skipf("no FreeTSA fixture: %v", err)
	}
	signed, err := parseTSR(tsr)
	if err != nil {
		t.Fatalf("parse the fixture: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(FreeTSACARootPEM) {
		t.Fatal("embedded FreeTSA root did not load")
	}
	intermediates := x509.NewCertPool()
	var leaf *x509.Certificate
	for _, cert := range signed.Certificates {
		if !cert.IsCA {
			leaf = cert
			continue
		}
		intermediates.AddCert(cert)
	}
	if leaf == nil {
		t.Fatal("fixture carries no leaf certificate")
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   leaf.NotBefore.Add(time.Hour),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		t.Fatalf("FreeTSA chain must reach the embedded root: %v", err)
	}
}
