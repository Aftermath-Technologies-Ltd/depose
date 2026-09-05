package cmd

// The driver's own behaviour, as distinct from the individual checks:
// which failures stop the run and which do not, and the three checks
// whose failing case needs a bundle built for it rather than a mutation
// of the golden one.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/timestamp"
)

func TestSignatureFailureShortCircuits(t *testing.T) {
	bundle := copyBundle(t)
	editManifest(t, bundle, func(m map[string]interface{}) { m["rootHash"] = strings.Repeat("0", 64) })
	res := VerifyBundle(bundle)
	last := res.Checks[len(res.Checks)-1]
	if last.Name != "remaining-checks" || last.Status != StatusSkipped {
		t.Fatalf("expected remaining-checks SKIPPED after a bad signature, got %+v", last)
	}
	if status, _ := statusOf(res, "chain-replay"); status != "" {
		t.Errorf("chain-replay must not run after the signature fails")
	}
}

func TestNonFatalFailuresKeepGoing(t *testing.T) {
	bundle := copyBundle(t)
	os.Remove(filepath.Join(bundle, "verify.txt"))
	res := VerifyBundle(bundle)
	if status, _ := statusOf(res, "bundle-completeness"); status != StatusFail {
		t.Errorf("bundle-completeness should still run after files-map fails")
	}
	if status, _ := statusOf(res, "files-map"); status != StatusFail {
		t.Errorf("files-map should fail on the deleted file")
	}
}

func TestBackdatingCheckRejectsProducedAtAfterToken(t *testing.T) {
	tokens := []timestamp.Token{{TSA: "FreeTSA", Timestamp: "2025-05-18T16:00:00Z"}}
	if r := backdatingResult("2025-05-18T16:00:02Z", tokens); r.Status != StatusFail {
		t.Errorf("producedAt 2s after the token must fail, got %s", r.Status)
	}
	if r := backdatingResult("2025-05-18T16:00:00Z", tokens); r.Status != StatusPass {
		t.Errorf("producedAt equal to the token must pass, got %s", r.Status)
	}
}

// TestMerkleRootCheckRejectsWrongRoot exercises the check in isolation:
// a manifest tamper would stop the run at signature-verify, so the root
// comparison is tested through the check function directly.
func TestMerkleRootCheckRejectsWrongRoot(t *testing.T) {
	bundle := copyBundle(t)
	res := VerifyBundle(bundle)
	if !res.Pass {
		t.Fatal("golden must pass")
	}
	m, raw, parse := checkManifestParse(bundle)
	if parse.Failed() {
		t.Fatal(parse.Detail)
	}
	ctx := &checkContext{bundlePath: bundle, manifest: m, rawManifest: raw}
	checkChain(ctx)
	if r := checkMerkleRoot(ctx); r[0].Status != StatusPass {
		t.Fatalf("golden root must pass: %s", r[0].Detail)
	}
	m.MerkleRoot = strings.Repeat("0", 64)
	if r := checkMerkleRoot(ctx); r[0].Status != StatusFail {
		t.Fatalf("wrong root must fail, got %s", r[0].Status)
	}
	m.MerkleRoot = ""
	if r := checkMerkleRoot(ctx); r[0].Status != StatusWarn {
		t.Fatalf("missing root must be a downgrade warning, got %s", r[0].Status)
	}
}
