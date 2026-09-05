// Package cmd, table tests over a golden signed bundle and mutations of
// it. The golden bundle under testdata/golden was sealed by the real
// producer against FreeTSA; every mutation below must make a specific,
// named check fail, and the untouched bundle must pass every check.
package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goldenBundle = "../testdata/golden/incident-golden-pocketos"

// copyBundle copies the golden bundle into a temp dir so a mutation
// never touches the fixture.
func copyBundle(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "bundle")
	err := filepath.Walk(goldenBundle, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(goldenBundle, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy golden bundle: %v", err)
	}
	return dst
}

func readFile(t *testing.T, bundle, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bundle, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return data
}

func writeFile(t *testing.T, bundle, rel string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(bundle, rel), data, 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// editManifest applies fn to the parsed manifest and writes it back.
// The signature no longer matches afterwards, which is the point of
// most manifest mutations.
func editManifest(t *testing.T, bundle string, fn func(m map[string]interface{})) {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(readFile(t, bundle, "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, bundle, "manifest.json", out)
}

func statusOf(res *VerifyResult, name string) (CheckStatus, string) {
	for _, c := range res.Checks {
		if c.Name == name {
			return c.Status, c.Detail
		}
	}
	return "", ""
}

func flipHexChar(s string) string {
	if strings.HasPrefix(s, "0") {
		return "1" + s[1:]
	}
	return "0" + s[1:]
}

func TestGoldenBundlePassesEveryCheck(t *testing.T) {
	res := VerifyBundle(copyBundle(t))
	if !res.Pass {
		t.Fatalf("golden bundle must pass; checks: %+v", res.Checks)
	}
	// The golden session predates the PostToolUse hook, so it carries no
	// effect records and the two pairing checks report SKIPPED rather than
	// a pass they did not earn. golden-intent-effect covers those.
	skipped := map[string]bool{"intent-effect": true, "file-continuity": true}
	for _, c := range res.Checks {
		if skipped[c.Name] {
			if c.Status != StatusSkipped {
				t.Errorf("check %s: status %s, want SKIPPED (%s)", c.Name, c.Status, c.Detail)
			}
			continue
		}
		if c.Status != StatusPass {
			t.Errorf("check %s: status %s, want PASS (%s)", c.Name, c.Status, c.Detail)
		}
	}
	want := []string{"manifest-parse", "schema-version", "mode-declaration", "mode-contract", "signature-verify", "payload-hash", "chain-replay", "intent-effect", "file-continuity", "merkle-root", "commitments", "timestamp-verify", "timestamp-backdating", "anchor-status", "artifact-events-jsonl", "ruleset-integrity", "files-map", "attestation-files", "bundle-completeness"}
	if len(res.Checks) != len(want) {
		t.Fatalf("got %d checks, want %d", len(res.Checks), len(want))
	}
	for i, name := range want {
		if res.Checks[i].Name != name {
			t.Errorf("check[%d] = %s, want %s", i, res.Checks[i].Name, name)
		}
	}
}
