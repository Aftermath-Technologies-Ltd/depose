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

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/timestamp"
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

func TestMutationsFailNamedChecks(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(t *testing.T, bundle string)
		opts      VerifyOpts
		failCheck string
		detail    string
	}{
		{
			name: "signature byte flipped",
			mutate: func(t *testing.T, b string) {
				editManifest(t, b, func(m map[string]interface{}) {
					block := m["signatures"].([]interface{})[0].(map[string]interface{})
					sig := block["signature"].(string)
					replacement := "A"
					if sig[0] == 'A' {
						replacement = "B"
					}
					block["signature"] = replacement + sig[1:]
				})
			},
			failCheck: "signature-verify",
			detail:    "INVALID",
		},
		{
			name: "manifest field tampered (counts.events)",
			mutate: func(t *testing.T, b string) {
				editManifest(t, b, func(m map[string]interface{}) {
					m["counts"].(map[string]interface{})["events"] = 1
				})
			},
			failCheck: "signature-verify",
		},
		{
			name: "mode contract violated (dev-unsigned with signatures)",
			mutate: func(t *testing.T, b string) {
				editManifest(t, b, func(m map[string]interface{}) {
					m["producer"].(map[string]interface{})["mode"] = "dev-unsigned"
				})
			},
			failCheck: "mode-contract",
			detail:    "dev-unsigned requires signatures=[]",
		},
		{
			name:      "key fingerprint mismatch",
			mutate:    func(t *testing.T, b string) {},
			opts:      VerifyOpts{ExpectedKeyFingerprint: strings.Repeat("0", 64)},
			failCheck: "key-fingerprint-pin",
			detail:    "mismatch",
		},
		{
			name: "ruleset tampered",
			mutate: func(t *testing.T, b string) {
				data := readFile(t, b, "rules/destructive.yaml")
				writeFile(t, b, "rules/destructive.yaml", append(data, []byte("\n# added\n")...))
			},
			failCheck: "ruleset-integrity",
			detail:    "hash mismatch",
		},
		{
			name: "required file missing",
			mutate: func(t *testing.T, b string) {
				os.Remove(filepath.Join(b, "verify.txt"))
			},
			failCheck: "bundle-completeness",
			detail:    "verify.txt",
		},
		{
			name: "extra file appended to tree",
			mutate: func(t *testing.T, b string) {
				writeFile(t, b, "raw/planted.txt", []byte("planted"))
			},
			failCheck: "files-map",
			detail:    "raw/planted.txt is on disk but not in the files map",
		},
		{
			name: "files map mismatch (narrative rewritten, same length)",
			mutate: func(t *testing.T, b string) {
				data := readFile(t, b, "narrative.md")
				data[len(data)/2] ^= 0x01
				writeFile(t, b, "narrative.md", data)
			},
			failCheck: "files-map",
			detail:    "narrative.md: sha256 mismatch",
		},
		{
			name: "raw JSONL swapped",
			mutate: func(t *testing.T, b string) {
				writeFile(t, b, "raw/claude-code/session.synthetic.jsonl", []byte("{\"type\":\"user\",\"content\":\"nothing happened\"}\n"))
			},
			failCheck: "files-map",
			detail:    "raw/claude-code/session.synthetic.jsonl",
		},
		{
			name: "timestamp token deleted",
			mutate: func(t *testing.T, b string) {
				os.Remove(filepath.Join(b, "attestations/rfc3161-timestamps/0.tsr"))
			},
			failCheck: "attestation-files",
			detail:    "0.tsr is missing",
		},
		{
			name: "chain broken (chainHash hex flipped)",
			mutate: func(t *testing.T, b string) {
				data := string(readFile(t, b, "events.jsonl"))
				idx := strings.Index(data, `"chainHash":"`)
				if idx < 0 {
					t.Fatal("no chainHash in golden events")
				}
				start := idx + len(`"chainHash":"`)
				data = data[:start] + flipHexChar(data[start:start+64]) + data[start+64:]
				writeFile(t, b, "events.jsonl", []byte(data))
			},
			failCheck: "chain-replay",
			detail:    "Chain hash mismatch",
		},
		{
			name: "payload rewritten under its hash",
			mutate: func(t *testing.T, b string) {
				data := string(readFile(t, b, "events.jsonl"))
				if !strings.Contains(data, "fully torn down") {
					t.Fatal("golden events.jsonl lost the assistant text this mutation targets")
				}
				data = strings.Replace(data, "fully torn down", "left untouched", 1)
				writeFile(t, b, "events.jsonl", []byte(data))
			},
			failCheck: "payload-hash",
		},
		{
			name: "commitment opened with the wrong salt",
			mutate: func(t *testing.T, b string) {
				data := string(readFile(t, b, "commitments.json"))
				idx := strings.Index(data, `"salt": "`)
				if idx < 0 {
					t.Fatal("golden commitments.json has no salt")
				}
				start := idx + len(`"salt": "`)
				data = data[:start] + flipHexChar(data[start:start+64]) + data[start+64:]
				writeFile(t, b, "commitments.json", []byte(data))
			},
			failCheck: "commitments",
			detail:    "wrong salt or value",
		},
		{
			name: "committed value rewritten in its opening",
			mutate: func(t *testing.T, b string) {
				data := string(readFile(t, b, "commitments.json"))
				if !strings.Contains(data, "terraform destroy -auto-approve") {
					t.Fatal("golden commitments.json does not hold the destroy command")
				}
				data = strings.Replace(data, "terraform destroy -auto-approve", "terraform plan -auto-approve", 1)
				writeFile(t, b, "commitments.json", []byte(data))
			},
			failCheck: "commitments",
		},
		{
			name: "commitments.json deleted while events still carry placeholders",
			mutate: func(t *testing.T, b string) {
				os.Remove(filepath.Join(b, "commitments.json"))
			},
			failCheck: "commitments",
			detail:    "no opening",
		},
		{
			name: "unsupported schema version",
			mutate: func(t *testing.T, b string) {
				editManifest(t, b, func(m map[string]interface{}) { m["schemaVersion"] = 99 })
			},
			failCheck: "schema-version",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := copyBundle(t)
			tc.mutate(t, bundle)
			res := VerifyBundle(bundle, tc.opts)
			if res.Pass {
				t.Fatalf("mutation must fail verification")
			}
			status, detail := statusOf(res, tc.failCheck)
			if status != StatusFail {
				t.Fatalf("check %s: status %q, want FAIL; checks: %+v", tc.failCheck, status, res.Checks)
			}
			if tc.detail != "" && !strings.Contains(detail, tc.detail) {
				t.Errorf("check %s detail %q does not mention %q", tc.failCheck, detail, tc.detail)
			}
		})
	}
}

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
