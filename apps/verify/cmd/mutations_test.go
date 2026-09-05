package cmd

// One mutation per row, each of which must fail one named check. This is
// the table the phase-2 brief asked for: a check with no failing case is
// not a check, and a report that fails without naming what failed is not
// a report.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
