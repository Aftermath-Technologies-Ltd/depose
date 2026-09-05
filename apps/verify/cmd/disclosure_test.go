package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The golden disclosure under testdata/golden-disclosure was produced by
// `depose disclose` from the golden bundle (5 of 10 events, /toolInput
// opened, /output and /toolCalls withheld). It must verify with no
// access to the original, and each mutation must fail a named check.

const goldenDisclosure = "../testdata/golden-disclosure"

func copyDisclosure(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "disclosure")
	err := filepath.Walk(goldenDisclosure, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(goldenDisclosure, path)
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
		t.Fatalf("copy golden disclosure: %v", err)
	}
	return dst
}

func editDisclosure(t *testing.T, dir string, fn func(d map[string]interface{})) {
	t.Helper()
	var d map[string]interface{}
	if err := json.Unmarshal(readFile(t, dir, "disclosure.json"), &d); err != nil {
		t.Fatal(err)
	}
	fn(d)
	out, _ := json.Marshal(d)
	writeFile(t, dir, "disclosure.json", out)
}

func TestGoldenDisclosureVerifiesStandalone(t *testing.T) {
	dir := copyDisclosure(t)
	if _, err := os.Stat(filepath.Join(dir, "raw")); err == nil {
		t.Fatal("the disclosure must not carry raw/ from the original")
	}
	res := VerifyDisclosure(dir)
	if !res.Pass {
		t.Fatalf("golden disclosure must pass: %+v", res.Checks)
	}
	want := []string{"manifest-parse", "schema-version", "mode-declaration", "mode-contract", "signature-verify", "disclosure-parse", "disclosure-inclusion", "disclosure-commitments", "timestamp-verify", "timestamp-backdating", "disclosure-files", "attestation-files"}
	if len(res.Checks) != len(want) {
		t.Fatalf("got %d checks, want %d: %+v", len(res.Checks), len(want), res.Checks)
	}
	for i, name := range want {
		if res.Checks[i].Name != name || res.Checks[i].Status != StatusPass {
			t.Errorf("check[%d] = %s %s, want %s PASS", i, res.Checks[i].Name, res.Checks[i].Status, name)
		}
	}
	if res.DisclosedEvents != 5 || res.LeafCount != 10 {
		t.Errorf("coverage %d of %d, want 5 of 10", res.DisclosedEvents, res.LeafCount)
	}
	if !IsDisclosure(dir) || IsDisclosure(goldenBundle) {
		t.Error("IsDisclosure must recognise a disclosure and not a full bundle")
	}
}

func TestDisclosureMutationsFailNamedChecks(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(t *testing.T, dir string)
		failCheck string
		detail    string
	}{
		{
			name: "disclosed event payload modified",
			mutate: func(t *testing.T, dir string) {
				data := string(readFile(t, dir, "events.jsonl"))
				if !strings.Contains(data, "tear down") {
					t.Fatal("expected assistant text in the disclosed events")
				}
				writeFile(t, dir, "events.jsonl", []byte(strings.Replace(data, "tear down", "keep up  ", 1)))
			},
			failCheck: "disclosure-inclusion",
			detail:    "disclosed event modified",
		},
		{
			name: "disclosed event metadata modified (wallTs)",
			mutate: func(t *testing.T, dir string) {
				data := string(readFile(t, dir, "events.jsonl"))
				idx := strings.Index(data, `"wallTs":"`)
				start := idx + len(`"wallTs":"`)
				data = data[:start] + "2099" + data[start+4:]
				writeFile(t, dir, "events.jsonl", []byte(data))
			},
			failCheck: "disclosure-inclusion",
			detail:    "chainHash does not recompute",
		},
		{
			name: "forged audit path on a disclosed event",
			mutate: func(t *testing.T, dir string) {
				editDisclosure(t, dir, func(d map[string]interface{}) {
					entry := d["disclosed"].([]interface{})[0].(map[string]interface{})
					path := entry["auditPath"].([]interface{})
					path[0] = flipHexChar(path[0].(string))
				})
			},
			failCheck: "disclosure-inclusion",
			detail:    "forged or misplaced proof",
		},
		{
			name: "withheld chain hash altered",
			mutate: func(t *testing.T, dir string) {
				editDisclosure(t, dir, func(d map[string]interface{}) {
					entry := d["withheld"].([]interface{})[0].(map[string]interface{})
					entry["chainHash"] = flipHexChar(entry["chainHash"].(string))
				})
			},
			failCheck: "disclosure-inclusion",
			detail:    "audit path does not reach the signed root",
		},
		{
			name: "disclosure claims a root the signature does not cover",
			mutate: func(t *testing.T, dir string) {
				editDisclosure(t, dir, func(d map[string]interface{}) {
					d["merkleRoot"] = flipHexChar(d["merkleRoot"].(string))
				})
			},
			failCheck: "disclosure-parse",
			detail:    "signed manifest covers",
		},
		{
			name: "manifest merkleRoot rewritten to match a forged disclosure",
			mutate: func(t *testing.T, dir string) {
				editManifest(t, dir, func(m map[string]interface{}) {
					m["merkleRoot"] = flipHexChar(m["merkleRoot"].(string))
				})
			},
			failCheck: "signature-verify",
		},
		{
			name: "commitment opened with the wrong salt",
			mutate: func(t *testing.T, dir string) {
				data := string(readFile(t, dir, "commitments.json"))
				idx := strings.Index(data, `"salt": "`)
				start := idx + len(`"salt": "`)
				data = data[:start] + flipHexChar(data[start:start+64]) + data[start+64:]
				writeFile(t, dir, "commitments.json", []byte(data))
			},
			failCheck: "disclosure-commitments",
			detail:    "wrong salt or value",
		},
		{
			name: "opened value rewritten",
			mutate: func(t *testing.T, dir string) {
				data := string(readFile(t, dir, "commitments.json"))
				if !strings.Contains(data, "terraform") {
					t.Fatal("expected the terraform command in the opened field")
				}
				writeFile(t, dir, "commitments.json", []byte(strings.Replace(data, "terraform", "tofu", 1)))
			},
			failCheck: "disclosure-commitments",
		},
		{
			name: "a position dropped from the partition",
			mutate: func(t *testing.T, dir string) {
				editDisclosure(t, dir, func(d map[string]interface{}) {
					w := d["withheld"].([]interface{})
					d["withheld"] = w[1:]
				})
			},
			failCheck: "disclosure-parse",
			detail:    "not fully accounted for",
		},
		{
			name: "carried file not pinned by the seal",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, dir, "rules/extra.yaml", []byte("planted"))
			},
			failCheck: "disclosure-files",
			detail:    "not pinned",
		},
		{
			name: "carried ruleset modified",
			mutate: func(t *testing.T, dir string) {
				data := readFile(t, dir, "rules/destructive.yaml")
				writeFile(t, dir, "rules/destructive.yaml", append(data, '\n'))
			},
			failCheck: "disclosure-files",
			detail:    "does not match the sealed files map",
		},
		{
			name: "timestamp token deleted",
			mutate: func(t *testing.T, dir string) {
				os.Remove(filepath.Join(dir, "attestations/rfc3161-timestamps/0.tsr"))
			},
			failCheck: "attestation-files",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyDisclosure(t)
			tc.mutate(t, dir)
			res := VerifyDisclosure(dir)
			if res.Pass {
				t.Fatalf("mutation must fail")
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

func TestConsistencyOfTwoDisclosuresFromOneSeal(t *testing.T) {
	a := copyDisclosure(t)
	b := copyDisclosure(t)
	res := VerifyConsistency(a, b)
	if !res.Pass {
		t.Fatalf("two disclosures of the same seal must be consistent: %+v", res.Checks)
	}
	if s, _ := statusOf(res, "tree-consistency"); s != StatusPass {
		t.Errorf("tree-consistency %s", s)
	}
	if s, d := statusOf(res, "disclosed-overlap"); s != StatusPass || !strings.Contains(d, "5 event(s)") {
		t.Errorf("disclosed-overlap %s %s", s, d)
	}

	// A disclosure whose overlapping event differs is not consistent.
	c := copyDisclosure(t)
	data := string(readFile(t, c, "events.jsonl"))
	writeFile(t, c, "events.jsonl", []byte(strings.Replace(data, "tear down", "keep up  ", 1)))
	if VerifyConsistency(a, c).Pass {
		t.Error("a modified later disclosure must not verify as consistent")
	}
}
