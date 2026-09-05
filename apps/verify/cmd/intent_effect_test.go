package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The golden bundle under testdata/golden-intent-effect was produced by
// the real Claude Code hook path (both halves) over five tool calls, four
// of them closed by a PostToolUse record. It carries one lost outcome, one
// file changed by something outside the session, and two kernel execve
// records, one of which no hook witnessed. Regenerate it with:
//
//	DEPOSE_WRITE_GOLDEN=1 npx vitest run packages/cli/test/hook-intent-effect-bundle.test.ts
const goldenIntentEffect = "../testdata/golden-intent-effect"

func copyIntentEffectBundle(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "bundle")
	err := filepath.Walk(goldenIntentEffect, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(goldenIntentEffect, path)
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
		t.Fatalf("copy golden intent-effect bundle: %v", err)
	}
	return dst
}

func TestGoldenIntentEffectBundle(t *testing.T) {
	res := VerifyBundle(copyIntentEffectBundle(t))
	if !res.Pass {
		t.Fatalf("golden intent-effect bundle must pass; checks: %+v", res.Checks)
	}
	want := map[string]CheckStatus{
		"intent-effect":   StatusPass,
		"file-continuity": StatusPass,
		// A development bundle carries no chain and no signature, and the
		// report says so rather than rendering either as PASS.
		"chain-replay":     StatusSkipped,
		"signature-verify": StatusSkipped,
	}
	for name, status := range want {
		if got, detail := statusOf(res, name); got != status {
			t.Errorf("check %s = %s, want %s (%s)", name, got, status, detail)
		}
	}
	if _, detail := statusOf(res, "intent-effect"); !strings.Contains(detail, "4 tool call(s)") {
		t.Errorf("intent-effect detail does not report the pair count: %s", detail)
	}
}

func TestIntentEffectMutationsFailNamedChecks(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(t *testing.T, dir string)
		failCheck string
		detail    string
	}{
		{
			name: "the gap disclosing a lost outcome is removed",
			mutate: func(t *testing.T, dir string) {
				editEvents(t, dir, func(events []map[string]interface{}) []map[string]interface{} {
					return dropGap(events, "intent_without_effect")
				})
			},
			failCheck: "intent-effect",
			detail:    "no intent_without_effect gap discloses it",
		},
		{
			name: "the gap disclosing an unwitnessed file change is removed",
			mutate: func(t *testing.T, dir string) {
				editEvents(t, dir, func(events []map[string]interface{}) []map[string]interface{} {
					return dropGap(events, "unwitnessed_file_change")
				})
			},
			failCheck: "file-continuity",
			detail:    "no unwitnessed_file_change gap disclosing the difference",
		},
		{
			name: "an effect names an intent that is not in the bundle",
			mutate: func(t *testing.T, dir string) {
				editEvents(t, dir, func(events []map[string]interface{}) []map[string]interface{} {
					effect := firstOfType(events, "tool_call_effect")
					payload := effect["payload"].(map[string]interface{})
					payload["intentEventId"] = "01ZZZZZZZZZZZZZZZZZZZZZZZZ"
					return events
				})
			},
			failCheck: "intent-effect",
			detail:    "not a shell_command_pre event in this bundle",
		},
		{
			name: "two effects claim the same intent",
			mutate: func(t *testing.T, dir string) {
				editEvents(t, dir, func(events []map[string]interface{}) []map[string]interface{} {
					var effects []map[string]interface{}
					for _, evt := range events {
						if evt["type"] == "tool_call_effect" {
							effects = append(effects, evt)
						}
					}
					first := effects[0]["payload"].(map[string]interface{})
					second := effects[1]["payload"].(map[string]interface{})
					second["intentEventId"] = first["intentEventId"]
					return events
				})
			},
			failCheck: "intent-effect",
			detail:    "closed by two effects",
		},
		{
			name: "the unsigned correlation on an intent points somewhere else",
			mutate: func(t *testing.T, dir string) {
				editEvents(t, dir, func(events []map[string]interface{}) []map[string]interface{} {
					effect := firstOfType(events, "tool_call_effect")
					intentID := effect["payload"].(map[string]interface{})["intentEventId"].(string)
					for _, evt := range events {
						if evt["id"] == intentID {
							evt["correlation"] = map[string]interface{}{"linkedEffectId": "01ZZZZZZZZZZZZZZZZZZZZZZZZ"}
						}
					}
					return events
				})
			},
			failCheck: "intent-effect",
			detail:    "unsigned correlation disagrees with the signed payload",
		},
		{
			name: "the unsigned correlation on an effect names a different intent",
			mutate: func(t *testing.T, dir string) {
				editEvents(t, dir, func(events []map[string]interface{}) []map[string]interface{} {
					effect := firstOfType(events, "tool_call_effect")
					effect["correlation"] = map[string]interface{}{"linkedIntentId": "01ZZZZZZZZZZZZZZZZZZZZZZZZ"}
					return events
				})
			},
			failCheck: "intent-effect",
			detail:    "its signed payload names",
		},
		{
			name: "the outcome hash an effect recorded is rewritten",
			mutate: func(t *testing.T, dir string) {
				editEvents(t, dir, func(events []map[string]interface{}) []map[string]interface{} {
					flipPostHash(t, lastEffectFollowedByAnIntent(t, events))
					return events
				})
			},
			failCheck: "file-continuity",
			detail:    "with no unwitnessed_file_change gap",
		},
		{
			name: "the pre-state hash a later intent reports is rewritten",
			mutate: func(t *testing.T, dir string) {
				editEvents(t, dir, func(events []map[string]interface{}) []map[string]interface{} {
					flipPreHash(t, lastIntentWithFileArgs(t, events))
					return events
				})
			},
			failCheck: "file-continuity",
			detail:    "with no unwitnessed_file_change gap",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyIntentEffectBundle(t)
			tc.mutate(t, dir)
			res := VerifyBundle(dir)
			if res.Pass {
				t.Fatal("mutation must fail verification")
			}
			status, detail := statusOf(res, tc.failCheck)
			if status != StatusFail {
				t.Fatalf("check %s: status %q, want FAIL; checks: %+v", tc.failCheck, status, res.Checks)
			}
			if !strings.Contains(detail, tc.detail) {
				t.Errorf("check %s detail %q does not mention %q", tc.failCheck, detail, tc.detail)
			}
		})
	}
}

// A bundle produced without the PostToolUse hook has no effect records at
// all. That is a coverage decision, not a defect, so the checks report
// SKIPPED rather than inventing a pass or a failure.
func TestBundleWithoutEffectsSkipsTheChecks(t *testing.T) {
	dir := copyIntentEffectBundle(t)
	editEvents(t, dir, func(events []map[string]interface{}) []map[string]interface{} {
		out := make([]map[string]interface{}, 0, len(events))
		for _, evt := range events {
			if evt["type"] == "tool_call_effect" {
				continue
			}
			out = append(out, evt)
		}
		return out
	})
	res := VerifyBundle(dir)
	for _, name := range []string{"intent-effect", "file-continuity"} {
		if status, _ := statusOf(res, name); status != StatusSkipped {
			t.Errorf("check %s = %s, want SKIPPED", name, status)
		}
	}
}
