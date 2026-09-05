package cmd

// Helpers for the tests that mutate a bundle's timeline. Editing
// events.jsonl also breaks the files map and the events.jsonl artifact
// hash, which is expected: each test asserts on the named check it is
// about, not on the run passing everything else.

import (
	"encoding/json"
	"strings"
	"testing"
)

// events reads events.jsonl as a slice of generic maps, in file order.
func readEvents(t *testing.T, bundle string) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(string(readFile(t, bundle, "events.jsonl"))), "\n") {
		var evt map[string]interface{}
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("parse event line: %v", err)
		}
		out = append(out, evt)
	}
	return out
}

func writeEvents(t *testing.T, bundle string, events []map[string]interface{}) {
	t.Helper()
	var lines []string
	for _, evt := range events {
		data, err := json.Marshal(evt)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(data))
	}
	writeFile(t, bundle, "events.jsonl", []byte(strings.Join(lines, "\n")+"\n"))
}

// editEvents applies fn to the parsed timeline and writes it back.
func editEvents(t *testing.T, bundle string, fn func(events []map[string]interface{}) []map[string]interface{}) {
	t.Helper()
	writeEvents(t, bundle, fn(readEvents(t, bundle)))
}

func firstOfType(events []map[string]interface{}, eventType string) map[string]interface{} {
	for _, evt := range events {
		if evt["type"] == eventType {
			return evt
		}
	}
	return nil
}

// dropGap removes the gap event with the given reason.
func dropGap(events []map[string]interface{}, reason string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(events))
	for _, evt := range events {
		if evt["type"] == "gap" {
			payload, _ := evt["payload"].(map[string]interface{})
			if payload != nil && payload["reason"] == reason {
				continue
			}
		}
		out = append(out, evt)
	}
	return out
}

// lastEffectFollowedByAnIntent finds the effect whose recorded outcome a
// later intent's pre-state is compared against, so a flipped hash there
// breaks continuity at a position no gap covers.
func lastEffectFollowedByAnIntent(t *testing.T, events []map[string]interface{}) map[string]interface{} {
	t.Helper()
	var candidate map[string]interface{}
	seenPaths := map[string]map[string]interface{}{}
	for _, evt := range events {
		payload, _ := evt["payload"].(map[string]interface{})
		if payload == nil {
			continue
		}
		switch evt["type"] {
		case "tool_call_effect":
			for _, raw := range asSlice(payload["files"]) {
				file := raw.(map[string]interface{})
				if _, ok := file["postSha256"].(string); ok {
					seenPaths[file["path"].(string)] = evt
				}
			}
		case "shell_command_pre":
			for _, raw := range asSlice(payload["fileArgs"]) {
				arg := raw.(map[string]interface{})
				if effect, ok := seenPaths[arg["path"].(string)]; ok {
					candidate = effect
				}
			}
		}
	}
	if candidate == nil {
		t.Fatal("fixture has no effect whose outcome a later intent reads back")
	}
	return candidate
}

func lastIntentWithFileArgs(t *testing.T, events []map[string]interface{}) map[string]interface{} {
	t.Helper()
	var candidate map[string]interface{}
	for _, evt := range events {
		if evt["type"] != "shell_command_pre" {
			continue
		}
		payload, _ := evt["payload"].(map[string]interface{})
		if payload != nil && len(asSlice(payload["fileArgs"])) > 0 {
			candidate = evt
		}
	}
	if candidate == nil {
		t.Fatal("fixture has no intent that names a file")
	}
	return candidate
}

func flipPostHash(t *testing.T, effect map[string]interface{}) {
	t.Helper()
	for _, raw := range asSlice(effect["payload"].(map[string]interface{})["files"]) {
		file := raw.(map[string]interface{})
		if post, ok := file["postSha256"].(string); ok {
			file["postSha256"] = flipHexChar(post)
			return
		}
	}
	t.Fatal("effect records no post-state hash")
}

func flipPreHash(t *testing.T, intent map[string]interface{}) {
	t.Helper()
	for _, raw := range asSlice(intent["payload"].(map[string]interface{})["fileArgs"]) {
		arg := raw.(map[string]interface{})
		if pre, ok := arg["preSha256"].(string); ok {
			arg["preSha256"] = flipHexChar(pre)
			return
		}
	}
	t.Fatal("intent records no pre-state hash")
}

func asSlice(value interface{}) []interface{} {
	items, _ := value.([]interface{})
	return items
}
