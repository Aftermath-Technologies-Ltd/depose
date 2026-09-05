// Package cmd, opening salted field commitments.
//
// A committed field is { "$commitment": sha256( jcs([salt, path, value]) ) }
// in the sealed payload; commitments.json carries the (eventId, path,
// salt, value) openings. Mirrors packages/core/src/events/commitments.ts.
package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/canonical"
)

const commitmentKey = "$commitment"

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// commitmentOpening is one entry of commitments.json.
type commitmentOpening struct {
	EventID string          `json:"eventId"`
	Path    string          `json:"path"`
	Salt    string          `json:"salt"`
	Value   json.RawMessage `json:"value"`
}

// loadCommitments reads commitments.json. present is false when the file
// does not exist, which is only acceptable if no event carries a
// placeholder.
func loadCommitments(bundlePath string) (openings []commitmentOpening, present bool, err error) {
	raw, err := os.ReadFile(filepath.Join(bundlePath, "commitments.json"))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, fmt.Errorf("cannot read commitments.json: %v", err)
	}
	var file struct {
		SchemaVersion int                 `json:"schemaVersion"`
		Algorithm     string              `json:"algorithm"`
		Openings      []commitmentOpening `json:"openings"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, true, fmt.Errorf("commitments.json is malformed: %v", err)
	}
	if file.SchemaVersion != 1 {
		return nil, true, fmt.Errorf("commitments.json schemaVersion %d is not supported", file.SchemaVersion)
	}
	if file.Algorithm != "sha256(jcs([salt, path, value]))" {
		return nil, true, fmt.Errorf("commitments.json algorithm %q is not supported", file.Algorithm)
	}
	return file.Openings, true, nil
}

// computeCommitment mirrors the producer: SHA-256 over the JCS form of
// the array [salt, path, value].
func computeCommitment(salt, path string, value json.RawMessage) (string, error) {
	var decoded interface{}
	dec := json.NewDecoder(bytes.NewReader(value))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return "", fmt.Errorf("opening value is not JSON: %w", err)
	}
	canon, err := canonical.Marshal([]interface{}{salt, path, decoded})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// placeholderAt returns the commitment hash at a top-level payload field,
// or "" when the field is not a placeholder.
func placeholderAt(payload json.RawMessage, field string) string {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(payload, &top); err != nil {
		return ""
	}
	raw, ok := top[field]
	if !ok {
		return ""
	}
	var obj map[string]string
	if err := json.Unmarshal(raw, &obj); err != nil || len(obj) != 1 {
		return ""
	}
	h, ok := obj[commitmentKey]
	if !ok || !hex64.MatchString(h) {
		return ""
	}
	return h
}

// placeholderFields lists the top-level payload fields that hold a
// commitment placeholder.
func placeholderFields(payload json.RawMessage) []string {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(payload, &top); err != nil {
		return nil
	}
	var fields []string
	for field := range top {
		if placeholderAt(payload, field) != "" {
			fields = append(fields, field)
		}
	}
	sort.Strings(fields)
	return fields
}

type openReport struct {
	placeholders int
	opened       int
	problems     []string
}

// openAll checks every opening against the sealed payloads. When
// requireAll is true (a full bundle, or no commitments.json at all),
// every placeholder must have a matching opening; a disclosure may leave
// placeholders unopened by design.
func openAll(eventIDs []string, payloads []json.RawMessage, openings []commitmentOpening, requireAll bool) openReport {
	byID := make(map[string]json.RawMessage, len(eventIDs))
	for i, id := range eventIDs {
		byID[id] = payloads[i]
	}
	var report openReport
	opened := make(map[string]bool)
	for _, o := range openings {
		key := o.EventID + o.Path
		payload, ok := byID[o.EventID]
		if !ok {
			report.problems = append(report.problems, fmt.Sprintf("opening for %s%s names an event not in events.jsonl", o.EventID, o.Path))
			continue
		}
		if !strings.HasPrefix(o.Path, "/") || strings.Count(o.Path, "/") != 1 {
			report.problems = append(report.problems, fmt.Sprintf("opening for %s has path %q; only top-level fields are committable", o.EventID, o.Path))
			continue
		}
		field := o.Path[1:]
		sealed := placeholderAt(payload, field)
		if sealed == "" {
			report.problems = append(report.problems, fmt.Sprintf("%s%s: sealed payload holds no commitment at that path", o.EventID, o.Path))
			continue
		}
		want, err := computeCommitment(o.Salt, o.Path, o.Value)
		if err != nil {
			report.problems = append(report.problems, fmt.Sprintf("%s%s: %v", o.EventID, o.Path, err))
			continue
		}
		if want != sealed {
			report.problems = append(report.problems, fmt.Sprintf("%s%s: opening does not match the sealed commitment (wrong salt or value)", o.EventID, o.Path))
			continue
		}
		opened[key] = true
		report.opened++
	}
	for i, id := range eventIDs {
		for _, field := range placeholderFields(payloads[i]) {
			report.placeholders++
			if requireAll && !opened[id+"/"+field] {
				report.problems = append(report.problems, fmt.Sprintf("%s/%s is committed but commitments.json has no opening for it", id, field))
			}
		}
	}
	sort.Strings(report.problems)
	return report
}

func joinProblems(problems []string) string {
	if len(problems) > 8 {
		return strings.Join(problems[:8], "; ") + fmt.Sprintf("; and %d more", len(problems)-8)
	}
	return strings.Join(problems, "; ")
}
