// Package cmd, the disclosure.json document and its structural check.
//
// A disclosure bundle carries the original manifest, signature, and
// timestamp unchanged, a subset of the sealed events byte for byte, an
// RFC 6962 audit path for every position, and the commitment openings
// for the fields being disclosed. docs/bundle-format.md#disclosure-bundles.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// disclosureDoc is disclosure.json.
type disclosureDoc struct {
	SchemaVersion int    `json:"schemaVersion"`
	BundleID      string `json:"bundleId"`
	MerkleRoot    string `json:"merkleRoot"`
	LeafCount     int    `json:"leafCount"`
	ProducedAt    string `json:"producedAt"`
	Disclosed     []struct {
		Index     int      `json:"index"`
		EventID   string   `json:"eventId"`
		AuditPath []string `json:"auditPath"`
	} `json:"disclosed"`
	Withheld []struct {
		Index     int      `json:"index"`
		ChainHash string   `json:"chainHash"`
		AuditPath []string `json:"auditPath"`
	} `json:"withheld"`
	Fields struct {
		Disclosed json.RawMessage `json:"disclosed"`
		Withheld  []string        `json:"withheld"`
	} `json:"fields"`
	IncludedFiles []string `json:"includedFiles"`
	Consistency   *struct {
		EarlierLeafCount int      `json:"earlierLeafCount"`
		EarlierRoot      string   `json:"earlierRoot"`
		Proof            []string `json:"proof"`
	} `json:"consistency"`
}

var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// loadDisclosure reads disclosure.json from dir.
func loadDisclosure(dir string) (*disclosureDoc, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "disclosure.json"))
	if err != nil {
		return nil, fmt.Errorf("cannot read disclosure.json: %w", err)
	}
	var doc disclosureDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("disclosure.json is malformed: %w", err)
	}
	return &doc, nil
}

// IsDisclosure reports whether dir carries a disclosure.json.
func IsDisclosure(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "disclosure.json"))
	return err == nil
}

// checkDisclosureParse ties disclosure.json to the signed manifest: same
// bundle, same Merkle root (so a disclosure cannot claim a root the
// signature does not cover), same leaf count, and a partition of the
// positions into disclosed and withheld with nothing missing or doubled.
func checkDisclosureParse(ctx *checkContext) []CheckResult {
	d := ctx.disclosure
	m := ctx.manifest
	fail := func(detail string) []CheckResult {
		return one(CheckResult{Name: "disclosure-parse", Status: StatusFail, Detail: detail})
	}
	if d == nil {
		return fail("disclosure.json could not be loaded")
	}
	if d.SchemaVersion != 1 {
		return fail(fmt.Sprintf("disclosure.json schemaVersion %d is not supported", d.SchemaVersion))
	}
	if d.BundleID != m.BundleID {
		return fail(fmt.Sprintf("disclosure names bundle %q but the signed manifest is %q", d.BundleID, m.BundleID))
	}
	if m.MerkleRoot == "" {
		return fail("the signed manifest has no merkleRoot; nothing for the disclosure to prove against")
	}
	if !hexHash.MatchString(d.MerkleRoot) || d.MerkleRoot != m.MerkleRoot {
		return fail(fmt.Sprintf("disclosure claims root %s..., but the signed manifest covers %s...", truncHex(d.MerkleRoot, 16), truncHex(m.MerkleRoot, 16)))
	}
	if d.LeafCount != m.Counts.Events {
		return fail(fmt.Sprintf("disclosure says %d leaves, the signed manifest counts %d events", d.LeafCount, m.Counts.Events))
	}
	seen := make(map[int]string, d.LeafCount)
	for _, e := range d.Disclosed {
		if prev, dup := seen[e.Index]; dup {
			return fail(fmt.Sprintf("index %d appears twice (%s and disclosed)", e.Index, prev))
		}
		seen[e.Index] = "disclosed"
	}
	for _, w := range d.Withheld {
		if prev, dup := seen[w.Index]; dup {
			return fail(fmt.Sprintf("index %d appears twice (%s and withheld)", w.Index, prev))
		}
		if !hexHash.MatchString(w.ChainHash) {
			return fail(fmt.Sprintf("withheld index %d has a malformed chainHash", w.Index))
		}
		seen[w.Index] = "withheld"
	}
	if len(seen) != d.LeafCount {
		missing := make([]int, 0)
		for i := 0; i < d.LeafCount; i++ {
			if _, ok := seen[i]; !ok {
				missing = append(missing, i)
			}
		}
		sort.Ints(missing)
		return fail(fmt.Sprintf("positions are not fully accounted for: %d of %d present, missing %v", len(seen), d.LeafCount, missing))
	}
	for i := range seen {
		if i < 0 || i >= d.LeafCount {
			return fail(fmt.Sprintf("index %d is outside 0..%d", i, d.LeafCount-1))
		}
	}
	return one(CheckResult{
		Name:   "disclosure-parse",
		Status: StatusPass,
		Detail: fmt.Sprintf("disclosure of bundle %s: %d of %d events disclosed, %d withheld, root %s... matches the signed manifest", d.BundleID, len(d.Disclosed), d.LeafCount, len(d.Withheld), truncHex(d.MerkleRoot, 16)),
	})
}
