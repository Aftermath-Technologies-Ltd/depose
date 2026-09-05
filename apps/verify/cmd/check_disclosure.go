// Package cmd, disclosure-mode checks: every disclosed event is a
// byte-faithful member of the sealed set at its stated position, every
// withheld position is accounted for against the same root, disclosed
// fields open to their commitments, and any carried original file
// matches the signed files map.
package cmd

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/canonical"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/chain"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/merkle"
)

// disclosedEvents holds the parsed disclosed lines for later checks.
type disclosedEvents struct {
	ids      []string
	payloads []json.RawMessage
}

// readDisclosedLines parses the disclosure's events.jsonl in order.
func readDisclosedLines(dir string) ([]chain.Event, []string, error) {
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var events []chain.Event
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		var evt chain.Event
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", len(events)+1, err)
		}
		events = append(events, evt)
		lines = append(lines, line)
	}
	return events, lines, scanner.Err()
}

// checkDisclosureInclusion is the membership proof. For each disclosed
// event, in order: the payload re-hashes to its payloadHash, the chain
// hash recomputes from the previous position's chain hash (a withheld
// predecessor supplies it), and the leaf's audit path reaches the root.
// For each withheld position the stated chain hash's leaf reaches the
// root through its own path.
func checkDisclosureInclusion(ctx *checkContext) []CheckResult {
	d := ctx.disclosure
	fail := func(detail string) []CheckResult {
		return one(CheckResult{Name: "disclosure-inclusion", Status: StatusFail, Detail: detail})
	}
	root, err := hex.DecodeString(d.MerkleRoot)
	if err != nil {
		return fail("merkleRoot is not hex")
	}
	events, _, err := readDisclosedLines(ctx.bundlePath)
	if err != nil {
		return fail(fmt.Sprintf("cannot read disclosed events.jsonl: %v", err))
	}
	if len(events) != len(d.Disclosed) {
		return fail(fmt.Sprintf("events.jsonl has %d line(s) but disclosure.json lists %d disclosed event(s)", len(events), len(d.Disclosed)))
	}

	// Chain hashes by position: withheld ones are stated, disclosed ones
	// are recomputed and must equal what the line carries.
	chainAt := make(map[int][]byte, d.LeafCount)
	for _, w := range d.Withheld {
		h, _ := hex.DecodeString(w.ChainHash)
		chainAt[w.Index] = h
		path, err := decodePath(w.AuditPath)
		if err != nil {
			return fail(fmt.Sprintf("withheld index %d: %v", w.Index, err))
		}
		if !merkle.VerifyInclusion(merkle.LeafHash(h), w.Index, d.LeafCount, path, root) {
			return fail(fmt.Sprintf("withheld index %d: audit path does not reach the signed root", w.Index))
		}
	}

	ids := make([]string, 0, len(events))
	payloads := make([]json.RawMessage, 0, len(events))
	for i, entry := range d.Disclosed {
		evt := events[i]
		if evt.ID != entry.EventID {
			return fail(fmt.Sprintf("events.jsonl line %d is %s but disclosure.json lists %s at index %d", i+1, evt.ID, entry.EventID, entry.Index))
		}
		if i > 0 && d.Disclosed[i-1].Index >= entry.Index {
			return fail(fmt.Sprintf("disclosed indices are not ascending at line %d", i+1))
		}
		computedPayload, err := chain.RecomputePayloadHash(evt.Payload)
		if err != nil {
			return fail(fmt.Sprintf("%s: %v", evt.ID, err))
		}
		if computedPayload != evt.PayloadHash {
			return fail(fmt.Sprintf("%s at index %d: payload does not canonicalize to its recorded payloadHash (disclosed event modified)", evt.ID, entry.Index))
		}
		prev := make([]byte, 32)
		if entry.Index > 0 {
			p, ok := chainAt[entry.Index-1]
			if !ok {
				return fail(fmt.Sprintf("%s at index %d: no chain hash for the preceding position %d", evt.ID, entry.Index, entry.Index-1))
			}
			prev = p
		}
		computedChain, err := chainHashFor(evt, prev)
		if err != nil {
			return fail(fmt.Sprintf("%s: %v", evt.ID, err))
		}
		if hex.EncodeToString(computedChain) != evt.ChainHash {
			return fail(fmt.Sprintf("%s at index %d: chainHash does not recompute from its metadata and predecessor (disclosed event modified)", evt.ID, entry.Index))
		}
		chainAt[entry.Index] = computedChain
		path, err := decodePath(entry.AuditPath)
		if err != nil {
			return fail(fmt.Sprintf("%s at index %d: %v", evt.ID, entry.Index, err))
		}
		if !merkle.VerifyInclusion(merkle.LeafHash(computedChain), entry.Index, d.LeafCount, path, root) {
			return fail(fmt.Sprintf("%s at index %d: audit path does not reach the signed root (forged or misplaced proof)", evt.ID, entry.Index))
		}
		ids = append(ids, evt.ID)
		payloads = append(payloads, evt.Payload)
	}
	ctx.disclosed = &disclosedEvents{ids: ids, payloads: payloads}
	return one(CheckResult{
		Name:   "disclosure-inclusion",
		Status: StatusPass,
		Detail: fmt.Sprintf("%d disclosed event(s) are byte-faithful members of the sealed set; all %d positions reach root %s...", len(events), d.LeafCount, truncHex(d.MerkleRoot, 16)),
	})
}

// chainHashFor recomputes SHA-256(prev || payloadHash || jcs(metadata)).
func chainHashFor(evt chain.Event, prev []byte) ([]byte, error) {
	monoValue, monoIsString, err := chain.MonoNsValue(evt.MonoNs)
	if err != nil {
		return nil, err
	}
	var monoNs interface{} = json.Number(fmt.Sprint(monoValue))
	if monoIsString {
		monoNs = fmt.Sprint(monoValue)
	}
	var parent interface{}
	if evt.ParentEventID != nil {
		parent = *evt.ParentEventID
	}
	meta, err := canonical.Marshal(map[string]interface{}{
		"id": evt.ID, "wallTs": evt.WallTs, "monoNs": monoNs, "sessionId": evt.SessionID,
		"agentId": evt.AgentID, "parentEventId": parent, "type": evt.Type, "payloadHash": evt.PayloadHash,
	})
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(prev)
	h.Write([]byte(evt.PayloadHash))
	h.Write(meta)
	return h.Sum(nil), nil
}

func decodePath(hexes []string) ([][]byte, error) {
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != merkle.HashSize {
			return nil, fmt.Errorf("audit path element %d is not a 32-byte hex hash", i)
		}
		out[i] = b
	}
	return out, nil
}

// checkDisclosureCommitments opens the disclosed fields. Placeholders
// without an opening are withheld by design; an opening for an event
// that is not disclosed, or one that does not match, fails.
func checkDisclosureCommitments(ctx *checkContext) []CheckResult {
	if ctx.disclosed == nil {
		return one(CheckResult{Name: "disclosure-commitments", Status: StatusSkipped, Detail: "inclusion check did not complete"})
	}
	openings, _, err := loadCommitments(ctx.bundlePath)
	if err != nil {
		return one(CheckResult{Name: "disclosure-commitments", Status: StatusFail, Detail: err.Error()})
	}
	report := openAll(ctx.disclosed.ids, ctx.disclosed.payloads, openings, false)
	if len(report.problems) > 0 {
		return one(CheckResult{Name: "disclosure-commitments", Status: StatusFail, Detail: fmt.Sprintf("%d problem(s): %s", len(report.problems), joinProblems(report.problems))})
	}
	withheld := report.placeholders - report.opened
	return one(CheckResult{
		Name:   "disclosure-commitments",
		Status: StatusPass,
		Detail: fmt.Sprintf("%d field(s) disclosed and opened; %d field(s) withheld as commitments", report.opened, withheld),
	})
}

// disclosureOwnFiles are written by the disclosure itself rather than
// copied from the sealed bundle.
var disclosureOwnFiles = map[string]bool{
	"manifest.json":    true,
	"disclosure.json":  true,
	"events.jsonl":     true,
	"commitments.json": true,
}

// checkDisclosureFiles verifies every other file in the tree against the
// signed files map, so a disclosure can carry the ruleset or the
// narrative but cannot carry anything the seal did not pin.
func checkDisclosureFiles(ctx *checkContext) []CheckResult {
	m := ctx.manifest
	onDisk, symlinks, err := walkBundleFiles(ctx.bundlePath)
	if err != nil {
		return one(CheckResult{Name: "disclosure-files", Status: StatusFail, Detail: fmt.Sprintf("cannot walk tree: %v", err)})
	}
	if len(symlinks) > 0 {
		return one(CheckResult{Name: "disclosure-files", Status: StatusFail, Detail: fmt.Sprintf("symlink(s) forbidden: %s", strings.Join(symlinks, ", "))})
	}
	var problems []string
	carried := 0
	for _, rel := range onDisk {
		if disclosureOwnFiles[rel] || filesMapExcluded(rel) {
			continue
		}
		entry, ok := m.Files[rel]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s is not pinned by the sealed files map", rel))
			continue
		}
		data, err := os.ReadFile(filepath.Join(ctx.bundlePath, filepath.FromSlash(rel)))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		sum := sha256.Sum256(data)
		if int64(len(data)) != entry.Bytes || !strings.EqualFold(hex.EncodeToString(sum[:]), entry.Sha256) {
			problems = append(problems, fmt.Sprintf("%s does not match the sealed files map", rel))
			continue
		}
		carried++
	}
	if len(problems) > 0 {
		return one(CheckResult{Name: "disclosure-files", Status: StatusFail, Detail: strings.Join(problems, "; ")})
	}
	return one(CheckResult{Name: "disclosure-files", Status: StatusPass, Detail: fmt.Sprintf("%d carried original file(s) match the sealed files map", carried)})
}
