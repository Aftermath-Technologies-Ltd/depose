// Package chain — tests for IRONROOT hash chain replay.
package chain

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReplayDetectsPayloadTamper is the critical regression test for the
// payload-tamper attack: rewriting payload content while leaving the
// stored payloadHash and chainHash intact must FAIL verification. Before
// this fix, the verifier replayed the chain only from the recorded
// payloadHash and never re-derived it from payload bytes, so this exact
// mutation passed.
func TestReplayDetectsPayloadTamper(t *testing.T) {
	dir := t.TempDir()

	// Hand-crafted event line. The stored payloadHash matches the
	// canonical form of payload {"command":"rm -rf /data/training"}.
	// We then rewrite the payload string but leave payloadHash/chainHash
	// intact. The verifier must detect the mismatch.
	//
	// Canonical JSON of {"command":"rm -rf /data/training"} =
	//   {"command":"rm -rf /data/training"}
	// SHA-256 hex of that = computed below at test runtime so this test
	// stays robust to any escape-set tweaks.
	originalPayload := `{"command":"rm -rf /data/training"}`
	tamperedPayload := `{"command":"rm -rf /tmp/nothing"}`

	// Compute the legitimate payloadHash so the original line would
	// pass payload-hash verification.
	legitimateHash, err := recomputePayloadHash([]byte(originalPayload))
	if err != nil {
		t.Fatalf("recompute legitimate payloadHash: %v", err)
	}

	// Build a tampered events.jsonl: payload bytes rewritten, but the
	// stored payloadHash is the one computed from the *original* payload.
	tamperedLine := `{"id":"01J000000000000000000000A0","wallTs":"2026-04-12T09:15:15.000Z","monoNs":0,"sessionId":"S","agentId":"claude-code","parentEventId":null,"type":"tool_call_intent","payload":` + tamperedPayload + `,"payloadHash":"` + legitimateHash + `","chainHash":"deadbeef"}`

	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(tamperedLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := ReplayChain(dir)
	if err != nil {
		t.Fatalf("ReplayChain error: %v", err)
	}

	if len(res.PayloadMismatches) == 0 {
		t.Fatalf("expected PayloadMismatches to be non-empty for tampered payload, got 0")
	}
	mm := res.PayloadMismatches[0]
	if mm.Expected != legitimateHash {
		t.Errorf("PayloadMismatch.Expected = %s, want %s", mm.Expected, legitimateHash)
	}
	if mm.Computed == legitimateHash {
		t.Errorf("PayloadMismatch.Computed unexpectedly equal to legitimate hash %s", legitimateHash)
	}
	if !strings.Contains(mm.EventID, "01J") {
		t.Errorf("PayloadMismatch.EventID looks wrong: %s", mm.EventID)
	}
}

// TestReplayAcceptsLegitimatePayload confirms the happy path: when payload
// canonicalizes to the recorded payloadHash, no PayloadMismatch is reported.
func TestReplayAcceptsLegitimatePayload(t *testing.T) {
	dir := t.TempDir()

	payload := `{"command":"echo ok"}`
	h, err := recomputePayloadHash([]byte(payload))
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	// chainHash is left empty so the chain-mismatch path is not exercised here.
	line := `{"id":"01J000000000000000000000B0","wallTs":"2026-04-12T09:15:15.000Z","monoNs":0,"sessionId":"S","agentId":"claude-code","parentEventId":null,"type":"tool_call_intent","payload":` + payload + `,"payloadHash":"` + h + `"}`

	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := ReplayChain(dir)
	if err != nil {
		t.Fatalf("ReplayChain: %v", err)
	}
	if len(res.PayloadMismatches) != 0 {
		t.Fatalf("expected no PayloadMismatches, got %d: %+v", len(res.PayloadMismatches), res.PayloadMismatches)
	}
}

// TestRecomputePayloadHashIsDeterministic confirms the JCS path produces
// the same hash regardless of input key order — that's what makes the
// hash a function of the value rather than the input encoding.
func TestRecomputePayloadHashIsDeterministic(t *testing.T) {
	a := `{"a":1,"b":"x","z":[1,2,3]}`
	b := `{"z":[1,2,3],"a":1,"b":"x"}`
	ha, err := recomputePayloadHash([]byte(a))
	if err != nil {
		t.Fatal(err)
	}
	hb, err := recomputePayloadHash([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("expected order-independent payloadHash, got %s vs %s", ha, hb)
	}
	// Sanity: hex output, 64 chars.
	if _, err := hex.DecodeString(ha); err != nil || len(ha) != 64 {
		t.Fatalf("payloadHash %q is not 64-char hex", ha)
	}
}
