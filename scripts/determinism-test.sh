#!/usr/bin/env bash
# scripts/determinism-test.sh
#
# F-27: Round-trip determinism CI test.
#
# Produces a bundle twice with a fixed ULID seed and pinned producedAt,
# then recursively diffs the two output directories. The diff must be
# empty — any nondeterminism (clock leaks, map iteration order, etc.)
# will be caught here.
#
# Prerequisites:
#   - pnpm build has been run (depose CLI binary must exist)
#   - No network required (uses --skip-timestamp for dev-unsigned mode)
#
# Exits 0 if bundles are byte-identical, 1 otherwise.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPOSE="$REPO_ROOT/packages/cli/bin/depose"
SESSION_JSONL="$REPO_ROOT/examples/datatalks-reconstruction/session.synthetic.jsonl"
FIXED_SEED=1716043800000
PRODUCED_AT="2025-05-18T16:00:00.000Z"

# Use a consistent key directory so the same Ed25519 key is used in both runs.
KEY_DIR=$(mktemp -d)
trap 'rm -rf "$KEY_DIR" "$REPO_ROOT/tmp-determinism-run1" "$REPO_ROOT/tmp-determinism-run2"' EXIT

OUT1="$REPO_ROOT/tmp-determinism-run1"
OUT2="$REPO_ROOT/tmp-determinism-run2"

echo "=== F-27: Round-trip determinism test ==="

echo "--- Run 1 ---"
"$DEPOSE" package \
  --from-claude "$SESSION_JSONL" \
  --output "$OUT1" \
  --skip-timestamp \
  --fixed-seed "$FIXED_SEED" \
  --produced-at "$PRODUCED_AT" \
  --key-dir "$KEY_DIR" \
  --session-id "determinism-test"

echo ""
echo "--- Run 2 ---"
"$DEPOSE" package \
  --from-claude "$SESSION_JSONL" \
  --output "$OUT2" \
  --skip-timestamp \
  --fixed-seed "$FIXED_SEED" \
  --produced-at "$PRODUCED_AT" \
  --key-dir "$KEY_DIR" \
  --session-id "determinism-test"

echo ""
echo "--- Diffing outputs ---"

DIFF_OUTPUT=$(diff -r "$OUT1" "$OUT2" 2>&1 || true)

if [[ -z "$DIFF_OUTPUT" ]]; then
  echo "PASS: Both bundles are byte-identical."
  echo ""
  echo "Output dir: $OUT1"
  exit 0
else
  echo "FAIL: Bundles differ:"
  echo "$DIFF_OUTPUT"
  echo ""
  echo "Round-trip determinism is broken. Two runs with the same seed and"
  echo "input must produce identical output."
  exit 1
fi