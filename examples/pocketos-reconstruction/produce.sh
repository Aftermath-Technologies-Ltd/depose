#!/usr/bin/env bash
# produce.sh — Run depose record on the synthetic PocketOS session JSONL.
#
# By default this runs in `signed` mode (depose record always signs).
# Set DEPOSE_DEV_UNSIGNED=1 to use depose package --skip-timestamp for
# a dev-unsigned bundle instead (offline / fast iteration).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SESSION_JSONL="$SCRIPT_DIR/session.synthetic.jsonl"
OUTPUT_DIR="$SCRIPT_DIR/depose-output"
DEPOSE="$REPO_ROOT/packages/cli/bin/depose"

EXTRA_ARGS=()
if [[ "${DEPOSE_DEV_UNSIGNED:-}" == "1" ]]; then
  EXTRA_ARGS+=(--skip-timestamp)
  echo "Depose: producing DEV-UNSIGNED bundle (DEPOSE_DEV_UNSIGNED=1)..."
else
  echo "Depose: producing SIGNED bundle (network required for FreeTSA)..."
fi
echo "  Input:  $SESSION_JSONL"
echo "  Output: $OUTPUT_DIR"
echo ""

if [[ "${DEPOSE_DEV_UNSIGNED:-}" == "1" ]]; then
  "$DEPOSE" package \
    --from-claude "$SESSION_JSONL" \
    --output "$OUTPUT_DIR" \
    --skip-timestamp
else
  "$DEPOSE" record \
    --from-claude "$SESSION_JSONL" \
    --output "$OUTPUT_DIR"
fi

echo ""
echo "Done. Verify with: depose-verify verify $OUTPUT_DIR/incident-*"
