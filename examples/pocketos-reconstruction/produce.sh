#!/usr/bin/env bash
# produce.sh — Run depose package on the synthetic PocketOS session JSONL.
#
# By default this runs in `signed` mode and hits FreeTSA over the
# network. Set DEPOSE_DEV_UNSIGNED=1 to skip the TSA round-trip and
# emit a dev-unsigned bundle instead (offline / fast iteration).
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

"$DEPOSE" package \
  --from-claude "$SESSION_JSONL" \
  --output "$OUTPUT_DIR" \
  ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}

echo ""
echo "Done. Verify with: depose-verify verify $OUTPUT_DIR/incident-*"
