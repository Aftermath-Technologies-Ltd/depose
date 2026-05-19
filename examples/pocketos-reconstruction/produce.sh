#!/usr/bin/env bash
# produce.sh — Run depose package on the synthetic PocketOS session JSONL
#
# Produces a signed .depo bundle from the simulated Claude Code session
# where the agent ran `terraform destroy -auto-approve`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SESSION_JSONL="$SCRIPT_DIR/session.synthetic.jsonl"
OUTPUT_DIR="$SCRIPT_DIR/depose-output"
DEPOSE="$REPO_ROOT/packages/cli/bin/depose"

echo "Depose: producing signed bundle from PocketOS synthetic session..."
echo "  Input:  $SESSION_JSONL"
echo "  Output: $OUTPUT_DIR"
echo ""

"$DEPOSE" package \
  --from-claude "$SESSION_JSONL" \
  --output "$OUTPUT_DIR" \
  --skip-timestamp

echo ""
echo "Done. Verify with: depose-verify verify $OUTPUT_DIR/incident-*"