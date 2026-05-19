#!/usr/bin/env bash
# produce.sh — Run depose package on the synthetic PocketOS session JSONL
#
# Produces a signed .depo bundle from the simulated Claude Code session
# where the agent ran `terraform destroy -auto-approve`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SESSION_JSONL="$SCRIPT_DIR/session.synthetic.jsonl"
OUTPUT_DIR="$SCRIPT_DIR/depose-output"

echo "Depose: producing signed bundle from PocketOS synthetic session..."
echo "  Input:  $SESSION_JSONL"
echo "  Output: $OUTPUT_DIR"
echo ""

npx depose package \
  --from-claude "$SESSION_JSONL" \
  --output "$OUTPUT_DIR" \
  --skip-timestamp

echo ""
echo "Done. Verify with: depose-verify verify $OUTPUT_DIR/incident-*"