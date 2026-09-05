#!/usr/bin/env bash
# produce.sh, rebuild the Kiro Cost Explorer example from scratch.
#
# Unlike the other two examples, this one goes through the capture hooks
# rather than reconstructing from a transcript: capture.mjs drives the
# real PreToolUse and PostToolUse handlers, and `depose record` merges
# what they wrote with the session log.
#
# Set DEPOSE_DEV_UNSIGNED=1 for an unsigned bundle (no network, no key).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SESSION_JSONL="$SCRIPT_DIR/session.synthetic.jsonl"
CAPTURE_DIR="$SCRIPT_DIR/captures"
OUTPUT_DIR="$SCRIPT_DIR/depose-output"
DEPOSE="$REPO_ROOT/packages/cli/bin/depose"

echo "1/3  Capturing the session through the Claude Code hooks..."
node "$SCRIPT_DIR/capture.mjs"

rm -rf "$OUTPUT_DIR"
if [[ "${DEPOSE_DEV_UNSIGNED:-}" == "1" ]]; then
  echo ""
  echo "2/3  Sealing (DEV-UNSIGNED: no signature, no timestamp)..."
  "$DEPOSE" package \
    --from-claude "$SESSION_JSONL" \
    --capture-dir "$CAPTURE_DIR" \
    --output "$OUTPUT_DIR" \
    --skip-timestamp
else
  echo ""
  echo "2/3  Sealing (signed; needs the network for the timestamp authority)..."
  "$DEPOSE" record \
    --from-claude "$SESSION_JSONL" \
    --capture-dir "$CAPTURE_DIR" \
    --output "$OUTPUT_DIR"
fi

BUNDLE="$(find "$OUTPUT_DIR" -maxdepth 1 -type d -name 'incident-*' | head -1)"

echo ""
echo "3/3  Producing the disclosure a regulator would receive..."
# Everything the incident report cites, with the command lines opened and
# the prompts and tool outputs left as commitments.
"$DEPOSE" disclose "$BUNDLE" \
  --events all \
  --fields /argv,/toolInput \
  --out "$OUTPUT_DIR/regulator-disclosure"

echo ""
echo "Bundle:     $BUNDLE"
echo "Disclosure: $OUTPUT_DIR/regulator-disclosure"
echo ""
echo "Verify both:"
echo "  depose-verify verify $BUNDLE"
echo "  depose-verify verify $OUTPUT_DIR/regulator-disclosure"
