#!/usr/bin/env bash
# scripts/install-from-pack-test.sh
#
# End-to-end install-from-pack test. Catches the kind of regressions
# that would slip past unit tests:
#   - workspace deps that fail to resolve once published
#   - missing files in the npm-pack tarball
#   - bin entries pointing at unbuilt artifacts
#   - depose-hook unable to load @depose/capture-claude after install
#
# Runs in CI on every push.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "=== Install-from-pack E2E test ==="
echo "Work dir: $WORK_DIR"

echo "--- 1. Pack the CLI ---"
cd "$REPO_ROOT/packages/cli"
pnpm pack --pack-destination "$WORK_DIR"
TARBALL="$WORK_DIR/depose-cli-0.1.0.tgz"
ls -lh "$TARBALL"

echo "--- 2. Install the tarball into an isolated prefix ---"
mkdir -p "$WORK_DIR/prefix"
npm install --prefix "$WORK_DIR/prefix" "$TARBALL"

DEPOSE_BIN="$WORK_DIR/prefix/node_modules/.bin/depose"
DEPOSE_HOOK_BIN="$WORK_DIR/prefix/node_modules/.bin/depose-hook"
if [[ ! -x "$DEPOSE_BIN" ]]; then
  echo "FAIL: depose bin not executable: $DEPOSE_BIN"
  exit 1
fi
if [[ ! -x "$DEPOSE_HOOK_BIN" ]]; then
  echo "FAIL: depose-hook bin not executable: $DEPOSE_HOOK_BIN"
  exit 1
fi

echo "--- 3. Run depose --help (smoke) ---"
"$DEPOSE_BIN" --help | head -5
echo ""

echo "--- 4. Run depose package against a synthetic JSONL ---"
SESSION="$REPO_ROOT/examples/datatalks-reconstruction/session.synthetic.jsonl"
BUNDLE_OUT="$WORK_DIR/bundle-out"
"$DEPOSE_BIN" package \
  --from-claude "$SESSION" \
  --output "$BUNDLE_OUT" \
  --skip-timestamp \
  --capture-dir "$WORK_DIR/captures" \
  --key-dir "$WORK_DIR/keys" \
  --session-id "pack-test"

BUNDLE_DIR="$BUNDLE_OUT/incident-unsigned-pack-test"
if [[ ! -d "$BUNDLE_DIR" ]]; then
  echo "FAIL: bundle not produced at $BUNDLE_DIR"
  exit 1
fi

echo "--- 5. Verify the bundle with depose-verify ---"
VERIFIER="$REPO_ROOT/apps/verify/build/depose-verify"
if [[ ! -x "$VERIFIER" ]]; then
  echo "depose-verify not built; building it now…"
  (cd "$REPO_ROOT/apps/verify" && make build-local)
fi
"$VERIFIER" verify "$BUNDLE_DIR" | tail -5

echo "--- 6. Smoke-test depose-hook can load capture-claude after install ---"
echo '{"tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"pack-test"}' \
  | "$DEPOSE_HOOK_BIN" pretooluse > "$WORK_DIR/hook-out.txt" 2>&1
if grep -q 'ERR_MODULE_NOT_FOUND\|Cannot find package' "$WORK_DIR/hook-out.txt"; then
  echo "FAIL: depose-hook could not load @depose/capture-claude after install"
  cat "$WORK_DIR/hook-out.txt"
  exit 1
fi

echo ""
echo "PASS: install-from-pack E2E"
