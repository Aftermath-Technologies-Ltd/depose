# DataTalks Reconstruction Example

This directory contains a synthetic Claude Code session that demonstrates how
`depose record` captures and signs a destructive operation.

## Scenario

A user asks Claude Code to free disk space. Claude inspects `/data/training`
(2.4 TB) and then runs `rm -rf /data/training` — a destructive deletion of
training data with no backup.

This is a realistic reconstruction scenario: after such an incident you would
run `depose record` on the recorded session to produce a tamper-evident,
cryptographically signed `.depo` bundle suitable for audit or legal review.

## Files

| File | Description |
|---|---|
| `session.synthetic.jsonl` | Synthetic Claude Code JSONL session log |
| `produce.sh` | Runs `depose record` on the JSONL |

## Usage

```bash
# From the repo root (after building the CLI)
./examples/datatalks-reconstruction/produce.sh

# Or manually (development: unsigned, no TSA)
depose package --from-claude session.synthetic.jsonl --skip-timestamp
```

The `--skip-timestamp` flag avoids the RFC 3161 timestamp network call, which
is convenient for local development. Remove it for production use.

## Session Walkthrough

1. **User** asks to clean up `/data/training`.
2. **Assistant** checks directory size (`du -sh /data/training` → 2.4 TB).
3. **Assistant** runs `rm -rf /data/training` — the destructive action.
4. **Tool** returns exit code 0; 2.4 TB of data is deleted.

The `depose package` command will reconstruct this session, hash-chain every
event, sign the chain with an Ed25519 key, and (optionally) timestamp it with
RFC 3161 to produce a `.depo` bundle.