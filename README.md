# DEPOSE

**Depose the agent. Produce the record.**

DEPOSE turns an AI coding agent session into a self-contained, hash-chained,
cryptographically signed evidence bundle — verifiable off-host by anyone with
a single Go binary and no other DEPOSE infrastructure.

It is designed for the moment *after* something has gone wrong: a destroyed
production database, a wiped infra account, a deleted directory. You point
DEPOSE at a Claude Code or Codex CLI session log and it produces a `.depo`
bundle that an auditor, regulator, or court can verify themselves.

---

## What it produces

A `.depo` bundle is a deterministically-ordered directory containing:

- `events.jsonl` — every captured event from the session, in canonical JSON
- `manifest.json` — bundle metadata, root hash of an IRONROOT hash chain, signatures, RFC 3161 timestamps
- `rules/destructive.yaml` — the destructive-operation ruleset used at reconstruction time
- `narrative.md` / `narrative.html` — template-driven prose with `[#evt-<ulid>]` citations
- `verify.txt` — human-readable verification summary

Tampering with any byte in any artifact causes verification to fail.

## What it is not

- Not an LLM-narrated incident summarizer in the signed path
- Not an agent runtime governance layer
- Not a rollback or restore tool
- Not a SaaS product or dashboard

---

## Install

```bash
git clone https://github.com/Aftermath-Technologies-Ltd/depose
cd depose
pnpm install
pnpm build

# Build the standalone verifier (Go 1.22+)
cd apps/verify && make build-local
```

Requirements: Node.js ≥ 20, pnpm 9.x, Go 1.22+ (for the verifier).

---

## Quick start

Produce a signed bundle from a Claude Code session JSONL:

```bash
./packages/cli/bin/depose package \
  --from-claude path/to/session.jsonl \
  --skip-timestamp
```

(`--skip-timestamp` skips the RFC 3161 network call; omit it for production.)

Verify the bundle from any host:

```bash
./apps/verify/build/depose-verify verify path/to/bundle.depo
```

A passing run looks like:

```
parse           OK
signature       OK
chain-replay    OK
artifacts       OK
timestamp       OK (or SKIPPED)
PASS  bundleId=01J... rootHash=99a96827806b4924...
```

See `depose --help` for the full command surface (`reconstruct`, `package`,
`install --claude`, `install --shell`, `explain`, `uninstall`).

---

## Active capture

For sessions you are running *now*, install the hooks that record events at
the moment they happen (rather than reconstructing from logs after the fact):

```bash
depose install --claude   # registers a Claude Code PreToolUse hook
depose install --shell    # installs shell shims for terraform, aws, gh, kubectl, psql, gcloud, railway, rm
```

The hook and shim write capture records under `~/.depose/captures/`. Subsequent
`depose package` runs merge captured records with the session JSONL so every
covered event has a verified pre-execution intent recorded.

See [docs/hook-installation.md](docs/hook-installation.md) and
[docs/shim-installation.md](docs/shim-installation.md).

---

## Architecture

Six layers, each does one thing. No LLM in the signed path.

```
CAPTURE → NORMALIZATION → RECONSTRUCTION → INTEGRITY → BUNDLE → NARRATIVE
```

- **Capture** — Claude Code PreToolUse hook (`packages/capture-claude`) and shell shims (`apps/capture-shim`) record events at execution time.
- **Normalization** — Claude Code JSONL, shell history (bash/zsh/fish), and git reflog are normalized into a common event schema (`packages/core`).
- **Reconstruction** — events are sorted, merged across sources, deduplicated, and gap-flagged; a causal timeline is built (`packages/core/reconstruct`).
- **Integrity** — IRONROOT hash chain, Ed25519 signing, RFC 3161 timestamping with FreeTSA primary / DigiCert fallback (`packages/chain`).
- **Bundle** — deterministic `.depo` directory layout (`packages/bundle`).
- **Narrative** — Handlebars template renderer with per-event citations (`packages/narrative`). Excluded from the root hash; derived from signed events.

Full design in [docs/architecture.md](docs/architecture.md). Bundle format spec
in [docs/bundle-format.md](docs/bundle-format.md). Threat model in
[docs/threat-model.md](docs/threat-model.md).

---

## Repository layout

```
packages/
  core/             event schema, normalization, reconstruction, ruleset matcher
  chain/            hash chain, Ed25519 signing, RFC 3161 timestamping
  bundle/           .depo format reader/writer
  narrative/        Handlebars-based deterministic narrative renderer
  capture-claude/   Claude Code PreToolUse hook
  cli/              `depose` command
apps/
  verify/           `depose-verify` static Go binary
  capture-shim/     shell shim Go binary
rules/              destructive operations ruleset (YAML)
examples/           synthetic reconstructions (datatalks, pocketos)
docs/               architecture, threat model, bundle format, install guides
```

---

## Examples

Two synthetic reconstructions are checked into the repo. Each ships a Claude
Code JSONL and a `produce.sh` that runs `depose package`:

- [examples/datatalks-reconstruction](examples/datatalks-reconstruction) — agent runs `rm -rf` on a training data directory.
- [examples/pocketos-reconstruction](examples/pocketos-reconstruction) — agent runs `terraform destroy -auto-approve`.

```bash
bash examples/datatalks-reconstruction/produce.sh
```

---

## Development

```bash
pnpm build       # tsc --build across all packages
pnpm typecheck   # tsc --build --noEmit
pnpm lint        # eslint
pnpm test        # vitest run (full suite)
```

CI runs lint, typecheck, tests, builds the Go verifier (cross-compiled for
darwin/linux × arm64/amd64), and verifies the example bundles end-to-end.

---

## License

Proprietary — all rights reserved.
