# DEPOSE — Depose the agent. Produce the record.

A self-contained, hash-chained, signed evidence bundle from local Claude Code / Codex CLI sessions, verifiable off-host by a third party with a separate verifier binary.

## What DEPOSE is

- **`depose`** — capture, reconstruct, package. Produces `.depo` bundles.
- **`depose-verify`** — verifier. Statically linked. Validates a `.depo` bundle on any host with no other DEPOSE infrastructure.

The bundle is the product. The CLIs are tools that produce and consume the bundle.

## What DEPOSE is NOT

- Not an LLM-narrated incident summarizer in the production path
- Not an agent runtime governance layer
- Not a rollback / restore tool
- Not a SaaS / dashboard

## Quick Start

```bash
# Install dependencies
pnpm install

# Build
pnpm build

# Reconstruct a session from Claude Code JSONL (unsigned, Phase 1)
pnpm exec depose reconstruct --from-claude session.jsonl

# Produce a fully signed .depo bundle (Phase 2)
pnpm exec depose package --from-claude session.jsonl

# Verify a .depo bundle (requires depose-verify binary)
cd apps/verify && make all
./build/depose-verify verify path/to/bundle.depo

# See help
pnpm exec depose --help
```

## Architecture

Six layers. Each does one thing. None LLM-narrated.

```
CAPTURE → NORMALIZATION → RECONSTRUCTION → INTEGRITY → BUNDLE → NARRATIVE
```

## Repository Layout

```
packages/
  core/       — event schema, normalization, reconstruction
  chain/      — hash chain, signing, RFC 3161 (Phase 2)
  bundle/     — .depo format read/write
  capture-claude/ — Claude Code PreToolUse hook (Phase 3)
  cli/        — `depose` command
  narrative/  — template-based renderer (Phase 4)
apps/
  verify/     — `depose-verify` static Go binary (Phase 2)
  capture-shim/ — shell shim Go binary (Phase 3)
rules/        — destructive operations ruleset (YAML)
examples/     — case study reconstructions (Phase 4)
docs/         — architecture, threat model, legal (Phase 4)
```

## Build Plan

See [BUILD_PLAN.md](./BUILD_PLAN.md) for the full operational build plan.

## Current Status: Phase 2 (Integrity and Signing)

### Phase 1 — Passive Reconstruction ✅

- ✅ Event schema (13 types, discriminated union payloads)
- ✅ Canonical JSON (RFC 8785 JCS-like)
- ✅ ULID helpers (deterministic seed for tests)
- ✅ Claude Code JSONL normalizer
- ✅ Shell history normalizer (bash, zsh, fish)
- ✅ Git reflog normalizer
- ✅ Multi-source merge with gap detection
- ✅ Destructive ruleset (YAML, 12 rules)
- ✅ Destructive rules matcher
- ✅ Timeline builder (causal graph, destructive ops index)
- ✅ Manifest builder (Phase 1: unsigned)
- ✅ Bundle writer (directory layout per §5)
- ✅ CLI: `depose reconstruct --from-claude <path>`
- ✅ Synthetic fixtures (terraform-destroy, session-with-gaps, shell-history, git-reflog)
- ✅ Tests (85 tests across core, bundle, cli)
- ✅ CI workflow (lint, typecheck, test)

### Phase 2 — Integrity and Signing ✅

- ✅ IRONROOT hash chain construction and verification (`packages/chain/hash-chain.ts`)
- ✅ Ed25519 signing and verification with PEM key management (`packages/chain/sign-ed25519.ts`)
- ✅ RFC 3161 TSA client with FreeTSA primary / DigiCert fallback (`packages/chain/timestamp-rfc3161.ts`)
- ✅ Sigstore keyless stub (deferred per BUILD_PLAN §2.7 decision criteria)
- ✅ Rekor transparency log stub (deferred)
- ✅ Bundle writer wired for hash chain, signing, timestamps (`packages/bundle/writer.ts`)
- ✅ CLI: `depose package --from-claude <path>` produces fully signed `.depo`
- ✅ Go verifier binary `depose-verify` (manifest parse → signature verify → chain replay → artifact check → RFC 3161 verify → anti-backdating)
- ✅ Cross-compiled: darwin-arm64, darwin-amd64, linux-arm64, linux-amd64
- ✅ Acceptance tests (10 e2e tests: happy path, tamper event, tamper artifact, strip signature, backdate detection, determinism, depose-verify integration)
- ✅ CI includes Go verifier build + cross-compile
- ✅ Tests: 138 passing (85 Phase 1 + 43 chain + 10 e2e)

### Remaining

- ⏳ Phase 3: Active capture (PreToolUse hook, shell shim)
- ⏳ Phase 4: Narrative + case studies

## License

Proprietary — all rights reserved.
