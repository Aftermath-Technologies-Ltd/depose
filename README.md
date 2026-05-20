<p align="center">
  <img src="./.github/assets/cover.svg" alt="DEPOSE: Depose the agent. Produce the record." width="100%">
</p>

<p align="center">
  <strong>Forensic evidence bundles for AI coding agent sessions.</strong><br>
  Hash-chained · Ed25519-signed · RFC&nbsp;3161-timestamped · verifiable off-host with a single Go binary.
</p>

<p align="center">
  <a href="https://github.com/Aftermath-Technologies-Ltd/depose/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Aftermath-Technologies-Ltd/depose/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Aftermath-Technologies-Ltd/depose/actions/workflows/verify-examples.yml"><img alt="Verify Examples" src="https://github.com/Aftermath-Technologies-Ltd/depose/actions/workflows/verify-examples.yml/badge.svg"></a>
  <img alt="Node" src="https://img.shields.io/badge/node-%E2%89%A520-339933?logo=node.js&logoColor=white">
  <img alt="TypeScript" src="https://img.shields.io/badge/typescript-5.9-3178c6?logo=typescript&logoColor=white">
  <img alt="Go" src="https://img.shields.io/badge/go-1.22-00ADD8?logo=go&logoColor=white">
  <img alt="pnpm" src="https://img.shields.io/badge/pnpm-9-F69220?logo=pnpm&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0--only-blue">
</p>

<p align="center">
  <a href="#why-depose">Why</a> ·
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#whats-in-a-bundle">Bundle</a> ·
  <a href="#active-capture">Active capture</a> ·
  <a href="#examples">Examples</a> ·
  <a href="#repository-layout">Layout</a> ·
  <a href="#development">Dev</a> ·
  <a href="#documentation">Docs</a>
</p>

---

## What it is

DEPOSE turns a Claude Code session into a self-contained, hash-chained, Ed25519-signed evidence bundle. Anyone with a single Go binary can verify it off-host, no DEPOSE infrastructure required. Point it at a session log after a wiped database, a deleted directory, or a destroyed cloud account, and it produces a `.depo` bundle an auditor, regulator, or court can check themselves.

## Why DEPOSE

Agent transcripts on disk aren't evidence. Anyone with shell access can rewrite them. When an agent does real damage the question stops being *what happened* and becomes *what can you prove happened, to a third party who doesn't trust your laptop*. DEPOSE gives three properties that hold off-host:

| Property | Mechanism |
|---|---|
| **Tamper-evident** | IRONROOT hash chain over events; any byte change fails replay. |
| **Authenticated** | Ed25519 manifest signature, sealed by a key the producer controls. |
| **Anti-backdated** | RFC 3161 timestamp from FreeTSA (DigiCert fallback) anchors the bundle to a moment in time. |

No LLM sits in the signed path. Narrative prose is templated from signed events and excluded from the root hash.

## Install

```bash
git clone https://github.com/Aftermath-Technologies-Ltd/depose
cd depose
pnpm install
pnpm build

# Standalone verifier (Go 1.22+)
cd apps/verify && make build-local
```

Requirements: **Node.js ≥ 20**, **pnpm 9**, **Go 1.22+** for the verifier. Platforms: macOS and Linux. Windows isn't supported (the signing key store relies on POSIX 0600 permissions and the capture shims are POSIX shell scripts); use WSL2 there.

## Quick start

Record a signed bundle from a Claude Code session JSONL:

```bash
./packages/cli/bin/depose record --from-claude path/to/session.jsonl
```

`depose record` always signs (Ed25519 + RFC 3161). For unsigned dev bundles, use `depose package --from-claude <path> --skip-timestamp`.

Verify the bundle from any host:

```bash
./apps/verify/build/depose-verify verify path/to/incident-<bundleId>
```

A passing run prints `parse / signature / chain-replay / artifacts / timestamp` each `OK`, followed by `PASS  bundleId=... rootHash=...`. Recipients can pin the producer's key (`--expected-key-fingerprint`) or a revocation list (`--revocation-list`); see [docs/key-management.md](docs/key-management.md).

Full command surface (`depose --help`): `record`, `package`, `reconstruct`, `verify`, `explain`, `install --claude|--shell`, `uninstall --claude|--shell`, `key {fingerprint,rotate,revoke,catalog}`.

## How it works

Six layers. Each does one thing. None LLM-narrated.

```
CAPTURE  →  NORMALIZATION  →  RECONSTRUCTION  →  INTEGRITY  →  BUNDLE  →  NARRATIVE
```

| Layer | What it does | Package |
|---|---|---|
| **Capture** | Hooks and shims record events at execution time. | `packages/capture-claude`, `apps/capture-shim` |
| **Normalization** | Claude Code JSONL, shell history (bash/zsh/fish), git reflog into a common event schema. | `packages/core` |
| **Reconstruction** | Sort, merge across sources, deduplicate, flag gaps, build a causal timeline. | `packages/core/reconstruct` |
| **Integrity** | IRONROOT hash chain, Ed25519 signing, RFC 3161 timestamping. | `packages/chain` |
| **Bundle** | Deterministic directory layout (tar packing is future work). | `packages/bundle` |
| **Narrative** | Handlebars-templated prose with `[#evt-<ulid>]` citations. Excluded from root hash. | `packages/narrative` |

Design rationale and threat model in [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md).

## What's in a bundle

A DEPOSE bundle is a directory tree:

```
incident-01JABC.../
├── manifest.json            ← bundleId, rootHash, eventsJsonlSha256, sigs, timestamps
├── events.jsonl             ← every event in canonical JSON, byte-pinned by manifest
├── rules/destructive.yaml   ← ruleset used at reconstruction time
├── narrative.md / .html     ← templated prose with per-event citations
├── verify.txt               ← human-readable verification summary
├── artifacts/               ← captured file diffs, payloads
├── attestations/            ← Ed25519 signatures, RFC 3161 timestamp tokens
└── raw/                     ← source JSONL, shell history fragments, capture records
```

Tampering with any byte of `events.jsonl`, `manifest.json`, or `rules/destructive.yaml` causes verification to fail. Full format spec (canonical JSON rules, chain construction, signing procedure, manifest schema) lives in [docs/bundle-format.md](docs/bundle-format.md) and [docs/canonical-json.md](docs/canonical-json.md).

## Active capture

Reconstructing from a JSONL after the fact is the lower-bound mode. For sessions you're running *now*, install hooks that record events at execution time:

```bash
depose install --claude   # registers Claude Code PreToolUse hook
depose install --shell    # shims terraform, aws, gh, kubectl, psql, gcloud, railway, rm
```

Capture records land under `~/.depose/captures/`. Later `depose package` runs merge them with the session JSONL so every covered event has a verified pre-execution intent on record.

Coverage matrix and threat-vs-coverage tradeoffs: [docs/capture-coverage.md](docs/capture-coverage.md). Install details: [docs/hook-installation.md](docs/hook-installation.md), [docs/shim-installation.md](docs/shim-installation.md).

## Examples

Two synthetic reconstructions are checked in. Each ships a Claude Code JSONL and a `produce.sh` that runs the full pipeline:

- **[datatalks-reconstruction](examples/datatalks-reconstruction)**: agent runs `rm -rf` on a training-data directory.
- **[pocketos-reconstruction](examples/pocketos-reconstruction)**: agent runs `terraform destroy -auto-approve`.

```bash
bash examples/datatalks-reconstruction/produce.sh
```

CI rebuilds both bundles on every push and validates them end-to-end.

## Repository layout

```
packages/
├── core/             event schema, normalizers, reconstruction, ruleset matcher
├── chain/            hash chain, Ed25519 signing, RFC 3161, key catalog
├── bundle/           bundle directory writer + manifest schema
├── narrative/        Handlebars-based deterministic narrative renderer
├── capture-claude/   Claude Code PreToolUse hook
└── cli/              `depose` + `depose-hook` commands (+ bundled rules)
apps/
├── verify/           `depose-verify` static Go binary
└── capture-shim/     `depose-shim` shell shim Go binary
examples/             synthetic reconstructions, replayed in CI
scripts/              determinism + install-from-pack E2E
tests/conformance/    cross-language canonical-JSON vectors
docs/                 architecture, threat model, bundle format, install guides
```

## Development

```bash
pnpm build       # TS packages + Go shim + esbuild bundle for the CLI
pnpm typecheck   # tsc --build --noEmit
pnpm lint        # eslint, --max-warnings 0
pnpm test        # vitest (TS); add `:go` for Go suites, `:all` for both
```

CI runs lint, typecheck, the TS + Go suites on Ubuntu and macOS (Node 20 + 22), cross-compiles `depose-verify` for darwin/linux × arm64/amd64, re-produces and verifies both example bundles end-to-end (including three semantic tamper rejections), packs and installs the CLI tarball, and asserts round-trip determinism. Releases additionally emit CycloneDX SBOMs (TS + Go) and SLSA L3 provenance, with `SHA256SUMS` signed via cosign keyless.

Build internals, the full CI matrix, and source-tree invariants: [docs/development.md](docs/development.md).

## Documentation

| Doc | What |
|---|---|
| [architecture.md](docs/architecture.md) | System design, two-binary model, data flow. |
| [bundle-format.md](docs/bundle-format.md) | `.depo` spec: layout, manifest schema, hash chain. |
| [canonical-json.md](docs/canonical-json.md) | RFC 8785 JCS rules used by both producer and verifier. |
| [threat-model.md](docs/threat-model.md) | What DEPOSE defends against, what it doesn't. |
| [capture-coverage.md](docs/capture-coverage.md) | Coverage matrix per capture mode. |
| [hook-installation.md](docs/hook-installation.md) | Claude Code PreToolUse hook setup. |
| [shim-installation.md](docs/shim-installation.md) | Shell shim setup. |
| [key-management.md](docs/key-management.md) | Signing-key flows, fingerprints, rotation/revocation. |
| [legal-considerations.md](docs/legal-considerations.md) | Evidentiary use, jurisdictional notes. |
| [development.md](docs/development.md) | Build, test, CI, and release internals. |

Repo-root: [SECURITY.md](SECURITY.md) (disclosure), [CHANGELOG.md](CHANGELOG.md).

## License

[GNU Affero General Public License v3.0 only](LICENSE) (SPDX: `AGPL-3.0-only`).
© Aftermath Technologies Ltd. and contributors.
