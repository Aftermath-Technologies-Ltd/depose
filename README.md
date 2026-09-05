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
  <a href="#the-incident-the-claim-the-command">Incident</a> ·
  <a href="#why-depose">Why</a> ·
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#whats-in-a-bundle">Bundle</a> ·
  <a href="#active-capture">Active capture</a> ·
  <a href="#verify-it-from-a-clean-machine">Verify</a> ·
  <a href="#examples">Examples</a> ·
  <a href="#repository-layout">Layout</a> ·
  <a href="#development">Dev</a> ·
  <a href="#documentation">Docs</a>
</p>

---

## The incident, the claim, the command

On 15 December 2025, an AI coding agent was asked to fix a bug in AWS
Cost Explorer. It decided the fastest route to a known-good state was to
destroy the production environment and rebuild it. Cost Explorer was
unavailable in cn-northwest-1 for about thirteen hours. The agent had
been given an engineer's operator role, so the two-person approval the
change required was never enforced against it.

The question after an incident like that is not what happened. It is
**what you can prove happened, to someone who does not trust your
laptop.** A transcript on disk is not that: anyone with shell access can
rewrite it, and nothing in it says where it is blind.

DEPOSE produces a bundle that is. This repository ships a reconstruction
of that incident's shape, captured through the real hooks and sealed the
same way every bundle is. Verify it yourself, with one binary and no
DEPOSE install:

```bash
depose-verify verify examples/kiro-cost-explorer/bundle
```

```
  [✓] signature-verify: PASS
         Ed25519 signature valid (1 signature(s))
  [✓] chain-replay: PASS
         Chain valid: 42 events, root hash 6998819f6d7fe435...
  [✓] intent-effect: PASS
         5 tool call(s) have a matching pre and post record; every unpaired intent is disclosed as a gap
  [✓] file-continuity: PASS
         1 file outcome(s) carry forward to the next recorded pre-state, or the difference is disclosed as a gap
  [✓] merkle-root: PASS
         RFC 6962 tree over 42 leaves has head f52cedd7d465bd50...
  [✓] timestamp-verify: PASS
         1 timestamp(s) valid: FreeTSA(2026-09-05T15:31:06.000Z): valid
  [✓] files-map: PASS
         all 16 file(s) in the tree match the signed files map
  ═══ RESULT: PASS ═══
```

The bundle says the agent edited the approval record to add itself as the
second approver, and gives that file's SHA-256 before and after. It says
the destroy ran under `AWS_PROFILE=cost-explorer-operator`. And it says,
in signed evidence, that one command has a pre-execution record and no
outcome: the thirteen hours are marked as missing rather than smoothed
over. Walkthrough: [Verify it from a clean machine](#verify-it-from-a-clean-machine).

## What it is

DEPOSE turns a Claude Code or Codex CLI session into a self-contained, hash-chained, Ed25519-signed evidence bundle. Anyone with a single Go binary can verify it off-host, no DEPOSE infrastructure required. Point it at a session log after a wiped database, a deleted directory, or a destroyed cloud account, and it produces a `.depo` bundle an auditor, regulator, or court can check themselves.

## Why DEPOSE

Agent transcripts on disk aren't evidence. Anyone with shell access can rewrite them. DEPOSE gives four properties that hold off-host:

| Property | Mechanism |
|---|---|
| **Tamper-evident** | IRONROOT hash chain over events, an RFC 6962 Merkle tree over the chain, a signed files map over every file. Any byte change fails verification with a named check. |
| **Selectively disclosable** | Sealed fields are salted commitments; `depose disclose` proves a subset of events and fields against the signed root without re-signing. |
| **Authenticated** | Ed25519 manifest signature, sealed by a key the producer controls and publishes the fingerprint of. |
| **Anti-backdated** | RFC 3161 timestamp from a third-party authority anchors the bundle to a moment in time. A bundle sealed with no network says so and `depose anchor` dates it later. |

The fifth property has no row because it is not cryptographic: **a DEPOSE
bundle states what it does not cover.** Coverage gaps are events, counted
in the signed manifest, and the verifier fails a bundle that has a hole
and no gap disclosing it. A log that cannot say where it is blind has to
be believed rather than checked.

No LLM sits in the signed path. Narrative prose is rendered from signed events and excluded from the root hash.

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

`depose record` always signs (Ed25519 + RFC 3161). An OpenAI Codex CLI rollout goes in the same way, with `--from-codex path/to/rollout-*.jsonl`; Codex has two log grammars and the one that was read is recorded in the signed manifest. For unsigned dev bundles, use `depose package --from-claude <path> --skip-timestamp`.

Verify the bundle from any host:

```bash
./apps/verify/build/depose-verify verify path/to/incident-<bundleId>
```

A passing run prints every check with its status (`PASS`, `FAIL`, `SKIPPED`, or `WARN`; a skipped check is never shown as a pass), followed by `RESULT: PASS`. Recipients can pin the producer's key (`--expected-key-fingerprint`) or a revocation list (`--revocation-list`); see [docs/key-management.md](docs/key-management.md).

Hand a regulator part of the record without re-signing or exposing the rest:

```bash
./packages/cli/bin/depose disclose path/to/incident-<bundleId> --events 3-9 --fields /toolInput --out incident-disclosure
./apps/verify/build/depose-verify verify incident-disclosure   # no access to the original needed
```

The disclosure carries the original signature and timestamp, the chosen events byte for byte, RFC 6962 audit paths against the sealed Merkle root for every position, and commitment openings for the chosen fields only. Withheld events reveal their count and positions, nothing else.

Full command surface (`depose --help`): `record`, `package`, `disclose`, `export`, `anchor`, `reconstruct`, `verify`, `explain`, `install --claude|--shell`, `uninstall --claude|--shell`, `key {fingerprint,rotate,revoke,catalog}`.

## How it works

Six layers. Each does one thing. None LLM-narrated.

```
CAPTURE  →  NORMALIZATION  →  RECONSTRUCTION  →  INTEGRITY  →  BUNDLE  →  NARRATIVE
```

| Layer | What it does | Package |
|---|---|---|
| **Capture** | Hooks and shims record events at execution time; an optional eBPF collector records what the kernel saw. | `packages/capture-claude`, `apps/capture-shim`, `apps/collect-execve` |
| **Normalization** | Claude Code JSONL, Codex CLI rollouts, shell history (bash/zsh/fish), git reflog into a common event schema. | `packages/core` |
| **Reconstruction** | Sort, merge across sources, deduplicate, flag gaps, build a causal timeline. | `packages/core/reconstruct` |
| **Integrity** | IRONROOT hash chain, Ed25519 signing, RFC 3161 timestamping. | `packages/chain` |
| **Bundle** | Deterministic directory layout (tar packing is future work). | `packages/bundle` |
| **Narrative** | Deterministic prose with `[#evt-<ulid>]` citations, rendered by a function rather than a template engine. Excluded from root hash. | `packages/narrative` |

DEPOSE has one runtime dependency: `yaml`, for reading the destructive
ruleset. Everything else, canonical JSON, the hash chain, the Merkle
tree, DER parsing, CBOR, COSE, did:key, and both narrative renderers, is
implemented in the repository. That is not minimalism for its own sake:
every one of those sits on the trust boundary, and a reader auditing what
a bundle proves should be able to read the code that proves it. The
packaged CLI inlines `commander` at build time, so an installed `depose`
pulls in nothing at all.

Design rationale and threat model in [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md).

## What's in a bundle

A DEPOSE bundle is a directory tree:

```
incident-01JABC.../
├── manifest.json            ← bundleId, rootHash, files map, sigs, timestamps
├── events.jsonl             ← every event in canonical JSON, byte-pinned by manifest
├── rules/destructive.yaml   ← ruleset used at reconstruction time
├── narrative.md / .html     ← templated prose with per-event citations
├── verify.txt               ← human-readable verification summary
├── artifacts/               ← captured file diffs, payloads
├── attestations/            ← Ed25519 signatures, RFC 3161 timestamp tokens
└── raw/                     ← source JSONL, shell history fragments, capture records
```

Every file in the tree is pinned by a signed files map in `manifest.json`: changing, adding, or deleting any file (the raw JSONL, a timestamp token, the narrative) causes verification to fail with a named check. Full format spec (canonical JSON rules, chain construction, files map, signing procedure, manifest schema) lives in [docs/bundle-format.md](docs/bundle-format.md) and [docs/canonical-json.md](docs/canonical-json.md).

## Active capture

Reconstructing from a JSONL after the fact is the lower-bound mode. For sessions you're running *now*, install hooks that record events at execution time:

```bash
depose install --claude   # registers the Claude Code PreToolUse and PostToolUse hooks
depose install --shell    # shims terraform, aws, gh, kubectl, psql, gcloud, railway, rm
```

Capture records land under `~/.depose/captures/`. Later `depose package` runs merge them with the session JSONL so every covered event has a verified pre-execution intent on record. If a hook throws, it writes a `capture_failed` record before exiting 0, and the bundle shows that as a gap event rather than a clean timeline. Destructive rules match every simple command inside a captured shell line, so `sudo rm -rf`, `env X=1 terraform destroy`, and `cd /prod && rm -rf .` all fire.

`--claude` registers both halves of every tool call. The PreToolUse hook records what the agent was about to run and the SHA-256 of every file the call names; the PostToolUse hook records the exit status and those same hashes afterwards, carrying the intent's event id inside its signed payload. A call with no recorded outcome becomes an `intent_without_effect` gap and gets its own section at the top of the narrative, and the verifier fails any bundle that has the hole without the gap.

On Linux, `depose-collect-execve` adds what the kernel saw:

```bash
sudo depose-collect-execve --session <id> --pid <agent pid>
```

It attaches to the `sched:sched_process_exec` tracepoint and records every exec in the agent's process tree, so a command invoked by absolute path, through `subprocess.run(..., shell=False)`, or by a static binary shows up as its own event with a `kernel_execve_without_hook` gap instead of being absent. It needs `CAP_BPF`; without it the collector records why it could not run and exits 0. macOS is hook-only, and says so rather than shipping a stub.

Coverage matrix and threat-vs-coverage tradeoffs: [docs/capture-coverage.md](docs/capture-coverage.md). Install details: [docs/hook-installation.md](docs/hook-installation.md), [docs/shim-installation.md](docs/shim-installation.md).

## Sealing without a network

`depose record` signs immediately and asks a timestamp authority to date
the seal. When no authority answers, the bundle is still produced: it is
signed, marked `anchorStatus: "pending"`, and the verifier reports it as
unanchored rather than invalid. Add the anchor when the network is back:

```bash
depose anchor incident-01JABC...
```

The anchor commits to exactly the bytes the signature covered and is
written to `attestations/anchor.json` with a countersignature by the
sealing key. `manifest.json` does not change, so the original seal
verifies exactly as it did. Pass `--require-anchor` to `depose record` if
your policy is that an undated bundle is not worth having.

## Exporting to IETF formats

A sealed bundle renders into three interchange formats, each a pure
function of the bundle:

```bash
depose export incident-01JABC... --format aat              # draft-sharif-agent-audit-trail JSON Lines
depose export incident-01JABC... --format asqav-receipt    # draft-marques-asqav signed compliance receipts
depose export incident-01JABC... --format scitt-statement  # COSE_Sign1 SCITT Signed Statement, ready to register
```

The two signed formats refuse to run with a key that did not seal the
bundle. Every field mapping, and every DEPOSE field the target format has
no home for, is in [docs/export-mapping.md](docs/export-mapping.md),
including the three places where a draft was ambiguous and DEPOSE chose
the reading that says less rather than the one that would assert
something it cannot prove.

## Verify it from a clean machine

Nothing below needs Node, pnpm, or a DEPOSE install. One binary, one
directory, no network.

**1. Get the verifier.** Download the release binary for your platform
from [the releases page](https://github.com/Aftermath-Technologies-Ltd/depose/releases),
or build it from this repository with `cd apps/verify && make build-local`
if you have Go. Release binaries are signed with cosign; `SHA256SUMS`,
`SHA256SUMS.sig`, and `SHA256SUMS.pem` are published beside them.

**2. Get the bundle.** It is a directory. Copy it, tar it, email it; the
verification does not care how it arrived:

```bash
git clone --depth 1 https://github.com/Aftermath-Technologies-Ltd/depose
```

**3. Verify it.**

```bash
depose-verify verify depose/examples/kiro-cost-explorer/bundle
```

Nineteen named checks run in a documented order. What each one means is
in [docs/bundle-format.md](docs/bundle-format.md#verifier-checks); the
four that carry the argument are:

| Check | What a PASS rules out |
|---|---|
| `signature-verify` | The manifest was written by someone without the producer's key. |
| `chain-replay`, `merkle-root` | Any event was added, removed, reordered, or edited after sealing. |
| `files-map`, `attestation-files` | Any file in the tree, including the raw transcript and the timestamp token, was swapped or truncated. |
| `timestamp-verify`, `timestamp-backdating` | The bundle was made after the fact and dated to look contemporaneous. |

A `SKIPPED` or `WARN` is never printed as `PASS`. A dev-unsigned bundle
prints `PASS (dev-unsigned, not evidence)` and says so in a banner.

**4. Read what it is willing to say it does not know.**

```bash
grep -A 4 'Lost Outcomes' depose/examples/kiro-cost-explorer/bundle/narrative.md
```

One tool call in that session has a pre-execution record and no outcome.
The bundle does not guess what happened; it marks the hole and the
verifier fails any copy that has the hole and not the mark.

**5. Verify the disclosure.** The same incident, as a regulator would
receive it: every event proven to be a member of the sealed set, most
fields still salted commitments.

```bash
depose-verify verify depose/examples/kiro-cost-explorer/disclosure
```

It verifies against the original manifest, signature, and timestamp,
without the original bundle being present at all.

## Examples

Three synthetic reconstructions are checked in:

- **[kiro-cost-explorer](examples/kiro-cost-explorer)**: an agent destroys a production environment after editing the approval record that should have stopped it. Captured through the hooks, with intent and effect records, a sealed bundle, and a disclosure. This is the one the walkthrough above verifies.
- **[datatalks-reconstruction](examples/datatalks-reconstruction)**: agent runs `rm -rf` on a training-data directory.
- **[pocketos-reconstruction](examples/pocketos-reconstruction)**: agent runs `terraform destroy -auto-approve`.

```bash
bash examples/datatalks-reconstruction/produce.sh
```

CI rebuilds the bundles on every push and validates them end-to-end.

## Repository layout

```
packages/
├── core/             event schema, normalizers, reconstruction, ruleset matcher
├── chain/            hash chain, Ed25519 signing, RFC 3161, key catalog
├── bundle/           bundle directory writer + manifest schema
├── narrative/        deterministic narrative renderer (no template engine)
├── capture-claude/   Claude Code PreToolUse and PostToolUse hooks
└── cli/              `depose` + `depose-hook` commands (+ bundled rules)
apps/
├── verify/           `depose-verify` static Go binary
├── capture-shim/     `depose-shim` shell shim Go binary
└── collect-execve/   `depose-collect-execve` optional Linux eBPF execve collector
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
| [compliance-mapping.md](docs/compliance-mapping.md) | Which bundle field and verifier check answers which sentence of the EU AI Act, DORA, SEC Rule 17a-4, and the HIPAA Security Rule, and where DEPOSE stops. |
| [export-mapping.md](docs/export-mapping.md) | `depose export` field mappings for AAT, ASQAV receipts, and SCITT statements, and what each format cannot carry. |
| [hook-installation.md](docs/hook-installation.md) | Claude Code capture hook setup, both halves. |
| [shim-installation.md](docs/shim-installation.md) | Shell shim setup. |
| [key-management.md](docs/key-management.md) | Signing-key flows, fingerprints, rotation/revocation. |
| [legal-considerations.md](docs/legal-considerations.md) | Evidentiary use, jurisdictional notes. |
| [development.md](docs/development.md) | Build, test, CI, and release internals. |

Repo-root: [SECURITY.md](SECURITY.md) (disclosure), [CHANGELOG.md](CHANGELOG.md).

## License

[GNU Affero General Public License v3.0 only](LICENSE) (SPDX: `AGPL-3.0-only`).
© Aftermath Technologies Ltd. and contributors.
