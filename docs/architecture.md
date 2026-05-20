# DEPOSE Architecture

DEPOSE is a two-binary forensic evidence system that captures, reconstructs,
packages, and verifies AI coding agent sessions into signed `.depo` bundles.
This document describes the architecture at a level sufficient for a new
contributor to understand the system's structure, data flow, and key design
decisions.

---

## 1. Two-binary model

DEPOSE ships two binaries with no shared runtime dependency:

| Binary          | Language   | Purpose                                      |
|-----------------|------------|----------------------------------------------|
| `depose`        | TypeScript (Node.js) | Capture, reconstruct, package, explain. Produces `.depo` bundles. |
| `depose-verify` | Go         | Validate a `.depo` bundle on any host with no other DEPOSE infrastructure. |

### 1.1 Why two languages?

The producer (`depose`) needs access to the Node.js ecosystem for Claude Code
hook integration, npm package reuse (tar, JSONL parsing, sigstore clients), and
developer ergonomics. TypeScript is the right choice for a tool that runs on the
developer's machine with a full runtime available.

The verifier (`depose-verify`) must run **anywhere** — a regulator's laptop, an
air-gapped environment, a CI runner with no Node.js installed. Go produces a
statically-linked single binary with no runtime dependency. The verifier uses
only the Go standard library and minimal dependencies (`crypto/ed25519`,
`crypto/x509`, `archive/tar`). This is a deliberate trade-off: reimplementing
tar parsing and chain replay in Go is acceptable because the verifier logic is
simple and must be auditable without understanding a complex framework.

### 1.2 Shared contract

The two binaries share no code. They share a **specification**: this document,
`docs/bundle-format.md`, and the TypeScript type definitions in
`packages/bundle/src/manifest.ts`. The Go verifier implements the same schemas
from scratch using the specification as the contract. Any divergence between the
producer's output and the verifier's expectations is a bug, and CI catches it
by producing a bundle and immediately verifying it.

---

## 2. Six-layer stack

The architecture is organized as six strictly layered components. Each layer
does one thing. Data flows downward; no layer reaches up.

```
┌───────────────────────────────────────────────────────────────┐
│  CAPTURE                                                       │
│   • Passive: Claude Code JSONL, shell history, git reflog,    │
│     fs mtime snapshots                                         │
│   • Active: PreToolUse hook (Claude Code) + PATH shim          │
│     (generic destructive binaries)                             │
└────────────────┬──────────────────────────────────────────────┘
                 │
┌────────────────▼──────────────────────────────────────────────┐
│  NORMALIZATION                                                 │
│   Vendor records → unified Event schema. Emits `gap` events    │
│   wherever a tool result has no matching pre-execution capture │
└────────────────┬──────────────────────────────────────────────┘
                 │
┌────────────────▼──────────────────────────────────────────────┐
│  RECONSTRUCTION                                                │
│   Deterministic timeline, parent-child causal graph,           │
│   destructive-operations index, cross-correlation against      │
│   git reflog + filesystem state                                │
└────────────────┬──────────────────────────────────────────────┘
                 │
┌────────────────▼──────────────────────────────────────────────┐
│  INTEGRITY                                                     │
│   Hash chain (IRONROOT construction) → root_hash              │
│   Sign manifest (Ed25519) — Sigstore keyless not yet impl.    │
│   RFC 3161 timestamps                                           │
└────────────────┬──────────────────────────────────────────────┘
                 │
┌────────────────▼──────────────────────────────────────────────┐
│  BUNDLE                                                        │
│   Deterministic directory tree, manifest.json entrypoint.       │
│   (Future: canonical USTAR packing in the producer.)            │
└────────────────┬──────────────────────────────────────────────┘
                 │
┌────────────────▼──────────────────────────────────────────────┐
│  NARRATIVE                                                     │
│   Template-driven, deterministic, every claim cites event ID. │
│   No LLM in signed path.                                       │
└───────────────────────────────────────────────────────────────┘
```

### 2.1 Layer 1: Capture

Capture is the sensory layer — it records what happened. It has two modes:

- **Passive**: Reads existing artifacts that the agent runtime already produces
  (Claude Code JSONL transcripts, shell history files, git reflog, filesystem
  mtime snapshots). No code injection; no runtime coupling.
- **Active**: Injects observation points into the agent's execution path to
  capture data that passive sources miss. Two mechanisms:
  - **Claude Code PreToolUse hook**: A command-line hook registered in
    `.claude/settings.json` that fires before every Bash/Edit/Write tool call.
    Captures argv, cwd, env subset, file hashes, and process tree. Never denies
    or modifies the call — observation only.
  - **Shell shim**: A Go binary placed earlier on PATH than destructive tools
    (`terraform`, `aws`, `kubectl`, etc.). When invoked, it captures the same
    pre-execution data, then `exec`s through to the real binary with full
    stdio/signal/exit-code passthrough.

Active capture is opt-in. The user runs `depose install --claude` and/or
`depose install --shell` to activate it. Capture records are written to
`$DEPOSE_CAPTURE_DIR` (default `~/.depose/captures`) with 0600 permissions.

### 2.2 Layer 2: Normalization

Raw captures are vendor-specific and heterogeneous. Normalization converts them
into a single, unified `Event` schema with a stable type system:

- `claude-code.ts` — parses Claude Code JSONL into Event records.
- `shell-history.ts` — parses bash/zsh/fish history into Event records.
- `git-reflog.ts` — parses reflog entries into Event records.
- `merge.ts` — merges all sources into a single timeline, sorted by ULID, and
  **emits `gap` events** wherever data is inconsistent or missing.

A `gap` event is the system's honest accounting of what it could not observe.
Every gap has a reason code (`tool_result_without_pre_capture`,
`shell_history_without_jsonl_correlation`, etc.) and affected event IDs.
Gaps are explicit rather than silently smoothed over — this is a core design
principle.

### 2.3 Layer 3: Reconstruction

Reconstruction builds the causal graph and identifies destructive operations:

- **timeline.ts** — constructs a parent-child directed graph from `parentEventId`
  links and same-session temporal correlation. The timeline is the canonical
  event ordering for narrative rendering.
- **destructive-rules.ts** — loads the YAML ruleset and matches events against
  it. Each match tags the event with the rule's ID and severity. The ruleset
  itself is stored in the bundle and hashed in the manifest.
- **correlate.ts** — cross-correlates captures against aftermath (git reflog
  changes, filesystem state changes) to strengthen or flag inconsistencies.

### 2.4 Layer 4: Integrity

Integrity is the cryptography layer. It makes the bundle tamper-evident:

- **Hash chain** (IRONROOT construction): Each event's chain hash incorporates
  the previous event's chain hash and the current event's metadata + payload hash.
  The terminal hash is `rootHash`. This construction means modifying any single
  event invalidates every subsequent event's chain hash, making tampering
  trivially detectable.

  ```
  chainHash[0] = SHA-256( zero32 || payloadHash[0] || eventMetadata[0] )
  chainHash[i] = SHA-256( chainHash[i-1] || payloadHash[i] || eventMetadata[i] )
  rootHash     = chainHash[N-1]
  ```

- **Signing**: Ed25519 (default, local keypair). Sigstore Fulcio (not yet
  implemented, opt-in, keyless via OIDC). The signature covers `manifest.json`, which contains
  `rootHash`.

- **RFC 3161 timestamps**: The bundle is submitted to a Time Stamp Authority
  (FreeTSA primary, DigiCert fallback) at packaging time. The `.tsr` tokens
  prove that the bundle existed at a specific time, as certified by a trusted
  third party.

- **Rekor** (not yet implemented): Transparency log entry for public auditability.
  The code path is scaffolded but throws on every call. Ed25519 + RFC 3161 is
  the only signing path today.

### 2.5 Layer 5: Bundle

The bundle layer serializes everything into a deterministic directory
tree under `incident-<ulid>/`:

- **manifest.ts** — builds the manifest with all computed hashes
  (rootHash, eventsJsonlSha256, rulesetHash), counts, and metadata.
- **writer.ts** — writes the directory tree. Per-file ordering inside
  `events.jsonl` is canonical (ULID sort) and the file's bytes are
  pinned by `manifest.eventsJsonlSha256` before the manifest is
  signed. Other files are not order-sensitive to verification.
- **layout.ts** — path conventions and constants.

Canonical USTAR archive packing in the producer is tracked as future
work. Until then, recipients pack/unpack with their preferred tool;
integrity flows through the in-bundle hashes, not the container
metadata. See `docs/bundle-format.md` §1 for a tar invocation that
produces a byte-identical archive across rebuilds.

### 2.6 Layer 6: Narrative

The narrative layer renders human-readable output without any LLM in the trust
path:

- **Handlebars templates** (`template.md.hbs`, `template.html.hbs`) — no
  side-effect helpers, fully deterministic.
- **render.ts** — walks the timeline and emits prose where every claim cites
  an event ID anchor (`[#evt-<ulid>]`), linking to `events.jsonl`.
- **rule-902.ts** — optional Federal Rule of Evidence 902(13)/(14)
  self-authenticating certification template signed by the bundle producer.

The LLM-generated `commentary.md` (from `depose explain`) is **not** part of
this layer's signed output. It is explicitly excluded from `rootHash` and
labeled "AI-GENERATED COMMENTARY — NOT EVIDENCE."

---

## 3. Data flow

```
                    ┌─────────────────────────────────────┐
                    │   Claude Code session (JSONL)       │
                    │   Shell history, git reflog          │
                    │   PreToolUse hook capture records    │
                    │   Shell shim capture records         │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │   NORMALIZATION                      │
                    │   Each source → Event[] + gap events │
                    │   Merge into unified timeline        │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │   RECONSTRUCTION                     │
                    │   Causal graph + destructive index   │
                    │   Cross-correlation + gap flags      │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │   INTEGRITY                         │
                    │   Hash chain → rootHash              │
                    │   Sign manifest (Ed25519/sigstore)  │
                    │   RFC 3161 timestamp                 │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │   BUNDLE                             │
                    │   Deterministic directory tree       │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │   NARRATIVE                          │
                    │   Template render → .md + .html      │
                    │   (included in bundle, unsigned)     │
                    └─────────────────────────────────────┘
```

The data flow is strictly unidirectional. No layer feeds back to a previous
layer. This simplifies reasoning, testing, and the verifier's job (which
replays the chain in the same order).

---

## 4. Key design decisions

### 4.1 No LLM in the signed path

The entire value proposition of DEPOSE is that the evidence bundle is
machine-verifiable without trusting any model output. LLMs hallucinate;
hash chains do not. The narrative is template-rendered with event-ID citations.
The only place an LLM touches the bundle is `commentary.md`, which is
explicitly excluded from the signed root and labeled non-evidentiary.

### 4.2 Show the gap, don't hide it

When DEPOSE cannot observe something (a tool result with no pre-execution
capture, a reflog change with no captured command), it emits a `gap` event.
The alternative — silently smoothing over missing data — would produce a
plausible-looking but incomplete narrative. Gaps make the limitations visible
and auditable. A bundle with three gap events is more trustworthy than a
bundle with zero gap events and silently missing data.

### 4.3 Determinism by default

Every aspect of bundle production is deterministic given the same inputs and
the same fixed clock:

- ULIDs are time-sortable and generated from an injectable clock.
- Events sort by ULID (stable sort).
- JSON serialization uses RFC 8785 JCS (deterministic property ordering).
- Tar entries are lexicographic by path, fixed mtime, fixed uid/gid.
- Narrative templates have no side-effect helpers.

This determinism enables: (a) reproducibility audits, (b) diff-based review
of bundle changes, (c) byte-identical rebuild CI checks.

### 4.4 Observation-only capture

The PreToolUse hook and shell shim **never deny or modify** a tool call. They
record pre-execution state and get out of the way. Denial is governance
(Microsoft Agent Governance Toolkit's lane). DEPOSE is forensics. This
constraint is load-bearing: if the capture layer could block execution, the
absence of a capture record would be ambiguous (was it not captured, or was
it blocked?). With observation-only capture, the absence of a record is always
a gap, never a policy decision.

### 4.5 Separate verifier, no shared code

The Go verifier does not import any TypeScript code. It re-implements the
bundle format and chain replay from scratch using the specification. This
eliminates the class of bugs where a shared parsing library has the same bug
in both producer and verifier. If the producer and verifier disagree, CI
fails loudly. This is a deliberate redundancy-for-correctness decision, at
the cost of maintaining two implementations.

### 4.6 Opt-in capture with strict privacy defaults

- Capture is per-directory/per-project, never global.
- Environment variables: only an allowlisted subset is stored in plaintext.
  The full environment is SHA-256 hashed (not stored) for tamper-evidence.
- File content: hash-only by default. Full content storage requires explicit
  opt-in and is limited to files under 1 MB.
- Capture records are written with 0600 permissions.
- The Ed25519 signing key is stored at `~/.depose/keys/signing.key` with 0600
  permissions and never logged.

### 4.7 Additive versioning

New event types and new payload fields are additive. The verifier ignores
unknown fields. Breaking changes (field removal, semantic alteration) require
a major `schemaVersion` bump and a migration path. The ruleset is hashed and
stored in the bundle; a future reader can see exactly which rules flagged what.

### 4.8 Standard cryptography, no novelty

DEPOSE uses:
- SHA-256 ( hashing everywhere — no exotic hash functions.
- Ed25519 (established, fast, widely supported).
- Sigstore Fulcio (not yet implemented; scaffold only).
- RFC 3161 (established TSA standard).

No custom cryptography. No novel constructions. The IRONROOT hash chain is a
standard pattern (similar to certificate transparency logs). The verification
logic is simple enough to audit by hand.

---

## 5. Package map

| Package              | Layer(s)        | Language   | Key files                                    |
|----------------------|-----------------|------------|----------------------------------------------|
| `packages/core`      | Normalize + Reconstruct | TS  | `schema.ts`, `merge.ts`, `timeline.ts`      |
| `packages/chain`     | Integrity       | TS         | `hash-chain.ts`, `sign-ed25519.ts`          |
| `packages/bundle`   | Bundle          | TS         | `manifest.ts`, `writer.ts`, `layout.ts`     |
| `packages/capture-claude` | Capture  | TS         | `hook-entry.ts`, `capture-record.ts`        |
| `packages/cli`      | All (orchestration) | TS    | `commands/reconstruct.ts`, `package.ts`    |
| `packages/narrative` | Narrative      | TS         | `render.ts`, `template.md.hbs`              |
| `apps/verify`       | Verification   | Go         | `cmd/verify.go`, `chain/replay.go`          |
| `apps/capture-shim` | Capture (shell) | Go        | `main.go`, `exec.go`, `record.go`           |

---

## 6. Cross-cutting patterns

### 6.1 Injected clock

All timestamp-dependent code uses an injectable `Clock` interface. Production
wires to `Date.now()` / `process.hrtime.bigint()`. Tests wire to a fixed-seed
implementation for determinism. This pattern ensures that the 300-line file cap
and the no-`Date.now()`-in-business-logic rule are enforceable.

### 6.2 Canonical JSON (RFC 8785 JCS)

Every hash input is serialized through `canonical-json.ts` before hashing. This
is used in:

- `payloadHash` computation for each event.
- `eventMetadata` serialization in the hash chain.
- `manifest.json` serialization before signing.
- Environment hash computation.

### 6.3 Error strategy

Fail loud, fail early. A normalizer that encounters an unknown field shape
emits a `gap` event rather than silently dropping data. A hash chain that
cannot be computed fails the entire packaging step. A TSA that is unreachable
prevents bundle production (a bundle without a timestamp defeats the purpose).

### 6.4 Testing philosophy

- Real fixtures over synthetic mocks. Claude Code JSONL from actual sessions.
- Every destructive rule has a positive and negative match test.
- The verifier has a tamper-suite that flips bytes at every structural boundary.
- Snapshot tests for narrative rendering, with golden files and explicit
  `--update-snapshots` flag.
- CI rebuilds and re-verifies example bundles on every PR.

---

## 7. Deployment topology

```
Developer Machine                          Third Party
┌──────────────────────┐                  ┌──────────────────────┐
│  Claude Code          │                  │                      │
│      │                │                  │  depose-verify        │
│      ▼                │  bundle dir      │      │               │
│  PreToolUse hook      │──────────────▶  │      ▼               │
│  Shell shim           │                  │  PASS / FAIL report   │
│      │                │                  │                      │
│      ▼                │                  │  No DEPOSE install   │
│  depose reconstruct   │                  │  No Node.js required │
│  depose package       │                  │  No network required │
│      │                │                  │  (except Rekor check)│
│      ▼                │                  │                      │
│  bundle directory     │                  └──────────────────────┘
└──────────────────────┘
```

The verifier runs on a fresh machine with no DEPOSE installation and no network
access (Rekor check is optional and gracefully skipped). This is the delivery
guarantee: a single binary, a single file, a definitive answer.