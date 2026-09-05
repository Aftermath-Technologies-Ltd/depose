# DEPOSE Bundle Format (.depo)

A DEPOSE bundle is a directory tree containing a complete, verifiable
evidence record of an AI coding agent session. This document is the
normative specification: any third party, including the standalone
`depose-verify` binary, can parse, validate, and reason about a bundle
from this document alone, without DEPOSE infrastructure.

Section anchors (`#files-map`, `#event-schema`, ...) are referenced
from source comments. Keep them stable.

---

<a id="container-format"></a>
## 1. Container format

The bundle ships as a **directory tree** rooted at `incident-<ulid>/`
(`incident-unsigned-<ulid>/` for dev-unsigned bundles). Recipients can
pack and unpack it with any tool that handles directories. Integrity is
established by cryptographic primitives over the bundle's *contents*
(per-event `payloadHash`, the IRONROOT chain `rootHash`, the signed
[files map](#files-map), the manifest signature), not by container
metadata, so the in-flight container is the recipient's choice.

If reproducible byte-identical *archives* matter for your workflow, pack
after produce with GNU tar (>= 1.28):

```bash
producedAt=$(jq -r .producedAt incident-<id>/manifest.json)
tar --sort=name \
    --mtime="$producedAt" \
    --owner=0 --group=0 --numeric-owner \
    --format=ustar \
    -cf bundle.tar incident-<id>/
```

`--format=ustar` avoids PAX extended headers, whose sub-second mtimes
defeat reproducibility across hosts. macOS BSD tar does not accept
these flags; use `gtar` from Homebrew.

---

<a id="directory-layout"></a>
## 2. Directory layout

```
incident-<ulid>/
  manifest.json                         # Entry point. Schema version, hashes, files map, counts.
  events.jsonl                          # One Event JSON per line, sorted by id (ULID).
  raw/
    claude-code/<session>.jsonl          # Verbatim Claude Code session transcript.
    shell-history/shell-history.txt     # Shell history at capture time, when supplied.
    git-reflog.txt                       # Git reflog at capture time, when supplied.
    captures/<event-id>.json            # Capture records behind capture-derived events.
  artifacts/
    files-pre/<sha256>/<original-basename>   # File snapshots before destructive ops.
    files-post/<sha256>/<original-basename>  # File snapshots after destructive ops.
  attestations/
    signatures.json                     # The manifest's signature blocks, verbatim.
    rfc3161-timestamps/<index>.tsr      # RFC 3161 tokens, one per manifest.timestamps[].
  rules/
    destructive.yaml                    # Exact ruleset used; hash in manifest.
  narrative.md                          # Deterministic template-rendered narrative.
  narrative.html                        # HTML render of the same narrative.
  verify.txt                            # Plain-English instructions for the recipient.
```

Directories that would be empty are not created, except
`attestations/rfc3161-timestamps/`, which always exists.

### 2.1 Path conventions

- **Top-level directory name**: `incident-<ulid>` where `<ulid>` is the
  bundle's ULID (same as `manifest.bundleId`).
- **File basenames in artifacts**: preserved as `<original-basename>`;
  the SHA-256 subdirectory prevents collisions and ties the file to its
  content hash.
- **Capture records**: named by the event id they produced, so a
  recipient can go from an `events.jsonl` row to its source record. This
  includes `capture_failed` records, whose event id is the id of the
  `gap` event they became (see [gap events](#gap-events)).
- **No symlinks.** A bundle must not contain symlinks or any non-regular
  file. The verifier fails the `files-map` check on sight of one.

---

<a id="deterministic-ordering"></a>
## 3. Deterministic ordering

`events.jsonl` is byte-pinned by `manifest.eventsJsonlSha256` and event
order inside it is sorted by event id (ULID); that is what the verifier
replays. Every other file is pinned by the [files map](#files-map), so
no file in the bundle is order-sensitive to verification.

### 3.1 events.jsonl ordering

Events within `events.jsonl` MUST be in ascending `id` order (ULID,
byte-wise). ULIDs encode a millisecond timestamp in their first 48 bits,
so this order is also chronological within a session. The chain is
computed over the file in that order; the producer refuses to seal an
unsorted list and the verifier rejects an unsorted file with
`events.jsonl is not sorted by id` rather than re-sorting it. Re-sorting
would let a file that reads one way on disk replay to a root sealed over
another.

---

<a id="signed-content"></a>
## 4. Signed vs. unsigned content

### 4.1 Signed content

The **root hash** is the terminal hash of the IRONROOT hash chain over
`events.jsonl`. It transitively covers every event's payload, metadata,
and chain linkage. `rootHash`, `eventsJsonlSha256`, `rulesetHash`, and
the `files` map are embedded in `manifest.json`, and `manifest.json` is
what the signature covers.

The signed trust path is:

```
events.jsonl  -->  per-event payloadHash (recomputed from payload bytes)
              -->  IRONROOT chain  -->  rootHash
              -->  manifest.eventsJsonlSha256 (over the literal file bytes)
every other file  -->  manifest.files[path] = { sha256, bytes }
              -->  manifest.json  -->  signature  -->  RFC 3161 token
```

Therefore the following content is signed (tampering invalidates
verification):

- `events.jsonl`, every byte, authenticated two ways: the verifier
  re-canonicalizes each `payload` and compares the SHA-256 to the stored
  `payloadHash`, then replays the chain to `rootHash`; and it re-hashes
  the whole file against `manifest.eventsJsonlSha256`.
- `manifest.json`: root hash, counts, ruleset hash, events.jsonl hash,
  files map, session metadata.
- `rules/destructive.yaml`, via `manifest.rulesetHash`.
- `raw/**`, `artifacts/**`, `narrative.md`, `narrative.html`,
  `verify.txt`, and any other file in the tree, via the files map.

### 4.2 Bound by content equality rather than the files map

Three paths cannot be hashed into the manifest because they are derived
from the finished manifest:

- `manifest.json` itself is covered by the signature.
- `attestations/signatures.json` must carry exactly the blocks in
  `manifest.signatures`.
- `attestations/rfc3161-timestamps/<i>.tsr` must be the byte decoding of
  `manifest.timestamps[i].tokenBase64`, and each token commits to
  SHA-256 of the unsigned manifest through `TSTInfo.messageImprint`.

The `attestation-files` check enforces both equalities, so a deleted,
swapped, or added attestation file fails verification.

### 4.3 Integrity-pinned but non-evidentiary

The narrative and `verify.txt` are pinned by the files map, so a
modified copy is detected, but they are **derived** prose, not evidence.
The canonical record is `events.jsonl` and the verifier's own report.
`commentary.md` from `depose explain` is written *beside* a sealed
bundle (`<bundle>-commentary.md`), never inside it, because a file added
to the tree after sealing fails the files map.

<a id="verifier-checks"></a>
### 4.4 Verifier behavior

Every check reports one of four statuses. A skipped or warned check is
never rendered as PASS:

| Status | Meaning |
|---|---|
| `PASS` | The check ran and the bundle satisfied it. |
| `FAIL` | The check ran and the bundle did not. The run fails. |
| `SKIPPED` | The check did not run, by mode contract or missing input. |
| `WARN` | The check ran; the bundle is weaker than current producers emit but not invalid (a downgrade, not a tamper). |

The verifier is one function per check
(`apps/verify/cmd/check_*.go`) run by a driver in the order below. The
run stops early only after a failure that makes the rest meaningless:
an unparseable manifest, an unsupported schema, an unrecognized mode, or
an invalid signature. Any other failure is recorded and the remaining
checks still run, so the report names every defect. When the run stops
early a final `remaining-checks: SKIPPED` line says why.

The `depose-verify` binary checks, in order:

1. **manifest-parse**: `manifest.json` parses. Failure stops the run.
2. **schema-version**: `schemaVersion` is within the supported range
   (see [versioning](#versioning)). Failure stops the run.
3. **mode-declaration**, **mode-contract**: `producer.mode` is `signed`
   or `dev-unsigned` and the presence of signatures and timestamps
   matches the declared mode.
4. **key-fingerprint-pin** (when `--expected-key-fingerprint` is given),
   **revocation-list** (when `--revocation-list` is given),
   **signer-identity** (when `--signer-identity` is given; SKIPPED until
   a Sigstore signature exists to bind it to).
5. **signature-verify**: the Ed25519 signature in `manifest.signatures[]`
   verifies against the canonical bytes of `manifest.json` with
   `signatures=[]` and `timestamps=[]`. SKIPPED in dev-unsigned mode.
6. **payload-hash**, **chain-replay**: every event's `payload`
   canonicalizes (RFC 8785 JCS) to its `payloadHash`, the file is in
   ascending id order, every `monoNs` is a decimal string (schema 3),
   and the replayed chain ends at `manifest.rootHash`. SKIPPED in
   dev-unsigned mode when `rootHash` is empty.
7. **timestamp-verify**, **timestamp-backdating**: each RFC 3161 token
   is strictly well-formed DER (definite lengths, minimal length
   encoding, no trailing bytes), parses, uses SHA-256, commits to SHA-256
   of the unsigned manifest, and carries a valid TSA signature chaining
   to the embedded FreeTSA root or the system pool; `manifest.producedAt`
   is not after any token's time (1 s tolerance for whole-second TSAs).
   SKIPPED in dev-unsigned mode.
8. **artifact-events-jsonl**: SHA-256 of the literal `events.jsonl`
   bytes equals `manifest.eventsJsonlSha256`.
9. **ruleset-integrity**: SHA-256 of `rules/destructive.yaml` equals
   `manifest.rulesetHash`.
10. **files-map**: the tree matches `manifest.files` exactly (see
    [files map](#files-map)). WARN on schemaVersion 2 bundles, which
    predate the map.
11. **attestation-files**: `attestations/signatures.json` and every
    `.tsr` match the manifest (see 4.2).
12. **bundle-completeness**: `manifest.json`, `events.jsonl`,
    `attestations/signatures.json`, `rules/destructive.yaml`, and
    `verify.txt` are present.
13. **rekor-verify**: SKIPPED; Rekor entries are not verified offline.

In `signed` mode any FAIL produces `RESULT: FAIL` and a non-zero exit.
A `dev-unsigned` bundle never prints plain `PASS`; it prints
`PASS (dev-unsigned, not evidence)`.

---

<a id="files-map"></a>
## 5. Files map

`manifest.files` pins every file in the bundle tree except the three
paths in 4.2. It is computed by the producer **after every other file is
on disk** and **before** the manifest is signed, so the signature and
the RFC 3161 token both cover it.

### 5.1 Field layout

```ts
files: {
  [relativePath: string]: {
    sha256: string;   // lowercase hex SHA-256 of the file's bytes
    bytes: number;    // byte length of the file
  }
}
```

Keys are paths relative to the bundle root using forward slashes, with
no leading `./` or `/`, no empty segments, and no `.` or `..` segments.
A key that violates this fails verification regardless of what is on
disk. Canonical JSON (JCS) sorts the keys; producers emit them in the
walk order below, which is the same order.

### 5.2 Excluded paths

```
manifest.json
attestations/signatures.json
attestations/rfc3161-timestamps/*
```

A files map that lists any of these is invalid.

### 5.3 Normative walk order

Depth-first over the tree starting at the bundle root. Within each
directory, entries are visited in byte-wise lexicographic order of their
UTF-8 names. Directories are descended into when reached in that order;
they contribute no entries of their own. Empty directories are ignored.
A symlink or any non-regular file anywhere in the tree is an error.

The resulting key order equals byte-wise lexicographic order of the full
relative paths, which is also the JCS key order in the manifest.

### 5.4 Verifier behavior

The verifier walks the tree with the same rules and fails `files-map`
when:

- any path is on disk but absent from the map (a file was added),
- any path is in the map but absent from disk (a file was deleted),
- any `sha256` or `bytes` disagrees with the file on disk,
- any symlink or non-regular file exists anywhere in the tree,
- any key is unsafe (5.1) or excluded (5.2).

On a `schemaVersion: 2` bundle, which has no `files` field, the check
reports WARN and names what is therefore not integrity-covered.

---

<a id="manifest-schema"></a>
## 6. Manifest schema

```ts
interface Manifest {
  /**
   * 3: adds the signed `files` map.
   * 2: added producer.host.nodeVersion, producer.host.kernel, session.host.
   */
  schemaVersion: 3;
  bundleId: string;                // ULID, matches directory name
  producedAt: string;              // ISO 8601 UTC
  producer: {
    tool: "depose";
    version: string;               // semver of the producing CLI
    mode: "signed" | "dev-unsigned";
    keyFingerprint?: string;       // SHA-256 of the signing key's SPKI DER (signed mode)
    host: {
      os: string;
      arch: string;
      nodeVersion: string;         // Node.js runtime version (e.g. "v20.19.0")
      kernel: string;              // OS kernel release from os.release()
    };
  };
  session: {
    agentId: string;
    sessionId: string;
    startedAt: string;
    endedAt: string;
    host: {
      os: string | null;
      arch: string | null;
      nodeVersion: string | null;
      kernel: string | null;
    } | null;
  };
  rootHash: string;                // Terminal chain hash over events.jsonl
  eventsJsonlSha256: string;       // SHA-256 of the literal events.jsonl bytes
  files: Record<string, { sha256: string; bytes: number }>;  // see §5
  signatures: SignatureBlock[];
  timestamps: Rfc3161Token[];
  rekor?: RekorEntry[];
  counts: {
    events: number;
    destructiveOperations: number;
    gaps: number;
    artifactsPre: number;
    artifactsPost: number;
    capturesAttributed: number;
    capturesExcluded: number;
  };
  rulesetHash: string;            // SHA-256 of rules/destructive.yaml
}
```

Full TypeScript definitions for `SignatureBlock`, `Rfc3161Token`, and
`RekorEntry` are in `packages/bundle/src/manifest.ts`. The Go verifier
mirrors them in `apps/verify/manifest/manifest.go`.

### 6.1 Signing procedure

1. Build the manifest with `signatures: []` and `timestamps: []` and
   the final `files` map.
2. Serialize with RFC 8785 JCS. Sign the bytes with Ed25519 (pure, no
   pre-hash). Put the signature block in `manifest.signatures`.
3. Serialize the manifest again with `signatures: []` and
   `timestamps: []` (identical bytes to step 2), SHA-256 it, and send
   that digest to the TSA. Put the token in `manifest.timestamps`.
4. Write `manifest.json` (JCS), `attestations/signatures.json`, and the
   `.tsr` files.

---

<a id="event-schema"></a>
## 7. Event schema (events.jsonl)

Each line is a canonical-JSON serialized `Event` object. Fields:

| Field            | Type                     | Description                                  |
|------------------|--------------------------|----------------------------------------------|
| `id`             | string (ULID)            | Sortable unique identifier                   |
| `wallTs`         | string (ISO 8601 UTC)    | Wall-clock timestamp                         |
| `monoNs`         | string (decimal integer) | Monotonic nanoseconds since session start. A decimal string on the wire (`"9007199254740993"`), a 64-bit integer in memory; JSON numbers lose precision past 2^53. Schema 2 wrote a number; the verifier accepts that form only for schema 2 bundles. |
| `sessionId`      | string                   | Session identifier                           |
| `agentId`        | string enum              | `claude-code`, `codex`, `cursor`, `shell`, `unknown` |
| `parentEventId`  | string \| null           | Causal parent in the event graph             |
| `type`           | string enum              | Event type (below)                           |
| `payload`        | object (discriminated)   | Type-specific data                           |
| `payloadHash`    | string (SHA-256)         | Hash of canonical JSON of payload            |
| `correlation`    | object (optional)        | Cross-links set by the merger; not hashed    |
| `chainHash`      | string (optional)        | Hash chain link; populated by chain pass     |

Event types: `prompt`, `assistant_message`, `tool_call_intent`,
`tool_call_executed`, `tool_result`, `file_diff`, `shell_command_pre`,
`shell_command_post`, `env_change`, `process_spawn`, `error`, `gap`,
`capture_failed`. Payload shapes are in
`packages/core/src/events/payloads.ts`. `capture_failed` events exist
only in the capture store; the merger replaces each with a `gap` event
before anything reaches a bundle.

<a id="hash-chain"></a>
### 7.1 Hash chain

```
chainHash[0] = SHA-256( zero32 || payloadHash[0] || eventMetadata[0] )
chainHash[i] = SHA-256( chainHash[i-1] || payloadHash[i] || eventMetadata[i] )
rootHash     = chainHash[N-1]
```

`payloadHash` is fed as its UTF-8 hex string, not decoded bytes.
`eventMetadata` is the JCS serialization of
`{ id, wallTs, monoNs, sessionId, agentId, parentEventId, type, payloadHash }`
with `monoNs` in its wire form (a decimal string). `payloadHash` appears
both standalone and inside the metadata; that is intentional. Events are
chained in `id` order.

Shared vectors: `tests/conformance/hash-chain-vectors.json` (per-event
chain hashes and roots, including monoNs above 2^53 and an unsorted
input that must be rejected) and `tests/conformance/manifest-vectors.json`
(files maps over given trees, unsigned canonical manifests, and their
hashes). Both the TypeScript producer and the Go verifier run them.

<a id="gap-events"></a>
### 7.2 Gap events

A `gap` event is the system's accounting of what it could not observe.
`payload.reason` is one of:

| Reason | Emitted when |
|---|---|
| `tool_result_without_pre_capture` | A tool result has no matching pre-execution capture. |
| `pre_capture_without_tool_result` | A capture record has no matching tool result. |
| `shell_history_without_jsonl_correlation` | A shell-history entry correlates to nothing in the session. |
| `reflog_change_without_command` | A reflog change has no observed command. |
| `jsonl_line_unparseable` | A session log line could not be parsed. |
| `unknown_jsonl_line_type` | A session log line has an unrecognized type. |
| `capture_failed` | The capture hook threw and wrote no record. The gap's `id` is the failure record's ULID; its `detail` names the hook phase, error class, and sanitized message. |

---

<a id="producer-invariants"></a>
### 7.3 Producer invariants

- **Never silently drop data.** A session-log line that cannot be parsed
  or recognized becomes a `gap` event; a capture that could not be taken
  becomes a `capture_failed` record and then a `gap`. The count of gaps
  is in the signed manifest.
- **Capture records are written with mode 0600** into a 0700 directory.
- **Only allowlisted environment variables are stored in plaintext**;
  the full environment is SHA-256 hashed. See `docs/threat-model.md` §4.
- **No LLM in the signed path.** Narrative and commentary are templated
  from signed events.

<a id="destructive-ruleset"></a>
## 8. Destructive ruleset

`rules/destructive.yaml`:

```yaml
version: 1
rules:
  - id: terraform-destroy
    matcher:
      argvHead: ["terraform", "destroy"]
    severity: critical
```

Matcher criteria (all defined criteria must match):

| Criterion | Semantics |
|---|---|
| `argvHead` | Case-insensitive exact match of the leading argv tokens. |
| `argvContainsAny` | Some argv token contains one of the strings (case-sensitive). |
| `anyArgvRegex` | Some argv token matches the regex (PCRE-style leading `(?i)` etc. honoured). |
| `stdinRegex` | The simple command's full text matches the regex (stdin itself is not captured). |

Severity is `critical`, `high`, `medium`, or `low`.

<a id="destructive-rule-matching"></a>
### 8.1 Destructive rule matching

Rules match **simple commands**, not the recorded argv verbatim. The
Claude PreToolUse hook records a Bash tool call as
`["bash", "-c", "<command>"]`; a `tool_call_intent` from the session log
carries the raw command string. Both are expanded the same way:

1. If argv is `<shell> [flags] -c <string>`, the string is parsed as a
   shell command list. `sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, and
   `ash` count as shells, by basename; `-lc` and `-ec` count as `-c`.
2. The list is split into simple commands on `&&`, `||`, `|`, `|&`,
   `;`, `&`, and newlines, honouring single quotes, double quotes,
   backslash escapes, comments, heredocs, and redirections (which are
   removed along with their targets). Subshells `( ... )`, `$( ... )`,
   and backticks are recursed into and their commands emitted in source
   order.
3. Each simple command has leading `VAR=value` assignments and these
   wrappers stripped, repeatedly, with the flags each takes: `sudo`,
   `doas`, `env`, `nice`, `time`, `nohup`, `command` (not `command -v`),
   `exec`, `timeout`, `xargs`, `builtin`. A wrapped `<shell> -c` is
   expanded per step 1.
4. Every rule is tested against every simple command. A rule fires if
   any simple command satisfies all of its criteria. The match records
   `simpleCommandIndex` (zero-based, source order across the whole
   compound command), `simpleCommand` (the argv after stripping),
   `simpleCommandCount`, and `strippedWrappers`.

The narrative renders the matched simple command with its position
(`command 2 of 3`) and the wrappers it was reached through.

---

<a id="signature-schemes"></a>
## 9. Signature schemes

### 9.1 Ed25519

- Local keypair stored at `~/.depose/keys/signing.key` (0600).
- Public key embedded in the `SignatureBlock` as PEM.
- Signature is over the JCS bytes of the unsigned manifest (§6.1).

### 9.2 Sigstore Fulcio

Not implemented. `SignatureBlock.scheme` reserves the value
`sigstore-fulcio`; the verifier rejects any block that is not `ed25519`.

---

<a id="versioning"></a>
## 10. Versioning

- `manifest.schemaVersion` is `3`.
- **Verifier compatibility policy.** A verifier with code-level
  `SupportedSchemaMax = N` supports the range `[N-1, N]`; today that is
  `[2, 3]`. Bundles outside that range are rejected with
  `unsupported schemaVersion` and a non-zero exit; the verifier does not
  attempt to parse a future schema's manifest.
- A `schemaVersion: 2` bundle has no files map; the `files-map` check
  reports WARN rather than FAIL for it.
- New event types and payload fields are additive within a schema
  version; they do not break verifiers that ignore unknown fields.
- Breaking changes (field removal, semantic alteration) require a schema
  version bump and a new verifier code path.
- `producer.version` (semver) identifies the producing CLI.

---

<a id="security-considerations"></a>
## 11. Security considerations

- The bundle does **not** encrypt its contents. If confidentiality is
  required, encrypt at the transport layer (age, GPG, S3 SSE).
- `manifest.producer.host` reveals the OS, architecture, Node.js
  version, and kernel release of the producing machine.
  `manifest.session.host` reveals the same for the capture environment
  (nullable). This aids verification of the capture environment and does
  not expose the hostname or IP.
- Full environment variables are never stored, only an allowlisted
  subset and a SHA-256 of the full environment.
- File content capture defaults to hash-only.
- A `capture_failed` record carries the first line of the error message
  with control characters removed and the home directory replaced by
  `~`. It never carries a stack trace.

See `docs/threat-model.md` for the complete security analysis.
