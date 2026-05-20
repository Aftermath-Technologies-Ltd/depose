# DEPOSE Bundle Format (.depo)

A DEPOSE bundle is the core product of DEPOSE: a directory tree
containing a complete, verifiable evidence record of an AI coding
agent session. This document specifies every aspect of the format so
any third party — including the standalone `depose-verify` binary —
can parse, validate, and reason about the bundle without any DEPOSE
infrastructure.

---

## 1. Container format

The bundle today ships as a **directory tree** rooted at
`incident-<ulid>/`. Recipients can pack and unpack it with any tool
that handles directories (e.g. `tar -cf` for transport). Integrity is
established by cryptographic primitives over the bundle's *contents*
(per-event payloadHash, IRONROOT chain rootHash, manifest signature,
`manifest.eventsJsonlSha256`, `manifest.rulesetHash`), not by tar
metadata, so the in-flight container is the recipient's choice.

> **Note on container determinism.** Earlier drafts of this document
> specified a deterministic POSIX USTAR archive (fixed mtime, uid/gid
> 0, no PAX headers, lexicographic ordering). The producer does not
> ship that container yet — `writer.ts` writes a directory tree. If
> reproducible byte-identical *archives* matter for your workflow,
> pack with `tar --sort=name --mtime="$(jq -r .producedAt manifest.json)"
> --owner=0 --group=0 --numeric-owner --pax-option=exthdr.name=%d/PaxHeaders/%f
> -cf bundle.tar incident-<id>/` after produce. A canonical tar
> packer in the producer is tracked as future work.

---

## 2. Directory layout

```
incident-<ulid>/
  manifest.json                         # Entry point. Schema version, hashes, counts.
  events.jsonl                          # One Event JSON per line, sorted by id (ULID).
  raw/
    claude-code/<session>.jsonl          # Verbatim Claude Code session transcript.
    shell-history/<host>.txt            # Shell history at capture time.
    git-reflog.txt                       # Git reflog at capture time.
    capture/<event-id>.json             # Pre-execution capture records.
  artifacts/
    files-pre/<sha256>/<original-basename>   # File snapshots before destructive ops.
    files-post/<sha256>/<original-basename>  # File snapshots after destructive ops.
  attestations/
    signatures.json                     # One or more signature blocks.
    rfc3161-timestamps/<index>.tsr      # RFC 3161 timestamp tokens.
    rekor-entries.json                  # Optional Rekor transparency log entries.
  rules/
    destructive.yaml                    # Exact ruleset used; hash in manifest.
  narrative.md                          # Deterministic template-rendered narrative.
  narrative.html                        # HTML render of the same narrative.
  verify.txt                            # Plain-English instructions for the recipient.
```

### 2.1 Path conventions

- **Top-level directory name**: `incident-<ulid>` where `<ulid>` is the bundle's ULID
  (same as `manifest.bundleId`). This provides a human-readable timestamp prefix
  and global uniqueness.
- **File basenames in artifacts**: Preserved as `<original-basename>` to maintain
  readability. The SHA-256 subdirectory prevents name collisions and ties the file
  to its content hash.
- **Capture records**: Named by the event ID they correspond to, facilitating
  direct correlation from `events.jsonl` entries.

---

## 3. Deterministic ordering

`events.jsonl` is byte-pinned by `manifest.eventsJsonlSha256` and
event order inside it is sorted by event id (ULID) — that's what the
verifier replays. Other files in the bundle are not order-sensitive
to verification; their integrity flows through the per-event chain
(`payloadHash` of payloads that reference artifact hashes) or via
`manifest.rulesetHash`.

If you want a byte-identical *archive* across rebuilds, see the
note in §1 about packing with deterministic tar flags after produce.
The order described below is the order a deterministic tar packer
would use and the order future producer-side tar support will emit.

### 3.1 Ordering rules (recommended for archival packers)

1. Directory entries precede their children.
2. Within a directory, entries are sorted by full path (e.g., `artifacts/files-pre/...`
   comes before `artifacts/files-post/...` because `files-pre` < `files-post`).
3. `manifest.json` is the first file entry (its path sorts first).
4. `events.jsonl` follows immediately after `manifest.json`.
5. `raw/...` entries follow `events.jsonl`.
6. `artifacts/...` entries follow all `raw/...` entries.
7. `attestations/...` entries follow all `artifacts/...` entries.
8. `rules/...` follows `attestations/...`.
9. `narrative.md`, `narrative.html`, `verify.txt` are last, sorted lexicographically.

### 3.2 events.jsonl ordering

Events within `events.jsonl` are sorted by their `id` field (ULID). Since ULIDs
encode a timestamp in their first 48 bits, this sort is also chronological within
a session. Events from different sessions in the same bundle share the same sort
key space; cross-session ordering follows ULID comparison.

---

## 4. Signed vs. unsigned content

Not everything in the bundle is covered by the integrity signature. This section
defines precisely what is signed, what is unsigned, and why.

### 4.1 Signed content (covered by `rootHash`)

The **root hash** is the terminal hash of the IRONROOT-style hash chain over
`events.jsonl`. It transitively covers every event's payload, metadata, and
chain linkage. The `rootHash` is embedded in `manifest.json`, and `manifest.json`
is what the signature covers.

The signed trust path is:

```
events.jsonl  -->  per-event payloadHash (recomputed from payload bytes)
              -->  IRONROOT chain  -->  rootHash
              -->  manifest.eventsJsonlSha256 (over the literal file bytes)
              -->  manifest.json
              -->  signature
```

Therefore, the following content is **signed** (tampering invalidates verification):

- `events.jsonl` — every byte. Authenticated two independent ways:
  (1) the verifier re-canonicalizes each event's `payload` and SHA-256s
  it to confirm the stored `payloadHash` matches, then replays the
  IRONROOT chain to confirm `rootHash`; (2) the verifier re-hashes
  the whole file and compares to `manifest.eventsJsonlSha256`. Both
  must pass.
- `manifest.json` — root hash, counts, ruleset hash, events.jsonl
  hash, session metadata.
- `rules/destructive.yaml` — indirectly, because its SHA-256 is stored
  as `manifest.rulesetHash`. Changing the rules without updating the
  manifest breaks verification.

### 4.2 Unsigned but integrity-checked content

- `raw/...` — verbatim source data. Not directly signed, but the normalizer
  produced the signed `events.jsonl` from this data. If a raw source file is
  modified, it does not invalidate the bundle, but a reviewer could detect
  the inconsistency by re-normalizing the raw data and comparing against
  `events.jsonl`.
- `artifacts/...` — file snapshots. Their content hashes appear in the signed
  event payloads (via `fileArgs.preSha256` / `fileArgs.postSha256` fields in
  `ShellCommandPrePayload`). If an artifact file is modified, the verifier
  checks its SHA-256 against the event payload and flags a mismatch.
- `attestations/signatures.json` — contains the signature over `manifest.json`.
  Not self-signed, but verified by the verifier using the embedded public key
  or Fulcio certificate.

### 4.3 Unsigned and non-evidentiary content

The following files are **explicitly excluded** from the signed trust path and
are **not evidence**:

- `narrative.md` — template-rendered prose. Deterministic, but derived from
  `events.jsonl` (which is signed). Modifying it does not invalidate the bundle.
- `narrative.html` — same as above, HTML render.
- `verify.txt` — human-readable instructions. Not integrity-checked.
- `commentary.md` (if present) — AI-generated postmortem produced by
  `depose explain`. Explicitly labeled "AI-GENERATED COMMENTARY — NOT EVIDENCE."
  Excluded from `events.jsonl`, excluded from `rootHash`, and ignored by the
  verifier entirely.

### 4.4 Verifier behavior

The `depose-verify` binary checks, in order:

1. **manifest-parse / schema-version / mode-declaration / mode-contract**:
   `manifest.json` parses, `schemaVersion` is in the supported range,
   and `producer.mode` (`signed` or `dev-unsigned`) is consistent with
   the presence of signatures and timestamps.
2. **signature-verify**: Ed25519 signature in
   `attestations/signatures.json` (also embedded in `manifest.signatures[]`)
   verifies against the bytes of `manifest.json` with `signatures=[]`
   and `timestamps=[]`.
3. **payload-hash**: For every event in `events.jsonl`, the verifier
   canonicalizes `payload` (RFC 8785 JCS) and SHA-256s the bytes; the
   result must equal the stored `payloadHash`. Detects payload-string
   rewrites that leave the hash field untouched.
4. **chain-replay**: Replay the IRONROOT hash chain over the events,
   sorted by ULID id; the terminal hash must equal `manifest.rootHash`.
   Detects any mutation to `payloadHash`, `chainHash`, or chained
   metadata fields.
5. **timestamp-verify**: For each RFC 3161 token, ASN.1-parse the
   TimeStampToken, enforce `hashAlgorithm = SHA-256`, compare
   `TSTInfo.HashedMessage` to SHA-256 of the unsigned manifest, and
   verify the embedded TSA's PKCS7 signature + cert chain against
   the embedded FreeTSA root + system pool.
6. **timestamp-backdating**: `manifest.producedAt` must not be after
   any TSA token's reported time (with a 1-second tolerance for
   whole-second TSA truncation).
7. **artifact-events-jsonl**: SHA-256 of the on-disk `events.jsonl`
   bytes must equal `manifest.eventsJsonlSha256`. Detects line
   reordering, whitespace insertion, or any byte-level mutation that
   would not otherwise show up in the per-event chain.
8. **ruleset-integrity**: SHA-256 of `rules/destructive.yaml` must
   equal `manifest.rulesetHash`.
9. **bundle-completeness**: All required files
   (`manifest.json`, `events.jsonl`,
   `attestations/signatures.json`, `rules/destructive.yaml`,
   `verify.txt`) are present.

In `signed` mode any failure produces `RESULT: FAIL` and a non-zero
exit. In `dev-unsigned` mode signature and timestamp checks are
skipped by mode-contract; chain replay and payload-hash still apply.

---

## 5. Manifest schema

The `manifest.json` file is the entry point for the bundle. Its schema:

```ts
interface Manifest {
  /**
   * Schema version 2 adds producer.host.nodeVersion, producer.host.kernel
   * (from os.release()), and session.host. v1 manifests (schemaVersion=1)
   * used producer.host.kernel for the Node.js version; verifiers should
   * interpret that field as nodeVersion when schemaVersion=1.
   */
  schemaVersion: 2;
  bundleId: string;                // ULID — matches directory name
  producedAt: string;              // ISO 8601 UTC
  producer: {
    tool: "depose";
    version: string;               // semver of the producing CLI
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
    host?: {
      os: string | null;
      arch: string | null;
      nodeVersion: string | null;
      kernel: string | null;
    };
  };
  rootHash: string;                // Terminal chain hash over events.jsonl
  eventsJsonlSha256: string;       // SHA-256 of the literal events.jsonl bytes
  signatures: SignatureBlock[];
  timestamps: Rfc3161Token[];
  rekor?: RekorEntry[];
  counts: {
    events: number;
    destructiveOperations: number;
    gaps: number;
    artifactsPre: number;
    artifactsPost: number;
  };
  rulesetHash: string;            // SHA-256 of rules/destructive.yaml
}
```

Full TypeScript definitions for `SignatureBlock`, `Rfc3161Token`, and `RekorEntry`
are in `packages/bundle/src/manifest.ts`.

---

## 6. Event schema (events.jsonl)

Each line is a canonical-JSON serialized `Event` object. Fields:

| Field            | Type                     | Description                                  |
|------------------|--------------------------|----------------------------------------------|
| `id`             | string (ULID)            | Sortable unique identifier                   |
| `wallTs`         | string (ISO 8601 UTC)    | Wall-clock timestamp                         |
| `monoNs`         | number                   | Monotonic nanoseconds since session start    |
| `sessionId`      | string                   | Session identifier                           |
| `agentId`        | string enum              | Agent that produced this event               |
| `parentEventId`  | string \| null           | Causal parent in the event graph             |
| `type`           | string enum              | Event type (see EventType union)            |
| `payload`        | unknown (discriminated)  | Type-specific data                           |
| `payloadHash`    | string (SHA-256)         | Hash of canonical JSON of payload            |
| `chainHash`      | string (optional)        | Hash chain link; populated by chain pass     |

Canonical JSON serialization follows RFC 8785 JSON Canonicalization Scheme (JCS).
This ensures deterministic hashing across JavaScript runtimes and the Go verifier.

---

## 7. Signature schemes

### 7.1 Ed25519 (default)

- Local keypair stored at `~/.depose/keys/signing.key` (0600 permissions).
- Public key embedded in the `SignatureBlock` as PEM.
- Signature is over the canonical JSON of `manifest.json`.

### 7.2 Sigstore Fulcio (opt-in)

- Activated when `SIGSTORE_OIDC=1` or a CI environment with OIDC is detected.
- Keyless signing via Fulcio; X.509 certificate embedded in the `SignatureBlock`.
- No local key material required.
- Identity bound to OIDC provider (GitHub Actions, Google, etc.).

Both schemes can coexist in a single bundle's `signatures` array, providing
flexibility for multi-party attestation.

---

## 8. Versioning

- `manifest.schemaVersion` is `2`. v1 bundles (schemaVersion=1) are still
  accepted by the verifier, but `producer.host.kernel` in v1 bundles held the
  Node.js version rather than the OS kernel release; interpret it as
  `nodeVersion` when processing v1 manifests.
- **Verifier compatibility policy.** A verifier with code-level
  `SupportedSchemaMax = N` supports the range `[N-1, N]`. Bundles
  with `schemaVersion` outside that range are rejected with
  `unsupported schemaVersion` and a non-zero exit code; the verifier
  does not attempt to parse a future schema's manifest, since silent
  best-effort parsing of an evolved schema is how integrity bugs
  get shipped.
- Bumping `schemaVersion` from `N` to `N+1` requires a new verifier
  release that raises both `SupportedSchemaMin` (to `N`) and
  `SupportedSchemaMax` (to `N+1`). Once a verifier with
  `SupportedSchemaMax = N+1` exists, older verifiers still verify
  `schemaVersion = N` bundles by design.
- New event types and new payload fields are **additive** within a
  schema version — they do not break existing verifiers that ignore
  unknown fields.
- Breaking changes (field removal, semantic alteration) require a
  major schema version bump and a new verifier code path.
- The `producer.version` field (semver) identifies the specific
  `depose` CLI that produced the bundle, enabling per-version
  behavior if needed.

---

## 9. Security considerations

- The bundle does **not** encrypt its contents. If confidentiality is required,
  encrypt the `.depo` file at the transport layer (e.g., age, GPG, S3 SSE).
- `manifest.producer.host` reveals the OS, architecture, Node.js version, and
  kernel release of the producing machine. In v1 (schemaVersion=1) bundles,
  the `kernel` field held the Node.js version instead of the OS kernel; this
  was corrected in v2. `manifest.session.host` reveals the same information
  for the session capture environment (nullable when unknown).
  This is intentional: it aids verification of the
  capture environment and does not expose the hostname or IP.
- Full environment variables are never stored — only an allowlisted subset and
  a SHA-256 hash of the full environment for tamper-evidence.
- File content capture defaults to hash-only; full content storage requires
  explicit user opt-in and is limited to files under 1 MB.

See `docs/threat-model.md` for a complete security analysis.