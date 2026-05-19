# DEPOSE Bundle Format (.depo)

The `.depo` file is the core product of DEPOSE. It is a deterministically-ordered tarball
containing a complete, verifiable evidence bundle from an AI coding agent session. This
document specifies every aspect of the format so that any third party — including the
standalone `depose-verify` binary — can parse, validate, and reason about the bundle
without any DEPOSE infrastructure.

---

## 1. Container format

The `.depo` file is a **POSIX tar archive** (USTAR format) with the following constraints:

| Property        | Value                              | Rationale                              |
|-----------------|------------------------------------|----------------------------------------|
| Format          | USTAR (no PAX headers)             | Deterministic; avoids variable xattrs  |
| uid / gid       | 0 / 0                              | Removes host-specific identity leakage  |
| File mode       | 0644 (files), 0755 (directories)   | Uniform; no permission surprises        |
| mtime           | Fixed to `manifest.producedAt`     | Deterministic across rebuilds           |
| Extended attrs  | None                               | Eliminates non-portable metadata        |
| Compression     | None (not gzip, not zstd)          | Deterministic byte output; verifier     |
|                 |                                    | needs only stdlib tar                   |

No compression is applied. The bundle may be large; recipients who want compression
can apply it externally. The archive must be byte-identical when re-produced from the
same inputs with the same fixed clock (modulo non-deterministic signature bytes).

---

## 2. Directory layout

```
incident-<ulid>.depo/
  manifest.json                         # Entry point. Schema version, hashes, counts.
  events.jsonl                          # One Event JSON per line, sorted by id (ULID).
  raw/
    claude-code/<session>.jsonl          # Verbatim Claude Code session transcript.
    codex/<session>.json                 # Verbatim Codex session data.
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

All files in the tar archive appear in **lexicographic order by path** (full path,
using `/` as separator, compared byte-by-byte). Directories appear before their
contents.

This ordering is critical: it ensures that two runs of `depose package` with the
same inputs and the same fixed clock produce byte-identical tar streams (excluding
signature bytes, which are non-deterministic by design).

### 3.1 Ordering rules

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
events.jsonl  -->  hash chain  -->  rootHash  -->  manifest.json  -->  signature
```

Therefore, the following content is **signed** (tampering invalidates the signature):

- `events.jsonl` — every event, its payload hash, metadata, and chain linkage.
- `manifest.json` — root hash, counts, ruleset hash, session metadata.
- `rules/destructive.yaml` — indirectly, because its SHA-256 is stored as
  `manifest.rulesetHash`. Changing the rules without updating the manifest
  breaks verification.

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

The `depose-verify` binary checks:

1. **Chain integrity**: Replay the hash chain over `events.jsonl`; confirm
   the terminal hash matches `manifest.rootHash`.
2. **Signature validity**: Verify the signature in `attestations/signatures.json`
   against `manifest.json` using the embedded public key or Fulcio certificate.
3. **Artifact hashes**: For every artifact in `artifacts/`, compute its SHA-256
   and confirm it matches the hash referenced in the corresponding event payload.
4. **Ruleset hash**: Compute SHA-256 of `rules/destructive.yaml` and confirm it
   matches `manifest.rulesetHash`.
5. **RFC 3161 timestamps**: Validate timestamp tokens against the TSA's certificate
   chain. Confirm `manifest.producedAt` does not postdate any timestamp's `genTime`.
6. **Rekor inclusion** (optional, if present): Verify the inclusion proof against
   the Rekor public instance.

If any check in (1)-(4) fails, the verifier reports **FAIL** with a specific
message identifying the failing component. RFC 3161 or Rekor failures are
reported as warnings unless the `--strict` flag is set.

---

## 5. Manifest schema

The `manifest.json` file is the entry point for the bundle. Its schema:

```ts
interface Manifest {
  schemaVersion: 1;
  bundleId: string;                // ULID — matches directory name
  producedAt: string;              // ISO 8601 UTC
  producer: {
    tool: "depose";
    version: string;               // semver of the producing CLI
    host: {
      os: string;
      arch: string;
      kernel: string;
    };
  };
  session: {
    agentId: string;
    sessionId: string;
    startedAt: string;
    endedAt: string;
  };
  rootHash: string;                // Terminal chain hash over events.jsonl
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

- `manifest.schemaVersion` is `1`.
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
- `manifest.producer.host` reveals the OS, architecture, and kernel version of
  the producing machine. This is intentional: it aids verification of the
  capture environment and does not expose the hostname or IP.
- Full environment variables are never stored — only an allowlisted subset and
  a SHA-256 hash of the full environment for tamper-evidence.
- File content capture defaults to hash-only; full content storage requires
  explicit user opt-in and is limited to files under 1 MB.

See `docs/threat-model.md` for a complete security analysis.