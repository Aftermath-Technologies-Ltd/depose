# DEPOSE Threat Model

This document enumerates what a DEPOSE bundle exposes, how an
attacker might exploit the system, and the mitigations in place. It is
written for both engineers and attorneys evaluating the risk profile
of producing or receiving a `.depo` bundle.

---

## 1. What a bundle exposes

A `.depo` bundle is an archive. The producer decides whether to
share it, but once shared, the recipient sees everything inside.

### 1.1 Env variables (allowlisted subset)

The `envSubset` field in `ShellCommandPrePayload` captures only
keys matching the configured allowlist. The default allowlist is:

- `AWS_*`
- `GH_*`
- `OPENAI_*`
- `ANTHROPIC_*`
- `RAILWAY_*`

These are captured because their values are operationally relevant
to understanding what an agent was authorized to do at the time of
execution. However, they may contain sensitive values:

- `AWS_SECRET_ACCESS_KEY` — full secret key.
- `GH_TOKEN` — GitHub personal access token.
- `ANTHROPIC_API_KEY` — API key with billing implications.

**Mitigation:** The full env is hashed (SHA-256) for tamper-evidence
without exposing non-allowlisted values. Users can customize the
allowlist to exclude sensitive keys via project config. Before
sharing a bundle, the producer should review `envSubset` in
`events.jsonl` and redact values if necessary (see §2).

### 1.2 File contents and hashes

The `fileArgs` field captures SHA-256 hashes of file paths
referenced in tool input. Full file content is captured **only**
when:

1. The file is under 1 MB, AND
2. The user has explicitly opted in via project config.

By default, only hashes are stored. The hash proves the file
existed and was in a specific state, without revealing its content.

**Risk:** Even hashes can be problematic. A hash of a known file
(e.g., a secrets template) can confirm the file's identity via
rainbow table or known-hash lookup.

**Mitigation:** The default is hash-only. Full content requires
explicit opt-in. The bundle does not include file contents for
files exceeding the size threshold regardless of opt-in.

### 1.3 Process tree and system metadata

Each `ShellCommandPrePayload` includes `parentProcessTree`,
`user`, `hostname`, and `cwd`. This reveals:

- The username on the machine.
- The hostname.
- The working directory path (which may reveal project names,
  organizational structure, or filesystem layout).
- Parent process PIDs and executable paths.

**Risk:** System metadata can reveal infrastructure details useful
for targeted attacks (hostname conventions, directory structure,
process names indicating installed tools).

**Mitigation:** This metadata is essential for evidentiary context
(proving which user, which machine, which process tree). Redaction
of hostname/username before sharing is possible but invalidates
the env hash, which must then be recomputed.

### 1.4 Prompt content

The `prompt` event type captures the user's input to the agent in
full. This may contain sensitive information: proprietary code
snippets, internal project names, business logic, or credentials
pasted directly into prompts.

**Risk:** Prompts are the highest-risk data class in the bundle.
They are necessary for evidentiary completeness (to show what the
agent was instructed to do) but may contain unrelated sensitive
content.

**Mitigation:** Redaction of prompt content is discussed in §2.
The bundle producer must exercise judgment before sharing.

---

## 2. Redaction

DEPOSE does not currently provide an in-tool redaction workflow.
Redaction is a producer responsibility, performed before sharing.
After redaction, the bundle must be **re-signed**, because any
modification invalidates the hash chain. This is by design:
redaction is a deliberate act, not a silent filter.

### Redaction workflow

1. Extract the `.depo` tarball.
2. Modify content in `events.jsonl`, `raw/`, or `artifacts/` as
   needed (e.g., replace `envSubset.AWS_SECRET_ACCESS_KEY` value
   with `REDACTED`).
3. Re-run `depose package` with the modified sources.
4. The re-signed bundle has a new `rootHash`, new signatures, and
   new RFC 3161 timestamps. The original bundle remains valid
   under its own signatures.

**Risk:** A recipient who receives both the original and redacted
bundles can diff them to identify what was redacted. Even the
existence of a redacted version may reveal that something was
sensitive.

**Mitigation:** Only share the redacted bundle. Destroy or
sequester the original per the producer's retention policy.

### Redaction and gap events

Redacting a `tool_result` event's output without also redacting the
corresponding `tool_call_intent` and `shell_command_pre` events may
create inconsistencies. The reconstructed timeline must remain
coherent. The producer should redact at the field level where
possible rather than removing entire events, which would require
rebuilding the hash chain and could introduce new `gap` events.

---

## 3. Attacker scenarios

### 3.1 Attacker with read access to `$DEPOSE_CAPTURE_DIR`

**What they learn:**

- Every command captured by the hook or shim, including argv,
  cwd, env subset, file hashes, and process trees.
- The timing of every captured operation.

**What they cannot do:**

- Modify capture records without detection (if the records are
  later incorporated into a signed bundle, any modification breaks
  the hash chain).
- Access the Ed25519 signing key (stored at
  `~/.depose/keys/signing.key` with 0600 permissions).
- Access non-allowlisted environment variables (only the allowlist
  subset is stored in capture records).

**Mitigation:** Capture records are written with 0600 permissions.
The capture directory should be on a filesystem with appropriate
access controls. If an attacker has persistent read access to the
capture directory, they have a continuous surveillance capability
regardless of DEPOSE — the mitigation is host-level access control.

### 3.2 Attacker with a bundle (no key)

**What they learn:** Everything in §1 above. The bundle is a
self-contained record with no access controls beyond what the
producer applied before sharing.

**What they cannot do:**

- Forge a valid bundle without the producer's private key — the
  Ed25519 signature is over the canonical bytes of `manifest.json`
  with `signatures=[]` and `timestamps=[]`, and the manifest pins
  every other authenticated artifact transitively (see below).
- Modify `manifest.json` without invalidating the Ed25519 signature.
- Modify the content of any event's `payload` field. The verifier
  re-canonicalizes each event's payload (RFC 8785 JCS) and SHA-256s
  the bytes; a mismatch with the recorded `payloadHash` fails the
  `payload-hash` check. This is the regression that was open before
  this fix: rewriting a payload string while leaving `payloadHash`
  and `chainHash` intact passed verification. It does not now.
- Modify `payloadHash`, `chainHash`, or chained metadata (id, wallTs,
  monoNs, sessionId, agentId, parentEventId, type, payloadHash) on
  any event without invalidating chain replay against
  `manifest.rootHash`.
- Add, remove, reorder, or otherwise byte-mutate `events.jsonl`
  beyond what the chain already covers. The verifier hashes the
  literal file bytes and compares against `manifest.eventsJsonlSha256`,
  which is signed.
- Modify `rules/destructive.yaml` without invalidating the
  `ruleset-integrity` check (manifest carries the SHA-256).
- Replay the bundle's timestamps against a different manifest. RFC
  3161 tokens commit to `SHA-256(unsigned manifest)` via
  `TSTInfo.HashedMessage`.
- Claim the bundle proves something it does not — the verification
  report is deterministic and reproducible.

**What they *can* do without changing the verification outcome:**

- Modify `narrative.md` / `narrative.html` / `verify.txt` — these
  are documented in `docs/bundle-format.md §4.3` as non-evidentiary.
  A modified narrative does not invalidate the bundle, but a
  recipient who reads it cannot rely on it; the canonical record is
  `events.jsonl` and the verifier's own report.

**Mitigation:** Before producing a bundle for sharing, audit the
contents. Use the hash-only default for file contents. Trim the
env allowlist to operationally necessary keys. Redact prompts
that contain sensitive but non-evidentiary content. After redaction,
re-run `depose package` to produce a new signed bundle with new
hashes.

### 3.3 Attacker who compromises the producer's Ed25519 key

**What they can do:**

- Sign arbitrary bundles claiming to be from the producer's key.
- Create bundles with fabricated events that verify successfully
  against the compromised key.

**What they cannot do:**

- Backdate signatures to before the key was compromised. The
  verifier's `timestamp-backdating` check fails any bundle whose
  `producedAt` is more than one second after every embedded RFC
  3161 timestamp (the one-second tolerance covers TSA whole-second
  truncation; see `apps/verify/timestamp/rfc3161.go`).
- Produce a valid RFC 3161 timestamp for a fabricated root hash
  without access to a TSA's signing key. The verifier's
  `timestamp-verify` check ASN.1-parses the TimeStampToken,
  validates the embedded TSA cert chain against an embedded trust
  pool (FreeTSA + system roots), and verifies the PKCS7 signature
  over `TSTInfo`. The previous byte-substring scan that B1 closed
  could be forged trivially; the current check cannot.
- Pass the recipient's key-fingerprint pin if the recipient is
  running `depose-verify --expected-key-fingerprint <hex>` against
  the producer's out-of-band-published fingerprint. The
  `key-fingerprint-pin` check rejects any mismatch.

**Mitigation:**

- **Air-gapped (today).** The producer publishes their key
  fingerprint out-of-band; recipients pin it with
  `--expected-key-fingerprint`. See `docs/key-management.md`.
- **Sigstore keyless (preferred when available).** A producer
  running under OIDC (CI, federated identity) signs with an
  ephemeral key bound to a short-lived Fulcio cert. There is no
  long-lived key to compromise. The producer-side path is
  scaffolded in `packages/chain/src/sign-sigstore.ts`; the
  verifier already accepts `--signer-identity <regex>`.

### 3.4 Attacker who can modify the verifier binary

**What they can do:**

- Make the verifier report PASS for a tampered bundle.
- Suppress specific verification checks.

**What they cannot do (if the recipient has the genuine binary):**

- The genuine binary will correctly detect tampering. The bundle
  itself does not change based on which verifier runs against it.

**Mitigation.** Releases of `depose-verify` are produced by the
tag-driven GitHub Actions workflow `.github/workflows/release.yml`:

- Cross-compiled for darwin/linux × arm64/amd64 with a stripped
  Go build (`-ldflags "-s -w"`) so the same source produces a
  bit-identical binary on the same toolchain.
- `SHA256SUMS` is generated over the binaries.
- `cosign sign-blob` (keyless, GitHub OIDC → Fulcio → Rekor) emits
  `SHA256SUMS.sig` and `SHA256SUMS.pem`. There is no long-lived
  signing key.
- An SLSA L3 in-toto provenance attestation is also published.

Recipients verify with:

```
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/Aftermath-Technologies-Ltd/depose/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
```

then check their downloaded binary's SHA-256 against `SHA256SUMS`.
The cosign verification ties the binary to *this* repository's
release workflow on the matching tag. A binary built by anyone
else cannot pass.

### 3.5 Attacker who controls the host during a session

**What they can do:**

- Intercept and modify the hook's stdin before it writes to the
  capture directory.
- Replace the real binary that the shim execs with a malicious one.
- Inject environment variables not present in the real session.
- Modify files before or after the hook captures their hashes.

**What DEPOSE cannot defend against:**

- A host-level adversary during the session is outside the trust
  boundary. If the kernel is compromised, no userspace tool can
  produce trustworthy evidence. DEPOSE's promise is post-hoc
  tamper detection, not real-time resistance to a rootkit.

**Mitigation:** Document this limitation honestly. A DEPOSE bundle
proves: "This is what the capture layer observed, and it has not
been altered since." It does not prove: "The host was not
compromised during capture."

---

## 4. Env allowlist

The env allowlist is a critical privacy and security boundary.
The default allows `AWS_*`, `GH_*`, `OPENAI_*`, `ANTHROPIC_*`,
and `RAILWAY_*` because these keys answer the question: "What
cloud and API resources was the agent authorized to access?"

**Risks of the default allowlist:**

- `AWS_SECRET_ACCESS_KEY` values are full secret keys. If a bundle
  is shared, the recipient can use these keys to access AWS
  resources until they are rotated.
- `GH_TOKEN` grants GitHub API access with the token's scope.
- Any allowlisted key with a sensitive value is exposed.

**Risks of a restrictive allowlist:**

- Too few keys reduce the evidentiary value of the env snapshot.
- No env subset makes it harder to argue what the agent could or
  could not access at the time of execution.

**Configuration:** Users extend or restrict the allowlist via
project-level `.depose.json` config. The full env hash (over all
keys and values) is always captured for tamper-evidence; only the
allowlisted subset values are stored in plaintext.

---

## 5. Hash-only defaults

File content capture defaults to hash-only for three reasons:

1. **Privacy.** Full file content may contain secrets, PII, or
   proprietary code unrelated to the evidentiary question.
2. **Bundle size.** Full artifacts can make bundles very large.
3. **Proportionality.** For many forensic questions, proving a
   file existed in a specific state (via hash) is sufficient
   without revealing its contents.

**Risk of hash-only:** A hash cannot prove file content. If the
evidentiary question requires showing what a file contained (not
just that it existed), hash-only is insufficient. The producer
must explicitly opt in to full content capture for those files.

**Risk of full content:** Files under 1 MB with full content in
`artifacts/files-pre/` and `artifacts/files-post/` are visible to
any bundle recipient. This includes any secrets, credentials, or
PII in those files.

---

## 6. Shim gaps

The shell shim (installed via `depose install --shell`) has known
coverage gaps. These are not bugs; they are architectural
limitations documented here and in `docs/capture-coverage.md`.

### 6.1 Absolute path invocation

Invoking a binary by absolute path (e.g., `/usr/bin/terraform
destroy`) bypasses the shim because the shell does not consult
PATH. The shim only intercepts when the shell resolves the command
via PATH and the shim directory has precedence.

**Mitigation:** The Claude Code PreToolUse hook captures tool calls
regardless of how the underlying binary is invoked, because Claude
Code's tool system records the command before executing it. The
shim covers non-Claude-Code shell sessions. Gap events flag
uninstrumented executions.

### 6.2 Tool aliases and renamed binaries

`tofu destroy` (OpenTofu) is not in the default shim allowlist.
The user must add it manually. Similarly, any renamed or aliased
destructive tool is uninstrumented by default.

**Mitigation:** The shim allowlist is user-extensible via
`.depose.json`. Documentation urges users to add non-standard
tool names. Gap events flag any `tool_result` that lacks a
corresponding `shell_command_pre`.

### 6.3 Subprocess exec without PATH

Python `subprocess.run(["terraform", "destroy"], shell=False)`
or Node `child_process.execFileSync("terraform", ["destroy"])`
bypass PATH and thus the shim, because they call `execve` directly
with a resolved binary path.

**Mitigation:** Only the Claude Code hook reliably captures these.
For non-Claude-Code programs, this is a known gap. The gap event
system makes this visible rather than hidden.

### 6.4 Statically linked binaries

A Go or Rust binary that calls `syscall.Exec` directly, without
going through the shell, cannot be intercepted by a PATH shim.

**Mitigation:** No userspace mitigation exists for this case. The
gap event system will flag it if a `tool_result` appears without a
corresponding `shell_command_pre` capture.

### 6.5 Stdin tee threshold

The shim tees stdin to a temp file for capture when stdin is under
1 MB. Above 1 MB, stdin is hash-only with a metadata note. This
means large input payloads (e.g., a multi-MB SQL migration piped
via stdin) are not fully captured.

**Mitigation:** The threshold is configurable. For sessions where
large stdin is operationally relevant (e.g., `psql < migration.sql`),
the producer should raise the threshold or opt in to full content
capture for the relevant file paths.

---

## 7. Mode contract: signed vs dev-unsigned

A DEPOSE bundle declares `manifest.producer.mode`, and the
verifier enforces the invariants of that declaration
(`apps/verify/cmd/verify.go`, `mode-declaration` and
`mode-contract` checks):

- **`signed`** — the only mode admissible as evidence. Requires a
  non-empty `rootHash`, at least one Ed25519 signature, and at
  least one RFC 3161 timestamp. The verifier rejects a bundle
  declaring `signed` but missing either.
- **`dev-unsigned`** — pipeline-testing bundles. `signatures` and
  `timestamps` must both be empty (the mode contract). The bundle
  directory is named `incident-unsigned-<id>` (not
  `incident-<id>`), and `verify.txt` plus `narrative.md` /
  `narrative.html` carry a "NOT EVIDENCE" banner. The verifier
  refuses to print plain "PASS" for a dev-unsigned bundle, even
  when every check is green, and instead emits
  `PASS (dev-unsigned — not evidence)`.

A dev-unsigned bundle that smuggles a signature in is caught by
the `mode-contract` check and fails verification.

## 8. Out of scope (explicit non-goals)

These are scenarios DEPOSE does **not** defend against. They are
called out so the reader does not infer protection that isn't there:

- **Producer-host compromise during the session.** DEPOSE captures
  what the host shows. If the kernel, init system, or shell
  binary lies, DEPOSE faithfully records the lie. The bundle
  proves what the capture layer observed, not ground truth on a
  rooted machine. See §3.5.
- **Replay attacks on RFC 3161 tokens.** A TSA cert is treated as
  trusted for its declared validity window. We do not implement
  TSA cert revocation lookups or short-lifetime root pinning. A
  TSA whose key is compromised within its validity window can
  retroactively forge timestamps; we accept this risk because the
  alternative (running our own TSA) is worse.
- **Windows producers.** The shim and capture-hook paths are
  developed against macOS and Linux. Windows is not tested.
  Windows recipients running `depose-verify.exe` against a
  Linux-produced bundle are supported.
- **Storage privacy at rest.** A `.depo` bundle is not encrypted.
  If confidentiality is required, encrypt at the transport layer
  (age, GPG, S3 SSE).
- **Real-time tamper resistance.** DEPOSE is post-hoc evidence,
  not an EDR. It does not block or alert on destructive actions
  in the moment.

## 9. Summary

| Threat | Impact | Mitigation | Residual risk |
|--------|--------|------------|---------------|
| Bundle exposes env values | Credential leak to recipient | Allowlist + redaction before sharing | Producer must audit before sharing |
| Bundle exposes file contents | PII/secret leak | Hash-only default | Full content requires explicit opt-in |
| Attacker reads capture dir | Surveillance of commands | 0600 permissions, host access control | Persistent read access is a host security problem |
| Attacker forges bundles | Fabricated evidence | Ed25519 + RFC 3161 timestamps | Key compromise requires organizational response |
| Attacker modifies verifier | False PASS reports | Published checksums, reproducible builds | Recipient must verify the verifier |
| Compromised host | All captures suspect | Post-hoc tamper detection only | Cannot defend against kernel-level adversary |
| Shim bypass | Missing capture records | Gap events, Claude Code hook | Absolute paths, aliases, direct execve |
| Large stdin not captured | Incomplete payload record | Configurable tee threshold | Producer must raise limits for relevant sessions |

The core trade-off is between **evidentiary completeness** and
**informational exposure**. Every piece of data that makes the bundle
more forensically useful also makes it more sensitive. DEPOSE defaults
to the privacy-protective side (hash-only, strict allowlist, gap
events) and requires explicit producer action to increase exposure.