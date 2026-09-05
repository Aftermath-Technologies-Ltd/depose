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

- `AWS_SECRET_ACCESS_KEY`, full secret key.
- `GH_TOKEN`, GitHub personal access token.
- `ANTHROPIC_API_KEY`, API key with billing implications.

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

## 2. Verifiable disclosure (redaction without re-signing)

A producer rarely hands over the whole session. `depose disclose`
produces a disclosure bundle that proves a chosen subset of events, and
a chosen subset of fields within them, belongs to the originally sealed
record, without re-signing anything and without the recipient ever
seeing the original. See `docs/bundle-format.md#disclosure-bundles`.

**What the recipient can verify from the disclosure alone:**

- The original manifest signature and RFC 3161 timestamp, unchanged.
- That every disclosed event is a byte-identical member of the sealed
  set at its stated position (RFC 6962 audit path to the signed Merkle
  root, plus a recomputed chain link).
- That every disclosed field opens to its sealed commitment
  (`sha256(jcs([salt, path, value]))`), so a value cannot be substituted.
- That any carried original file (the ruleset, the narrative) matches
  the signed files map.
- With two disclosures, that the later one extends the earlier
  (consistency proof) and that shared events are identical.

**What a disclosure reveals about what it withholds, by design:**

- The number of sealed events and the positions of the withheld ones.
  A recipient can see "events 4 through 9 were not disclosed" and
  argue about it; they cannot see what those events were.
- The chain hash of each withheld event (needed to recompute the
  disclosed events' own chain links). It is a SHA-256 over metadata and
  a payload hash; recovering the event requires guessing all of it.
- Which fields of a disclosed event are withheld (the placeholder is
  visible; its salt makes the value unguessable).

**Limits:**

- Events whose payload contains no committed field (prompts and
  assistant text by default) are hidden only by the one-wayness of
  their payload hash. A recipient who can guess the exact metadata and
  text can confirm the guess. Declare `prompt.text` and
  `assistant_message.content` in the ruleset's `disclosable` list to
  commit them.
- The narrative in the original bundle is derived from plaintext. Carry
  it into a disclosure only if everything it cites is disclosed.
- Consistency proofs relate two seals only when the earlier one is a
  prefix of the later with identical salts; today that holds for
  disclosures of the same seal, and for re-seals under a fixed seed.

The earlier "redact by editing and re-signing" workflow is gone. A
re-signed bundle is a different record with a different timestamp; a
disclosure is the same record, partially shown.

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
regardless of DEPOSE, the mitigation is host-level access control.

### 3.2 Attacker with a bundle (no key)

**What they learn:** Everything in §1 above. The bundle is a
self-contained record with no access controls beyond what the
producer applied before sharing.

**What they cannot do:**

- Forge a valid bundle without the producer's private key, the
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
- Modify, replace, add, or delete any other file in the tree. The
  signed `manifest.files` map pins every file (`raw/`, `artifacts/`,
  the narrative, `verify.txt`) by SHA-256 and length; the `files-map`
  check walks the tree and fails on any difference, including a
  planted symlink. The attestation files the map cannot contain are
  bound by content equality in the `attestation-files` check, so a
  deleted or swapped `.tsr` also fails. See
  `docs/bundle-format.md#files-map`.
- Replay the bundle's timestamps against a different manifest. RFC
  3161 tokens commit to `SHA-256(unsigned manifest)` via
  `TSTInfo.HashedMessage`.
- Claim the bundle proves something it does not, the verification
  report is deterministic and reproducible.

**What they *can* do without changing the verification outcome:**

- Nothing inside the bundle directory. Every file is either signed
  through the files map or bound to the manifest by content equality.
  The narrative and `verify.txt` remain non-evidentiary (they are
  derived prose; the canonical record is `events.jsonl` and the
  verifier's own report), but a modified copy is now detected rather
  than tolerated.

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
- **Key rotation and revocation.** A compromised key is published as
  revoked in the producer's key catalog; the verifier's
  `revocation-list` check fails a bundle signed by a revoked key. See
  `docs/key-management.md`.

DEPOSE offers one signing scheme: Ed25519 over the canonical manifest,
anchored with RFC 3161. Keyless signing through an OIDC identity
provider would remove the long-lived key, and DEPOSE does not implement
it; see `docs/decisions.md` D22 for why the scaffolding was removed
rather than left in place.

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

Sections 6.1, 6.3, and 6.4 have the same mitigation on Linux and it is
worth stating once: `depose-collect-execve` (§6.8) witnesses these
execs in the kernel, so they appear in the bundle as `process_spawn`
events with a `kernel_execve_without_hook` gap instead of being absent.
It is optional and needs `CAP_BPF`, so the per-section text below still
describes what happens without it.

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
corresponding `shell_command_pre` capture. On Linux the eBPF collector
witnesses the exec itself; see §6.8.

### 6.5 Hook failures

The Claude PreToolUse hook exits 0 on any error so it can never block
the agent. Before this behaviour was paired with evidence, an
exception in the hook produced no record at all, and the resulting
bundle looked complete. The hook now writes a `capture_failed` record
(phase, error class, sanitized first line of the message, monotonic
time, session id) before exiting, falling back to a line in
`capture-failed.log` when the record file cannot be written. The
merger turns each into a `gap` event with reason `capture_failed`,
counted in the signed manifest and surfaced in the narrative.

**Residual gap:** a failure while reading or parsing the hook's stdin
cannot know the session id, so its record is unattributed and only
enters a bundle when the producer opts in with
`--include-unscoped-captures`.

The PostToolUse hook behaves the same way and its `capture_failed`
records carry `source: "claude-posttooluse"`, so a bundle says which
half of the pair was lost.

### 6.5a Outcomes that were never recorded

A tool call whose PreToolUse hook ran and whose PostToolUse hook did
not is the case this system exists for: the agent was about to act and
what happened next is not in the bundle. It reaches the timeline as an
`intent_without_effect` gap and gets its own section at the top of the
narrative, ahead of the timeline. The verifier fails any bundle that has
an unclosed hook-captured intent and no gap disclosing it, so the hole
cannot be edited out of `events.jsonl` and still verify.

What the pair cannot see: a file the command created without naming it
in the tool input. The effect record covers the paths the call declared,
because those are the only ones either hook knows about. See
`docs/bundle-format.md#intent-and-effect`.

### 6.5b Files changed by something outside the session

Between one call's recorded outcome for a path and the next call's
recorded pre-state for the same path, the bundle claims custody. When
the two hashes disagree, something changed the file and nothing in the
bundle witnessed it: another process, another terminal, a person. The
merge emits an `unwitnessed_file_change` gap naming both events and the
verifier requires it, which turns "the evidence is silent about this
window" into a statement the bundle makes rather than one a reader has
to notice.

### 6.6 Destructive rules on wrapped commands

Rules match every simple command a shell would run, after stripping
`sudo`, `env`, `nice`, `time`, `nohup`, `command`, `exec`, `timeout`,
`xargs`, `doas`, and `VAR=value` prefixes, and after recursing into
`bash -c` strings, subshells, and command substitutions. Evasions this
closes: `sudo rm -rf`, `env X=1 terraform destroy`,
`cd /prod && rm -rf .`, `(cd /prod && rm -rf .)`, `$(terraform destroy)`.
Evasions it does not close: a destructive command hidden in a script
file the agent wrote earlier and then executed (`bash deploy.sh`), an
alias, or a binary renamed by the agent. Those remain visible only as
the file writes and executions themselves.

### 6.7 Stdin tee threshold

The shim tees stdin to a temp file for capture when stdin is under
1 MB. Above 1 MB, stdin is hash-only with a metadata note. This
means large input payloads (e.g., a multi-MB SQL migration piped
via stdin) are not fully captured.

**Mitigation:** The threshold is configurable. For sessions where
large stdin is operationally relevant (e.g., `psql < migration.sql`),
the producer should raise the threshold or opt in to full content
capture for the relevant file paths.

---

### 6.8 Kernel-witnessed execve

`depose-collect-execve` attaches an eBPF program to the
`sched:sched_process_exec` tracepoint and records every exec inside the
agent's process tree, tagged `source: kernel`. It closes §6.1, §6.3, and
§6.4 for the process tree it watches: the kernel sees an execve whether
it came through PATH, an absolute path, `subprocess.run` with
`shell=False`, or `syscall.Exec` from a static binary.

**What it still does not close.** It sees execs, not syscalls: a command
that opens and truncates a file without spawning a process is invisible
to it, as is one that runs on another machine over an already-open
connection. It filters on process ancestry, so a daemon the agent asked
to do the work, rather than executing it directly, is out of scope. A
process that exits before `/proc` can be read yields a record with the
pid, comm, and timestamp but no argv.

**Trust boundary.** The collector runs with `CAP_BPF` and writes into
the same capture store as the hook, under the producer's control. It
raises the cost of a silent omission (an attacker now has to defeat both
the hook and the kernel probe, or stop the collector and leave the
`capture_failed` record it writes on the way down) but it does not move
the trust boundary: the producer still assembles the bundle. See §3.

**Availability.** Without `CAP_BPF` the collector writes a
`capture_failed` record with phase `ebpf-attach` and exits 0. macOS has
no supported equivalent (Endpoint Security needs an Apple-granted
entitlement, openbsm is deprecated and off by default), so the collector
refuses to start there rather than shipping something that loads and
records nothing.

## 7. Mode contract: signed vs dev-unsigned

A DEPOSE bundle declares `manifest.producer.mode`, and the
verifier enforces the invariants of that declaration
(`apps/verify/cmd/verify.go`, `mode-declaration` and
`mode-contract` checks):

- **`signed`**, the only mode admissible as evidence. Requires a
  non-empty `rootHash`, at least one Ed25519 signature, and at
  least one RFC 3161 timestamp. The verifier rejects a bundle
  declaring `signed` but missing either.
- **`dev-unsigned`**, pipeline-testing bundles. `signatures` and
  `timestamps` must both be empty (the mode contract). The bundle
  directory is named `incident-unsigned-<id>` (not
  `incident-<id>`), and `verify.txt` plus `narrative.md` /
  `narrative.html` carry a "NOT EVIDENCE" banner. The verifier
  refuses to print plain "PASS" for a dev-unsigned bundle, even
  when every check is green, and instead emits
  `PASS (dev-unsigned, not evidence)`.

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
| Hook exception | Lost capture looks like a clean timeline | capture_failed record and gap event | stdin read/parse failures are unattributed |
| Wrapped destructive command | Rule never fires on active capture | Simple-command expansion and wrapper stripping | Commands hidden in scripts or aliases |
| Large stdin not captured | Incomplete payload record | Configurable tee threshold | Producer must raise limits for relevant sessions |

The core trade-off is between **evidentiary completeness** and
**informational exposure**. Every piece of data that makes the bundle
more forensically useful also makes it more sensitive. DEPOSE defaults
to the privacy-protective side (hash-only, strict allowlist, gap
events) and requires explicit producer action to increase exposure.