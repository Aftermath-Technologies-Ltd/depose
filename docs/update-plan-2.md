# DEPOSE Update Plan 2 — End-to-End Evaluation & Remediation

**Date:** 2026-05-19
**Scope:** Full end-to-end evaluation of the project (correctness, security,
tech debt, UX). Root-cause analysis for each issue plus a concrete fix.
**Status (gates today):** `pnpm typecheck`, `pnpm lint`, `pnpm test` (252/252)
all green. None of the issues below are caught by the current test suite —
they are correctness, drift, and design problems the tests do not exercise.

This plan is the successor to `docs/update-plan.md`. Numbering is fresh; each
finding is `[F-NN]` (Finding) with a root cause and a remediation. Findings
are grouped by area and ordered roughly by severity within each area.

---

## Executive summary

DEPOSE compiles, lints, and passes its tests, but the test suite tests the
*synthetic fixtures it ships with*, not the real-world contract the README and
threat model advertise. Five class-A issues sit in the producer:

1. **The normalizer does not parse real Claude Code session logs.** It parses
   a flat synthetic shape (`{type:"user", content:"..."}`) that the live
   product hasn't emitted in a long time. Real sessions land as `gap` events.
2. **Reconstruction-time fields are stamped from the producer host, not the
   session host.** `cwd`, `user`, `hostname`, and `process.platform` are read
   at `depose package` time and written into events the manifest claims
   describe the session. A `darwin` developer producing a bundle from a Linux
   session's JSONL writes "darwin" into the bundle's `host.os`.
3. **Event ULIDs encode packaging time, not event wallTs.** Every
   reconstructed event gets `ulidFromTime(Date.now())`. The `id` field is
   sortable, but it lies about when the event happened, and chain replay
   sorts by an attribute that has no relation to the session.
4. **The producer trusts whatever the TSA returns without checking it.**
   `requestTimestamps` extracts `genTime` via a byte-substring scan for
   `0x18`, never re-verifies the TSR's `MessageImprint` matches what was
   asked for, never checks the nonce, and falls back to the local clock if
   parsing fails. The Go verifier does the real cryptographic check; the
   producer would happily bundle a forged or replayed token.
5. **`depose install --claude` registers `depose-hook` as the hook command,
   but the CLI package only declares `depose` in its `bin` map.** A user who
   `pnpm install`s depose then runs `install --claude` ends up with a
   settings.json that points at a binary that is not on PATH. The hook
   silently does nothing.

Plus: two unimplemented integrations (`sigstore`, `rekor`) that the threat
model treats as available paths; bundle layout drift (always-empty
`raw/`, `artifacts/`, `rekor-entries.json`); a misleading `depose explain`
that claims to be AI-generated while being a deterministic template; a
shell-history parser that munges piped commands into a single argv array
(destroying rule matching); and a `tool_result`-to-`shell_command_pre`
correlator whose primary signals (`cwd`, `argv`) do not exist on
`ToolResultPayload`, so matching is essentially time-only.

---

## A. Correctness — the producer does not actually do what the README claims

### [F-01] Claude Code JSONL normalizer doesn't parse the real format

**Where:** `packages/core/src/normalize/claude-code.ts`

**Observed.** The normalizer's `ClaudeCodeLine` interface and the switch in
`normalizeClaudeCodeLine` expect a flat shape:

```jsonc
{ "type": "user", "content": "...", "timestamp": "..." }
{ "type": "assistant", "content": "...", "tool_calls": [...] }
{ "type": "tool", "tool_name": "...", "output": "..." }
```

The current Claude Code session log shape (verified against
`~/.claude/projects/.../*.jsonl` from a recent session) is:

```jsonc
{ "type": "user",
  "message": { "role": "user", "content": "..." },
  "uuid": "...", "parentUuid": "...", "sessionId": "...",
  "timestamp": "..." }

{ "type": "assistant",
  "message": { "role": "assistant", "content": [
    { "type": "thinking", "thinking": "..." },
    { "type": "text", "text": "..." },
    { "type": "tool_use", "name": "Bash", "input": { "command": "..." } }
  ]},
  "timestamp": "..." }
```

`line.content` is `undefined`. `line.tool_calls` is `undefined`. The
normalizer reaches `case 'user':`, reads `line.content` as `undefined`,
calls `JSON.stringify(undefined)` → `"undefined"` (literally that string),
and emits a `prompt` event with text `"undefined"`. For `assistant` it
emits a message with `content: ""`. Tool calls are entirely lost.

**Why this passes tests.** The bundled `examples/*/session.synthetic.jsonl`
files were hand-written to the *old* shape, and the test fixtures match.
The unit tests are an internal-consistency check, not a contract test.

**Root cause.** The schema was never re-derived against a real Claude Code
transcript after the format moved to the typed-content-blocks model. There
is no fixture in the repo built from real Claude Code output, so the
regression cannot be detected.

**Remediation.**
1. Add `examples/real-jsonl/` with one or two redacted real Claude Code
   transcripts and treat them as fixtures the normalizer must parse without
   emitting only `gap` events.
2. Add a second-pass normalizer that, when `line.message` exists, descends
   into `line.message.content`. For each typed block:
   - `{type: "text", text}` → emit `assistant_message` with `content`.
   - `{type: "thinking", thinking}` → emit `assistant_message` content
     (label the variant in payload metadata so a reader can tell it apart
     from a user-visible response).
   - `{type: "tool_use", id, name, input}` → emit `tool_call_intent`. Keep
     the upstream `tool_use_id` so it can be matched to the subsequent
     `tool_result` block (Claude Code emits the result as a `user`-typed
     message with `content: [{type:"tool_result", tool_use_id, content}]`).
3. Keep the legacy flat-shape path under a feature flag for the synthetic
   examples until the examples are rewritten against the new shape.
4. Add a contract test: a real-shape JSONL must produce 0 `gap` events for
   recognized line types, and `prompt`/`assistant_message`/`tool_*` counts
   must match the input.

---

### [F-02] Reconstruction emits producer-host fields as if they were session fields

**Where:**
- `packages/core/src/normalize/claude-code.ts` lines 409–420 (the
  `shell_command` case)
- `packages/core/src/normalize/shell-history.ts` lines 77–79, 108–117
- `packages/cli/src/pipeline.ts` lines 162–175
  (`createShellCommandEvent`)
- `packages/bundle/src/manifest.ts` lines 161–166 (`producer.host`)

**Observed.** When the producer reconstructs from a JSONL, the synthesised
`ShellCommandPrePayload` events read `process.cwd()`, `process.env.USER`,
and `process.env.HOSTNAME` from the producer's machine. The manifest's
`producer.host.{os,arch,kernel}` is set from `process.platform`,
`process.arch`, and (oddly) `process.version` (the Node.js version, not
the OS kernel). A bundle reconstructed on macOS for a Linux session reads
`os: "darwin"`, `kernel: "v20.x.x"`. The session host is unrecoverable.

The TSR genTime is the only honest field about "when this was produced".

**Root cause.** The schema conflates two distinct hosts — the host where
the agent ran (session host) vs. the host that did the cryptographic
packaging (producer host). Reconstruction code had nothing else to fill
session-host fields with and silently substituted the producer host.
`producer.host.kernel = process.version` is just a misnamed field.

**Remediation.**
1. Split the host concept in two:
   - `producer.host` keeps producer-machine metadata, but rename `kernel`
     → `nodeVersion` (since that's what it actually holds) and add a
     real `kernel` populated via `os.release()`.
   - Add `session.host` with `os`, `kernel`, `user`, `hostname` populated
     only from observed session data (active capture records or the JSONL
     itself if a field exists). Leave fields `null` when unknown.
2. In reconstruct/pipeline paths, when a `shell_command_pre` is
   *synthesised* from JSONL (not a real capture record), set
   `cwd`/`user`/`hostname` to `""` and `source: "reconstructed"` (new
   enum variant alongside `claude-pretooluse`/`shell-shim`). Never read
   `process.env.USER` for events the producer didn't observe.
3. Bump `schemaVersion` to 2 with a deprecation note for the old shape
   so the verifier accepts both for one minor release.
4. Add a `gap` reason `host_unknown_session_reconstructed_from_jsonl` for
   any synthesised event so a reader sees the limitation explicitly.

---

### [F-03] Event ULIDs encode packaging time, not event wallTs

**Where:**
- `packages/core/src/normalize/claude-code.ts:491`
- `packages/core/src/normalize/merge.ts:343`
- `packages/core/src/normalize/git-reflog.ts:206`
- `packages/cli/src/pipeline.ts:162`

All four normalizers call `ulidFromTime(Date.now())` to mint event IDs.
`Date.now()` is the wall clock of the producer at packaging time, not the
event's `wallTs`. The example bundle confirms this:
`incident-96JT7DA5AR8TN6Z2GNSW9RCJ4G` has wallTs `2026-04-12T09:15:00.000Z`
but its first event ID `06F44TCGG9A9G0X9XP92Y3M6N8` decodes to a timestamp
in May 2026 (when the bundle was produced).

**Observed effects.**
- `ulidToTime(event.id)` (which `packages/core/src/events/ids.ts` exports
  as a public helper) returns the packaging time, not the event time.
- Chain replay sorts events by ID. The producer iterates JSONL lines in
  order, so within one packaging run the IDs are monotone in the order the
  lines were read — which happens to be JSONL order — so chain replay
  works. But a second `depose package` over the same JSONL produces
  different IDs, and a different `rootHash`. The "deterministic by
  default" claim in `architecture.md §4.3` is false unless callers wire
  `setFixedUlidSeed`, which no production path does.
- A recipient looking at an ID and expecting "this event happened on the
  timestamp encoded in the ULID" is misled.

**Root cause.** `ulidFromTime` was added to keep IDs sortable; the
contributors then plugged in `Date.now()` because the function "needs a
number". The site-specific value should have been `new Date(wallTs).getTime()`.

**Remediation.**
1. Replace every `ulidFromTime(Date.now())` with
   `ulidFromTime(new Date(wallTs).getTime())` so the ID encodes the
   event's actual time. Tie-break inside the same ms via monoNs (already
   used elsewhere for ordering).
2. Add an invariant test: for every event in the bundle, assert
   `ulidToTime(event.id) === Date.parse(event.wallTs)` (modulo 1ms).
3. Add a CI step to re-package both example bundles twice and `diff -r`
   the two outputs: must be byte-identical except for fields the spec
   marks variable (signature, TSR token, producedAt). Pin
   `setFixedUlidSeed` in the produce.sh script to make this enforceable.

---

### [F-04] Producer never verifies what the TSA sent back

**Where:** `packages/chain/src/timestamp-rfc3161.ts`

**Observed.**
1. `extractTimestampFromTsr` walks the DER blob looking for the first byte
   `0x18` (GeneralizedTime ASN.1 tag) and parses 14–17 chars after the
   length byte as `YYYYMMDDHHmmSS[.frac]Z`. The byte `0x18` can legally
   appear in many other positions (any embedded INTEGER, OCTET STRING
   content, RDN value, etc.). It happens to work for FreeTSA and DigiCert
   today because their TSTInfo's `genTime` is the *first* `0x18` in the
   DER, but it's not a verifier — it's a heuristic.
2. `requestTimestamps` then does:
   ```ts
   tokens.push({
     tsa: endpoint.name,
     timestamp: timestamp ?? new Date().toISOString(),  // ← fallback to local clock
     tokenBase64: tsrDer.toString('base64'),
   });
   ```
   If extraction fails, the producer silently uses its own clock as the
   "timestamp" field. The bundle then carries a `producedAt` and a
   `timestamps[0].timestamp` that both come from the producer — the
   TSA's actual time is hidden inside the base64 token and never used to
   cross-check.
3. The producer never compares `parsed.HashedMessage` (the hash the TSA
   actually signed) to the SHA-256 of the manifest it sent. A TSA that is
   compromised, mis-configured, or hostile could return a token for a
   different document. The producer would package it. Only `depose-verify`
   later catches this, which is the right cryptographic behavior but the
   wrong producer behavior — the producer shouldn't ship a bundle it
   knows is broken.
4. The nonce — generated and embedded in the TimeStampReq — is never
   compared to the response's `TSTInfo.Nonce` field. Replay protection
   on the request/response pair is therefore unused.

**Root cause.** Comment on line 365: "A TS-side `verifyTimestamp` lived
here previously and did a byte-substring scan over the DER blob..." The
broken helper was removed but no real producer-side verification replaced
it.

**Remediation.**
1. Adopt a real ASN.1 parser on the producer side. Either:
   (a) port the `digitorus/timestamp` parsing logic to TypeScript (small —
       it's a few hundred lines of DER walking), or
   (b) shell out to the already-built `depose-verify` binary in a "verify
       this token before bundling" mode.
   Recommendation: (b). It keeps the producer/verifier code in one place,
   and the producer can re-use the verifier's authoritative answer.
2. After receiving a TSR, run the verifier's `timestamp.VerifyToken` over
   it with the just-computed manifest hash. If the result is not `Valid`,
   discard the token and try the next TSA. Never ship an unvalidated
   token.
3. Check the nonce: extract `TSTInfo.Nonce`, compare to the nonce we
   embedded in the request, fail closed on mismatch.
4. Delete the `timestamp: timestamp ?? new Date().toISOString()` fallback.
   If the TSA's `genTime` can't be parsed, the token is unusable — fail
   the request and try the fallback TSA.

---

### [F-05] `depose install --claude` registers a binary that isn't on PATH

**Where:**
- `packages/cli/src/commands/install.ts:37` — `HOOK_COMMAND = 'depose-hook pretooluse'`
- `packages/cli/package.json` — `bin: { "depose": "./bin/depose" }`
- `packages/cli/bin/depose-hook` — exists but is not in the `bin` map

**Observed.** Running `depose install --claude` writes this into
`~/.claude/settings.json`:
```json
{ "type": "command", "command": "depose-hook pretooluse" }
```
After `pnpm install -g @depose/cli` (or a future `npm install -g depose`)
only `depose` is symlinked into the bin directory. `depose-hook` is not.
The hook then fails to launch every time Claude tries to invoke it,
silently — Claude Code logs but does not surface hook failures, and the
hook is observation-only by contract so users have no signal anything is
broken.

The repo today only works because contributors run `depose install`
against the local repo while sitting in the repo root, where the local
`bin/depose-hook` is reachable via the shebang — but the path written into
settings.json (`depose-hook pretooluse`) still requires it on PATH, which
it isn't unless the user manually adds `packages/cli/bin` to PATH.

**Root cause.** The CLI was built with two binaries in mind but only one
was declared in the `bin` map. The install command was never end-to-end
tested via `npm pack && npm install -g`.

**Remediation.**
1. Add `"depose-hook": "./bin/depose-hook"` to `packages/cli/package.json`
   `bin` map.
2. Change `HOOK_COMMAND` to spell out the resolved path to `depose-hook`
   at install time — `which depose-hook` if found, otherwise the
   absolute path computed from `import.meta.url`. Writing an absolute
   path means the hook keeps working after the user changes PATH.
3. Verify the hook is actually invokable before writing settings.json.
   If `which depose-hook` returns nothing AND the absolute path doesn't
   exist, fail the install with a clear message.
4. Add an end-to-end install test that builds the package with `pnpm
   pack`, installs into a tmpdir, runs `install --claude
   --project --project-root <tmp>`, and asserts that the recorded
   `command` resolves to a real executable.

---

## B. Correctness — silent bugs in normalization and matching

### [F-06] `tool_result` ↔ `shell_command_pre` correlator reads fields that don't exist

**Where:** `packages/core/src/normalize/merge.ts:255–298`

`findMatchingShellPre` reads `cwd` and `argv` from the target's payload to
score matches. For `tool_result` events the payload is `ToolResultPayload`
— which has `toolName`, `output`, `exitCode`, `error`,
`linkedShellCommandPreId`. No `cwd`, no `argv`. So the cwd/argv branches
score 0 and the only remaining signal is timestamp proximity
(`Math.max(0, 10 - Math.floor(timeDiff/1000))`, capped at 10), which by
itself fails the threshold `bestScore >= 5` only above 5 seconds delta.
Within the match window, the correlator returns the
*temporally-nearest* `shell_command_pre` to every tool_result regardless
of whether the command actually matches.

**Root cause.** The function was written generically over
`{cwd, argv, wallTs}` but the call site passes both `tool_result` and
`tool_call_intent`. Only `tool_call_intent` (sometimes) has those fields
because the JSONL normalizer drops `toolInput` into `payload.toolInput`,
not into `payload.cwd`/`payload.argv`.

**Remediation.**
1. Specialize correlation: from a `tool_result`, find the *parent*
   `tool_call_intent` (already in the same JSONL line in the new normalizer
   contemplated in F-01), and from that `tool_call_intent` extract
   `payload.toolInput.command` to tokenize.
2. Drop the cwd/argv score path on `tool_result` entirely. Score is
   `(argv-overlap-from-tool-call-intent × 5) + time-proximity`.
3. Add a regression test: a JSONL with two `Bash` tool_results in the
   same 5-second window must each correlate to their own `tool_call_intent`,
   not crosswire.

---

### [F-07] Shell-history tokenizer treats pipes as command separators that vanish

**Where:** `packages/core/src/normalize/shell-history.ts:212–224`

The tokenizer's pipe handling:
```ts
if (ch === '|' && !inDoubleQuote && !inSingleQuote) {
  if (current.length > 0) { tokens.push(current); current = ''; }
  i++;  // skip pipe
  while (... whitespace) i++;
  continue;
}
```
For input `echo foo | grep bar`, the produced tokens are
`["echo", "foo", "grep", "bar"]` — the pipe disappears and `grep`
becomes argv[2] of a single "command". Destructive rule matching
(`argvHead: ["rm"]`, `argvContainsAny: ["-rf"]`) then operates on a
flattened argv that no longer represents any real command. Worse, this
hides destructive operations: `terraform plan | terraform destroy` is
silently flattened into `["terraform", "plan", "terraform", "destroy"]`
where `argvHead === ["terraform", "destroy"]` is false.

**Root cause.** The tokenizer was written as a single-argv splitter
without a concept of pipe-separated stages. The pipe code path was added
as an afterthought that "skips the pipe."

**Remediation.**
1. Return `string[][]` from the tokenizer (one inner array per
   pipe-separated stage), not `string[]`.
2. Update `parseShellHistory` to return one `ShellHistoryCommand` *per
   pipe stage*, sharing the same timestamp but with distinct argvs.
3. Apply destructive matching per stage. `terraform plan | terraform
   destroy` becomes two commands; the second matches `terraform-destroy`.
4. Match handling for `&&` and `||` and `;` similarly — each is a separate
   command in shell semantics. Today they are stripped through the
   `[^\s;|&<>()'"`$]+` regex in `extractPathsFromCommand` and silently
   merged in `tokenize`.

---

### [F-08] `parseFishHistory` does not parse fish history

**Where:** `packages/core/src/normalize/shell-history.ts:145–147`

`parseFishHistory` is `return parseBashHistory(content);` — a stub that
treats fish history as bash. Real fish history (in `~/.local/share/fish/fish_history`)
is YAML-ish:
```
- cmd: ls -la
  when: 1684417200
- cmd: rm -rf /tmp/cache
  when: 1684417201
  paths:
    - /tmp/cache
```
The bash parser sees lines like `- cmd: ls -la` and tokenizes the leading
`-` as argv[0]. Every fish-sourced command is mis-recorded.

**Root cause.** Parser was scaffolded and never finished.

**Remediation.** Either:
- Implement a real fish parser (it's ~30 lines), or
- Delete `parseFishHistory` from the public API and remove fish from the
  README's "shell history (bash/zsh/fish)" claim until it's implemented.

The README/threat-model both claim fish is supported. The honest move is
to delete the claim and add a `gap` reason `unsupported_shell_history_format`
emitted when the parser detects fish syntax.

---

### [F-09] Unparseable JSONL lines are labeled with the wrong gap reason

**Where:** `packages/core/src/normalize/claude-code.ts:168–182,
202–218, 456–471`

Three places emit `gap` events with `reason: 'shell_history_without_jsonl_correlation'`
— a reason that has nothing to do with JSONL parsing. The schema's
allowed reasons are:
- `tool_result_without_pre_capture`
- `shell_history_without_jsonl_correlation`
- `reflog_change_without_command`
- `pre_capture_without_tool_result`

None of those match "Claude Code JSONL line failed to parse". The fix
is to add (and use) a fifth reason.

**Root cause.** Reason enum was minimised and the JSONL parser reused
the first available reason rather than expanding the enum.

**Remediation.**
1. Add `jsonl_line_unparseable` and `unknown_jsonl_line_type` to
   `GapPayload.reason`. Bump `schemaVersion` to 2 (additive — verifier
   ignores unknown reasons under the additive-versioning policy at
   `architecture.md §4.7`).
2. Use the right reason at each gap-emission site.

---

### [F-10] Assistant tool calls collide on `monoNs`

**Where:** `packages/core/src/normalize/claude-code.ts:288–305`

When an `assistant` line has multiple `tool_calls`, every emitted
`tool_call_intent` gets `monoNs: monoNs + 1` (the same value for all of
them). Sort stability across calls is preserved only by array order on
the way out of one normalizer pass, but once events from multiple sources
are merged, `mergeEvents` sorts by `(wallTs, monoNs)` and the order of
tool calls within the same assistant turn becomes non-deterministic
across runs.

**Root cause.** Loop index not used in the `monoNs` increment.

**Remediation.** Replace `monoNs: monoNs + 1` with
`monoNs: monoNs + 1 + index` where `index` is the loop counter. Add a
test that a multi-tool-call assistant message round-trips its tool_calls
in declaration order.

---

### [F-11] `tool_call_executed` payload is cast to the wrong type in narrative

**Where:** `packages/narrative/src/render.ts:138–145`

```ts
case 'tool_call_executed': {
  const p = event.payload as ToolCallIntentPayload;  // ← wrong
```
`ToolCallExecutedPayload` has `exitCode` and `durationMs`;
`ToolCallIntentPayload` does not. The cast happens to read fields that
exist on both, so it silently "works", but the narrative drops the
exitCode/durationMs that this branch should display.

**Root cause.** Copy-paste from the `tool_call_intent` branch.

**Remediation.** Cast to `ToolCallExecutedPayload`. Surface the exit code
and duration in the rendered summary.

---

## C. Cryptographic integrity — latent divergence risks

### [F-12] Go verifier chain replay uses `json.Marshal` instead of canonical JSON

**Where:** `apps/verify/chain/replay.go:148–163`

The replay computes event metadata with `json.Marshal(metadataMap)`. Go's
default JSON marshaler:
- HTML-escapes `<`, `>`, `&` as `<`, `>`, `&`.
- Renders `nil` maps as `null` (matches TS).
- Sorts map keys alphabetically (matches TS canonical-json).

The TypeScript producer's `canonicalJson` does **not** HTML-escape. For
event metadata (ULIDs, ISO timestamps, hex hashes, predefined enums) the
characters never collide in practice — but the same comment in
`apps/verify/manifest/manifest.go:166–170` explains that
`StripSignatureFields` uses `canonical.Marshal` *specifically to avoid
HTML escaping*, because the manifest can contain user content. The chain
replay path skips that same precaution.

If an `agentId`, `wallTs`, or `type` ever contained one of those three
characters, signed bundles would verify fine via `signature-verify` and
`artifact-events-jsonl` but fail `chain-replay`. The current event schema
prevents this, but the latent divergence violates the JCS-everywhere
contract `docs/canonical-json.md` declares.

**Root cause.** Two separate code paths in the Go verifier (`manifest`
package and `chain` package) made different choices about JSON encoding.

**Remediation.** Replace `json.Marshal(metadataMap)` with
`canonical.Marshal(metadataMap)` in `chain/replay.go`. Add a conformance
test that includes a metadata field containing `<`, `>`, and `&`.

---

### [F-13] Public key file is written with 0600

**Where:** `packages/chain/src/sign-ed25519.ts:115–116`

```ts
writeFileSync(pubPath, keyPair.publicKeyPem, 'utf-8');
chmodSync(pubPath, KEY_PERMISSIONS);  // 0o600
```
A public key is, by definition, public. Storing it 0600 has no security
benefit (the key is also embedded in every produced bundle) and causes
friction: a user running `sudo` on a service account can't read the
key under their own user, and key-management workflows that copy
`signing.pub` to a `.well-known` page fail with "permission denied" on
operating systems with multi-user homes.

**Root cause.** Constant `KEY_PERMISSIONS = 0o600` was applied to both
files without distinguishing them.

**Remediation.** Add `PUBLIC_KEY_PERMISSIONS = 0o644` and apply it to the
public key only. Update the threat-model and key-management docs to
reflect that `signing.pub` is, and should be, world-readable.

---

### [F-14] Env hash is collision-prone on values containing newlines

**Where:**
- `packages/capture-claude/src/env-allowlist.ts:50–53`
- `apps/capture-shim/record.go:170–180`

Both implementations compute:
```
fullEnv = sorted("k=v").join("\n")
envHash = SHA256(fullEnv)
```
A value containing `\n` is indistinguishable from the next key/value pair.
Two distinct environments can produce the same hash:
- `{ "A": "x\nB=y" }` → `"A=x\nB=y"`
- `{ "A": "x", "B": "y" }` → `"A=x\nB=y"`

Same hash, different environments. `envHash` is a tamper-evidence field,
not a confidentiality boundary, so the impact is limited — but it
defeats the whole point of capturing a hash.

**Root cause.** Newline as separator with no escaping.

**Remediation.** Compute `envHash` as
`SHA256(canonicalJson(sortedRecord))` — canonical JSON escapes embedded
quotes and newlines and is what the rest of the codebase already uses for
the same job. Update both TS and Go shim implementations identically.

---

### [F-15] Secret-bearing env values stored in plaintext by default

**Where:** `packages/capture-claude/src/env-allowlist.ts` and
`apps/capture-shim/record.go`

The default allowlist captures `AWS_*`, `GH_*`, `OPENAI_*`,
`ANTHROPIC_*`, `RAILWAY_*`. The threat model `docs/threat-model.md §1.1`
acknowledges that `AWS_SECRET_ACCESS_KEY` and `GH_TOKEN` are full
secrets, and recommends the producer "review `envSubset` before
sharing". This is producer-burden mitigation for a producer-mistake risk
DEPOSE itself created.

**Root cause.** Allowlist prefixes were chosen for evidentiary
*completeness* without considering that the same prefix typically
contains the most sensitive value in the entire bundle.

**Remediation.** Add a value-redaction policy: any env value whose key
matches a secret-name heuristic (`/SECRET|TOKEN|KEY|PASSWORD|CREDENTIALS/i`)
is replaced with `"sha256:<hex>"` in `envSubset`, with the original
content NOT stored anywhere in the bundle. The presence of the key is
evidentiarily sufficient ("the agent had `AWS_SECRET_ACCESS_KEY` set");
the value isn't needed and is actively harmful. Make this the *default*;
provide `--capture-secret-values` for the rare evidentiary case (e.g.,
proving the agent used a specific compromised token).

---

### [F-16] Hook hashes file contents for every Bash command, not just destructive ones

**Where:** `packages/capture-claude/src/file-hash.ts`,
`packages/capture-claude/src/hook-entry.ts:71`

The PreToolUse hook calls `hashFileArgs` for every `Bash`/`Edit`/`Write`
invocation. For `Bash`, `extractPathsFromCommand` regex-matches absolute
and `./`-prefixed paths in the command line and SHA-256s every file that
exists. A simple `cat /etc/passwd && grep something /var/log/system.log
&& ls /opt/very-large-blob.bin` will hash `/etc/passwd`, the system log,
and the blob — synchronously, blocking every tool call.

This is unnecessary work (most commands aren't destructive), adds
measurable latency to every Claude tool invocation, and reads files the
agent might not even touch.

**Root cause.** Hook design defaults to "capture everything that could
matter" without a heuristic for "this command is likely destructive".

**Remediation.**
1. Add a fast-path destructive-rules pre-check in the hook: tokenize the
   command, run the matchDestructiveRules logic against the bundled
   default ruleset. If the command does NOT match, skip file hashing
   entirely and record `fileArgs: []`.
2. For matched commands, only hash files that appear as explicit
   arguments to the destructive operation (not arbitrary paths anywhere
   in the command line).
3. Add a 100 MB per-file cap; above the cap, record `preSha256: null,
   sizeBytes: <stat>` so the limitation is visible.
4. Stream the hash instead of loading the whole file into memory.

---

### [F-17] Hook reads `ps` and `tty` synchronously on every tool call

**Where:** `packages/capture-claude/src/hook-entry.ts:148–197`

`walkProcessTree` calls `execSync('ps -o ppid=,comm= -p ...')` up to 10
times. `resolveTty` calls `execSync('tty')`. Each `execSync` spawns
`/bin/sh` and forks. On a Mac, an empty `execSync` is on the order of
10–20 ms; 11 of them is 100–200 ms of synchronous latency added to every
Claude tool call. For a session with 50 tool calls that's 5–10 seconds
of pure hook overhead.

**Root cause.** The hook uses subprocess `ps` because the Linux `/proc`
path was a later thought; on Linux the shim reads `/proc/<pid>/stat`
directly. The hook does not.

**Remediation.**
1. On Linux, read `/proc/<pid>/stat` directly (zero subprocesses).
2. On macOS, use `libproc.proc_pidinfo` via `node:os` or `process.pid`
   parent walking via `process.ppid`. macOS Node exposes `os.uptime()`,
   `os.userInfo()`, etc., but not a parent-pid syscall; if necessary,
   keep `ps` on macOS but call it *once* with a comma-separated list of
   pids (`ps -o pid=,ppid=,comm= -p p1,p2,p3,...`) — one `execSync` per
   tool call, not 10–20.
3. Cache the process tree per Claude Code session (the parent shell
   doesn't change mid-session) — first hook call resolves it, subsequent
   calls reuse the cached result.

---

## D. Bundle layout drift — files that lie about what's in the bundle

### [F-18] `raw/` and `artifacts/` directories are always empty

**Where:** `packages/bundle/src/writer.ts:273–294`

The writer always creates:
- `raw/claude-code/` (empty dir)
- `raw/shell-history/` (empty dir)
- `raw/git-reflog.txt` (empty file)
- `raw/capture/` (empty dir)
- `artifacts/files-pre/` (empty dir)
- `artifacts/files-post/` (empty dir)
- `attestations/rekor-entries.json` with `{"entries": []}`

The example bundles confirm: every one of these is empty on disk. The
README and `bundle-format.md` describe these as containing source JSONL,
shell history fragments, capture records, pre/post file content, and
Rekor entries.

This is bundle-format drift: the structure exists, the contents never
land. A recipient with the bundle has no way to re-derive the events from
the original sources — `events.jsonl` is the only artifact, and the
"raw sources are preserved" guarantee is false.

**Root cause.** The directory tree was scaffolded in Phase 1 with the
intent of filling it in Phase 2/3. The fill-in never happened, but the
empty scaffolding stayed.

**Remediation.**
1. Copy the source JSONL into `raw/claude-code/<source>.jsonl` verbatim.
   Compute its SHA-256 and add to the manifest counts (`counts.rawArtifacts.claudeJsonl`).
2. Copy any sibling `shell-history.txt`/`git-reflog.txt` into `raw/`.
3. Copy all capture records that contributed to the timeline into
   `raw/capture/`. The capture-record files are already JSON; just
   `cp` them.
4. Populate `artifacts/files-pre/` from capture records' `fileArgs` when
   full-content capture is opted in.
5. Stop emitting empty placeholder paths. If a source wasn't used,
   don't create its directory. The verifier should treat missing
   `raw/<source>` as "no events from that source" — currently the empty
   dirs read like "every source was present, just empty", which is
   actively misleading.
6. Stop emitting `attestations/rekor-entries.json: {"entries":[]}`. If
   no Rekor entries exist, omit the file. The verifier's check 8 already
   keys off `m.Rekor != nil`.

---

### [F-19] `producer.host.kernel` is the Node.js version, not the OS kernel

**Where:** `packages/bundle/src/manifest.ts:161–166`

```ts
host: {
  os: process.platform,    // "darwin" / "linux"
  arch: process.arch,      // "arm64" / "x64"
  kernel: process.version, // "v20.19.0" — Node.js version, not kernel
},
```

Example bundle confirms: `"kernel":"v26.0.0"`. That's Node 26, not a kernel
version.

**Root cause.** `process.version` was chosen because it was conveniently
available; the field name was not corrected.

**Remediation.**
1. Rename the field. Either:
   - `producer.host.kernel` → `producer.host.nodeVersion` and add a
     separate `producer.host.kernel` populated by `os.release()`.
   - Drop `kernel` entirely (the producer's kernel doesn't matter for
     evidence) and just record `producer.host.runtime: "node@" + process.version`.
2. Bump `schemaVersion` to 2 with a one-release migration period where
   both names are written.

---

### [F-20] Unimplemented Sigstore + Rekor paths are documented as available

**Where:**
- `packages/chain/src/sign-sigstore.ts` — throws on every call
- `packages/chain/src/rekor.ts` — throws on every call
- `docs/threat-model.md §3.3` — describes Sigstore keyless as a
  "preferred when available" mitigation
- `docs/architecture.md §2.4` — lists Rekor as the integrity layer's
  fourth bullet

Both modules export type definitions and one or two stub functions that
throw `"not yet implemented"`. The threat model and architecture docs
treat them as live options. A reader who follows the threat model's
recommendation runs into runtime errors.

**Root cause.** Scaffolds shipped; implementations didn't.

**Remediation.** Two choices, pick one. Don't ship the scaffolds-as-docs
state.
- **Option A — implement.** Sigstore client (`@sigstore/sign` is on npm
  and works in Node); Rekor submission is a single signed HTTP POST.
  Both fit in ~150 lines each.
- **Option B — delete and document the choice.** Remove
  `sign-sigstore.ts` and `rekor.ts` entirely. Strike the references from
  threat-model and architecture. Make the docs honest: Ed25519 + RFC 3161
  is the only signing path today.

I recommend **Option A** for Sigstore (it's load-bearing for the
"long-term-key-compromise" mitigation the threat model relies on) and
**Option B** for Rekor (the producer can submit to Rekor out-of-band; it
isn't on the critical path for evidence integrity).

---

### [F-21] `depose explain` is misleading

**Where:** `packages/cli/src/commands/explain.ts`

The command's output is wrapped in a banner that says "AI-GENERATED
COMMENTARY — NOT EVIDENCE." The implementation is deterministic
template rendering. The comment at line 134 admits: "no actual LLM call
— this is a template-based commentary".

Two problems:
1. **It's not AI-generated.** Calling it that and adding a scary banner
   teaches recipients to ignore similar banners elsewhere — including the
   `dev-unsigned` banner, which IS load-bearing.
2. **It duplicates `narrative.md`.** Both are deterministic
   timeline summaries. The only difference is the surrounding banner.

**Root cause.** The command was designed for a future LLM-narrated
postmortem; it shipped with a placeholder implementation that never got
upgraded.

**Remediation.**
- If you want the LLM-narrated mode, actually implement it (call out to
  Claude API with the timeline as context). Keep the banner — the
  banner is the contract that protects the rest of the bundle.
- If you don't, delete `depose explain` entirely. `narrative.md` already
  covers the deterministic-summary use case. A misleading subcommand is
  worse than no subcommand.

I recommend deletion. The narrative is sufficient.

---

## E. UX and CLI simplification

### [F-22] CLI has redundant subcommands that confuse first-time users

**Where:** `packages/cli/src/commands/main.ts`

The current command surface:
```
depose reconstruct  → produces a dev-unsigned bundle
depose package       → produces a signed bundle (or dev-unsigned with --skip-timestamp)
depose verify       → only prints a "use depose-verify instead" message
depose explain      → produces a non-evidence "AI" commentary that's actually a template
depose install      → install claude hook and/or shell shims
depose uninstall    → reverse
depose key fingerprint → print signing key fingerprint
```

Issues:
1. **`reconstruct` vs `package`.** Reconstruct is `package --skip-timestamp` minus the network round-trip and minus the chain build. Two commands for two modes of the same operation, with a third mode (`package --skip-timestamp`) that overlaps with both.
2. **`verify`** exists only to print an error pointing at the Go binary. It's a usability anti-pattern: users type `depose verify` and get told they were wrong.
3. **`explain`** see F-21.

**Remediation.** Collapse to a smaller, honest surface:

```
depose record [--from-claude PATH] [--unsigned]
    Produces a bundle. Defaults to signed mode. --unsigned skips
    signing and timestamping for pipeline tests.

depose install [--claude] [--shell]
    Active capture installation.

depose uninstall [--claude] [--shell]

depose key fingerprint [--ssh]
```

That's it. No `reconstruct`, no `verify`, no `explain`. Old commands stay
as aliases for one minor release printing a deprecation warning, then
removed.

The single-command surface aligns with what users want: "make a bundle."
Mode is a flag, not a verb.

---

### [F-23] `install --shell` symlinks the shim even when copy would be simpler

**Where:** `packages/cli/src/commands/install.ts:209–243`

`installShellShims` copies `depose-shim` to `~/.depose/bin/depose-shim`,
then `symlinkSync` for each name in the allowlist. If the user later
moves or deletes `~/.depose/bin/depose-shim`, all the named symlinks
break. Worse, `existsSync(linkPath)` followed by `symlinkSync` has a TOCTOU
race; the explicit "try readFileSync to test for broken symlink" branch
at line 228 reads "will throw for broken symlinks" but then doesn't do
anything with the result. Dead-code masquerading as logic.

**Root cause.** Symlink-then-skip-on-EEXIST was the simplest thing but
not robust to a redo.

**Remediation.**
1. Make the install idempotent: if a target name exists and is already a
   symlink pointing to `targetShim`, leave it. If it points somewhere
   else, fail with a "this name is already shimmed to X" message. If it
   doesn't exist, create the symlink. No silent EEXIST swallowing.
2. Delete the dead `readFileSync` "broken symlink" branch.
3. Provide a `--force` flag to replace conflicting names.

---

### [F-24] `produce.sh` is the documented quick-start, but the README says `package` directly

**Where:** README `Quick start` section vs.
`examples/datatalks-reconstruction/produce.sh`

The README tells users to run:
```bash
./packages/cli/bin/depose package --from-claude path/to/session.jsonl --skip-timestamp
```
The example reconstruction scripts hide that complexity behind
`produce.sh`. The two paths diverge: one shows `--skip-timestamp`, the
other doesn't (depends on `DEPOSE_DEV_UNSIGNED`). Users following the
README hit the FreeTSA network call by default; users running the
example don't.

**Root cause.** Two parallel ergonomic surfaces ended up in slightly
different states.

**Remediation.**
1. Pick the README's quick-start as canonical. The example `produce.sh`
   should call the same canonical command with the same flags. Make
   `DEPOSE_DEV_UNSIGNED=1` work in both paths (currently README path
   doesn't have it).
2. Document one canonical happy-path in the README. The example
   `produce.sh` becomes a wrapper, not a divergent path.

---

### [F-25] No `--help` example for the verifier-side pinning flags

**Where:** `apps/verify/main.go:23–28`

`depose-verify`'s usage message is:
```
Usage: depose-verify verify <path-to-bundle>
       depose-verify version
```
It doesn't mention `--expected-key-fingerprint` or `--signer-identity`,
which are the load-bearing mechanisms the threat model promises for
defending against compromised producer keys (`§3.3`). The flags work; the
help doesn't advertise them. A recipient following the threat model has
no way to know the flags exist without reading source.

**Remediation.** Update the usage string in `main.go` to:
```
Usage: depose-verify verify [options] <path-to-bundle>

Options:
  --expected-key-fingerprint <hex>    Reject the bundle if its producer
                                       key fingerprint does not match.
  --signer-identity <regex>           (Future) Sigstore signer identity
                                       binding.

Commands:
  verify        Validate a .depo bundle.
  version       Print the verifier version.
```

---

## F. Tests, fixtures, and CI

### [F-26] No fixture from a real Claude Code session

**Tests pass because every JSONL fixture in the repo was hand-written to
match the normalizer's expectations.** See F-01. A fixture from a real
session would have caught the regression on day one.

**Remediation.** Add `tests/fixtures/real-claude-code/session-*.jsonl`
containing one or two redacted real-session captures. Wire them into the
normalizer test suite. A reasonable bar: every non-`thinking` block in the
real fixture must yield exactly one event with the right `type`; the
total `gap` event count must be 0 for the recognized line types.

---

### [F-27] No round-trip determinism test

The architecture doc claims "reproducibility audits" via byte-identical
rebuilds. There is no CI step that produces the same bundle twice and
diffs them. Given F-03, two runs of `depose package` over the same JSONL
produce *different* `rootHash` values today. The reproducibility claim
needs a test or a retraction.

**Remediation.** Add a CI step:
1. Pin the clock via `setFixedUlidSeed`.
2. Run `depose package --skip-timestamp` twice into two distinct output
   dirs.
3. Recursively diff. The diff must be empty.
This catches every form of nondeterminism: clock leak, env leak, map
iteration order, etc.

---

### [F-28] CI doesn't actually run the Go tests

`pnpm test` runs the TypeScript suite. The README mentions `Go test
./... under apps/verify` but it isn't part of the default `pnpm test`
target. `package.json:test` is just `vitest run`.

**Remediation.** Add a top-level `pnpm test:go` script that wraps
`(cd apps/verify && go test ./...) && (cd apps/capture-shim && go test ./...)`
and make `pnpm test` call both. Today the Go tests are easy to forget.

---

### [F-29] Dead variables in `shell-history.ts`

Lines 104–127 declare `_monoNs`, `_prePayload`, `_postPayload` — all
unused. ESLint should be flagging this, but the underscore-prefix
convention suppresses the warning. They're not unused-for-future-use;
they're unused because the original implementation didn't get
finished. Delete them.

**Remediation.** Delete the unused variables. Configure ESLint to flag
underscore-prefixed unused variables in non-test code (or document
that the prefix is reserved for legitimately unused arguments).

---

## G. Documentation drift

### [F-30] README claims 252 tests across 23 files — accurate; but coverage of real-world inputs is zero

The README is technically correct on every count, but it implies that
"252 tests" means the producer is verified end-to-end. The tests test
the synthetic fixtures the project ships. F-01, F-02, F-03 all pass
every test. Either the README needs to qualify what the tests cover, or
the tests need to actually cover real-world inputs (preferred).

**Remediation.** Address F-26 (real fixtures) and F-27 (round-trip
determinism). The number 252 becomes meaningful once those exist.

---

### [F-31] `docs/threat-model.md §3.3` references key-management mitigations that depend on unimplemented Sigstore

The doc says: "Sigstore keyless (preferred when available). … The
producer-side path is scaffolded in `packages/chain/src/sign-sigstore.ts`;
the verifier already accepts `--signer-identity <regex>`." The producer
path throws "not yet implemented" on every call. The verifier's
`--signer-identity` is a no-op placeholder (see `apps/verify/cmd/verify.go:217–225`).

**Remediation.** See F-20. Either implement or remove the claim.

---

### [F-32] `architecture.md §3` claims data flow is strictly unidirectional, but `mergeEvents` writes back into events

`mergeEvents` mutates `tool_result.payload.linkedShellCommandPreId` and
`tool_call_intent.payload.linkedShellCommandPreId` in place during the
correlate step (`merge.ts:158–164, 169–180`). After mutation, the
event's `payloadHash` is stale (it was computed in the normalizer over
the original payload). The chain pass recomputes `chainHash` from
`payloadHash` not from `payload` — so the chain looks valid, but the
recorded `payloadHash` no longer matches the actual payload bytes.

This works today because the Go verifier's `recomputePayloadHash` step
(F-12 area, `chain/replay.go:200–223`) re-canonicalizes the payload from
the on-disk JSONL — which contains the *post-mutation* payload (the
writer serializes the mutated event), so re-hashing finds the same
`payloadHash` the producer stored. But there is no enforcement that
`payloadHash` is recomputed after mutation; it's accidental.

**Root cause.** Correlation should produce a *new* event (or a new field
outside the payload), not mutate the payload of an existing event.

**Remediation.**
1. Move correlation metadata (`linkedShellCommandPreId`) into a
   *separate* event-level field (`event.correlation`) outside `payload`,
   so it isn't hashed into `payloadHash`. Correlation is metadata about
   the timeline, not part of the event's intrinsic content.
2. Alternatively, after mutating payload, re-run
   `event.payloadHash = sha256(payload)`. Add a `merge.ts` test that asserts
   `payloadHash === sha256(payload)` for every event post-merge.

I recommend #1. Correlation is a reconstruction artifact, not a
producer-attested fact about the event itself.

---

## H. Honest-claims hygiene

### [F-33] Threat-model §3.4 cosign-verify regex hard-codes the org name

`docs/threat-model.md` and `packages/bundle/src/constants.ts:7` both
hard-code `Aftermath-Technologies-Ltd/depose`. If the repo moves
(rename, fork, transfer), every verify.txt in every produced bundle
points at the wrong place and every cosign verification fails. This is
load-bearing for the verifier-binary trust chain (`§3.4`).

**Remediation.** Move the slug to a build-time constant injected from
`pnpm package`. Document the upgrade path: a producer running a future
release writes new bundles with new identity URLs; old bundles are
verified by the verifier release whose URL matches *their* manifest.

---

### [F-34] CI grep that "blocks merges if VERIFIER_DOWNLOAD_URL appears elsewhere" — referenced but not visible

`packages/bundle/src/constants.ts:5–7` says "A CI grep in
`.github/workflows/ci.yml` blocks merges if the URL appears anywhere else
in the codebase." If true, this is good hygiene. If not, it's a doc
that comforts the reader without doing anything.

**Remediation.** Verify the grep exists; if it doesn't, add it (a one-line
`grep -rn "https://github.com/...releases/latest" -- ':!packages/bundle/src/constants.ts' && exit 1`).
If it does, no action needed.

---

## Prioritization

Tackle in this order. Each tier is internally parallel; tiers themselves
should be sequential because earlier ones affect the test fixtures and
schema versioning that later ones build on.

**Tier 1 — Correctness foundation (do first).**
- F-01 (real JSONL normalizer) — unblocks every downstream claim.
- F-26 (real fixtures) — without this, F-01 can regress silently.
- F-03 (ULID encodes event time, not packaging time).
- F-04 (validate TSR before bundling).
- F-05 (depose-hook in `bin` map; absolute path in settings).

**Tier 2 — Schema and host honesty.**
- F-02 (split producer-host vs. session-host fields).
- F-19 (rename `kernel` field).
- F-32 (move correlation out of payload).
- F-09 (gap reason for unparseable JSONL).
- F-15 (redact secret-key values by default).
- Bump `schemaVersion` to 2 once. Migration path documented in
  `bundle-format.md §8`.

**Tier 3 — Cleanup, dead code, drift.**
- F-06 (correlator on tool_result).
- F-07 (pipe-aware shell tokenizer).
- F-08 (fish parser: implement or remove).
- F-10 (monoNs collision on tool_calls).
- F-11 (narrative type cast).
- F-12 (Go canonical-json in chain replay).
- F-13 (public key 0644).
- F-14 (env hash uses canonical JSON).
- F-16 (hook file-hashing only for destructive commands).
- F-17 (hook process-tree latency).
- F-18 (bundle layout: stop emitting empty stubs; copy raw sources).
- F-29 (dead variables).

**Tier 4 — Surface area, docs.**
- F-20 (sigstore + rekor: implement A or delete B).
- F-21 (delete `depose explain` or implement it for real).
- F-22 (collapse CLI commands).
- F-23 (install --shell idempotency).
- F-24 (one canonical quick-start).
- F-25 (verifier help text).
- F-27 (round-trip determinism CI).
- F-28 (Go tests in `pnpm test`).
- F-30, F-31, F-33, F-34 (doc honesty).

---

## What's *not* on this list

Things I checked and did not find a problem with:

- **Ed25519 signing scheme.** Pure Ed25519, signed bytes are canonical
  JSON of the unsigned manifest, verifier matches. No pre-hash, no
  cross-language seam. Correct.
- **IRONROOT chain construction.** TS producer and Go verifier compute
  the same chain (modulo F-12's latent HTML-escape risk, which can't be
  triggered by today's schema).
- **`eventsJsonlSha256` and `rulesetHash` pinning.** Both belt-and-braces
  on top of the chain. Correct and well-tested.
- **`mode-contract` enforcement.** `signed` and `dev-unsigned` are
  cleanly separated; the verifier refuses to pretend dev-unsigned is
  evidence even on a green run. Correct.
- **`--expected-key-fingerprint` pinning.** Works end-to-end when used;
  the only issue is discoverability (F-25).
- **Verifier's RFC 3161 path** (`apps/verify/timestamp/rfc3161.go`). Real
  ASN.1 parse, real PKCS7 signature check, real cert chain validation,
  real anti-backdating. Correct.
- **`schemaVersion` enforcement.** Verifier fails closed on unsupported
  versions. Correct.

The verifier is solid. The producer is where the work is.
