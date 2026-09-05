# Design decisions

Forks the spec and CLAUDE.md did not settle, and the option taken. The
rule applied throughout: when in doubt, make the verifier stricter.

## D1. Shell tokenizer is hand-written, not shell-quote

The CLI ships with `yaml` as its only runtime dependency, and the
tokenizer sits on the trust boundary (it decides whether a destructive
rule fires). A third-party parser would add a dependency whose quoting
bugs become false negatives in evidence. `packages/core/src/reconstruct/shell-split.ts`
is about 300 lines, covers quoting, heredocs, redirections, subshells,
and substitutions, and every construct has a fixture. The Go side needs
no counterpart: neither the verifier nor the replay path matches rules,
so `mvdan.cc/sh` is not pulled in.

## D2. Files map excludes the attestation artifacts and binds them by equality

`manifest.json`, `attestations/signatures.json`, and the `.tsr` files are
derived from the finished manifest, so they cannot be hashed into it
without a circular dependency. Rather than a second signature pass
(which would leave the timestamp token committing to a superseded
manifest), the verifier checks `signatures.json` against
`manifest.signatures` and each `.tsr` against the decoded
`manifest.timestamps[i].tokenBase64`, both already covered by the
signature. Nothing in the tree is unpinned.

## D3. schemaVersion 3, and a v2 bundle's missing files map is WARN

The files map is a new signed field, so the schema version bumps to 3
and the verifier supports [2, 3]. A v2 bundle cannot carry a map; failing
it would reject every bundle sealed before this change for something its
schema never promised. The verifier reports WARN with an explicit list of
what is not covered, and a v3 bundle without a map fails.

## D4. `depose explain --bundle` writes beside the bundle

Once every file in the tree is pinned, writing `commentary.md` into a
sealed bundle makes it fail verification. The command now writes
`<bundle>-commentary.md` next to it. The command is deprecated anyway.

## D5. capture_failed records from stdin read or parse failures are unattributed

If the hook cannot read or parse its input, it does not know the
session id. The record carries `sessionId: null` and follows the same
scoping rule as any unattributed capture: excluded unless the producer
passes `--include-unscoped-captures`. Guessing a session for it would
put an inferred association into signed evidence.

## D6. Check status is a four-value enum

`PASS`, `FAIL`, `SKIPPED`, `WARN`. A check that did not run is never
rendered as a pass, and a downgrade (an older schema lacking a newer
guarantee) is distinguished from a tamper.

## D7. RFC 3161 tokens must be strict DER, on both sides

The Go fuzzer found that digitorus/pkcs7's BER-to-DER converter panics on
a two-byte input. The verifier now walks every token as strict DER
(definite lengths, minimal length encoding, bounded nesting, no trailing
bytes) before handing it to the library, and runs the library under a
recover guard so a parser panic is an error rather than a crash. The
producer's own DER reader applies the same rules. RFC 3161 specifies DER,
so no conforming TSA is rejected; a BER-emitting TSA fails validation on
the producer, which then tries the next TSA.

## D8. events.jsonl order is verified, not repaired

TypeScript required pre-sorted input and Go re-sorted before replay. Two
behaviours for one file is a divergence, and the lenient one lets a file
that reads one way on disk replay to a root sealed over another. Both
sides now require ascending id order: the producer throws before sealing
and the verifier fails `chain-replay` on an unsorted file. The
`unsorted-input-rejected` vector pins this. Replacing the insertion sort
with a library sort (planned for the performance phase) is moot: there is
no sort.

## D9. monoNs is a decimal string on the wire

Go read `monoNs` as an int and JavaScript as a double; they diverge past
2^53, which a nanosecond monotonic clock reaches after 104 days of
uptime. Schema 3 writes `monoNs` as a decimal string; TypeScript holds a
bigint and Go an int64. The verifier accepts the numeric form only for
schema 2 bundles and fails a schema 3 bundle that uses it. The
`monons-above-2-53` and `monons-int64-max` vectors pin the digits.

## D10. The verifier stops after a bad signature, and nowhere else it need not

A failed signature means nothing the manifest pins can be trusted, so the
remaining checks would only report consequences of the same defect. A
missing narrative, a bad ruleset hash, or a files-map mismatch leaves the
other checks meaningful, so they still run and the report lists every
defect. The stop points are: manifest-parse, schema-version,
mode-declaration, signature-verify.

## D11. Committed fields are sealed in the committed form, and the original bundle keeps the openings

SD-JWT-style selective disclosure only works if the sealed record already
carries commitments; a disclosure cannot retrofit them. So the producer
commits every disclosable field at seal time and stores the openings in
`commitments.json`, pinned by the files map and opened by the verifier
on every full-bundle run. The narrative and the destructive-rule counts
are computed from the plaintext before commitment, so nothing a reader
sees changes; only `events.jsonl` carries placeholders. Recipients who
want the plaintext read it from the openings, which is what
`restoreEvent` does.

## D12. Tool inputs inside assistant messages are committed too

`assistant_message.toolCalls` duplicates every tool input in plaintext.
Leaving it out of the default disclosable list would make committing
`tool_call_intent.toolInput` decorative. It is committed by default.
Prompt and assistant text are not, because the task's default names tool
inputs, tool outputs, file contents, and environment values; the ruleset
knob is documented for producers whose prompts are sensitive.

## D13. Withheld events disclose their chain hash, not just their leaf hash

A disclosed event's chain link is `SHA-256(prev || payloadHash || meta)`.
Verifying that link is what binds the disclosed bytes to the leaf; a
leaf hash alone would let an attacker keep a valid leaf while rewriting
the event under it. So a withheld position carries its chain hash and
the verifier recomputes every disclosed event's link from its
predecessor. The chain hash is a SHA-256 over metadata and a payload
hash; it reveals nothing beyond position unless the whole event can be
guessed, and for any event with a committed field that means guessing a
32-byte salt.

## D14. Consistency proofs are implemented and wired, with an honest scope note

RFC 6962 consistency proofs, `--consistent-with`, and
`depose-verify consistency` are complete and pinned by vectors. Two
seals share a prefix only when their chain hashes do, which requires the
same commitment salts for the shared events. Nothing today reuses salts
across seals except the deterministic fixed-seed mode, so in practice
consistency holds between disclosures of one seal (trivially, equal
roots) and the larger-tree path is exercised by tests and vectors. A
future `depose record --extend <bundle>` that reuses openings would make
it hold across incremental seals; that is noted rather than built.

## D15. The signed half of the intent-effect binding is the effect's payload

An effect can name its intent inside its own payload, where the value is
hashed into `payloadHash` and covered by the chain and the signature. An
intent cannot name its effect the same way: the effect does not exist
when the intent is written, and rewriting a sealed event afterwards is
exactly what the format forbids. So the reverse link lives in the
event's `correlation` block, which is outside `payloadHash` but still
covered by the signature through `manifest.files["events.jsonl"]`.

The verifier treats the payload as authoritative and fails when the
correlation disagrees with it. The alternative, dropping the reverse link
so there is nothing to disagree with, would have made the timeline harder
to read for no gain in strength: a bundle where the two disagree has been
edited, and saying so is better than not noticing.

## D16. Gaps are required, not advisory

`intent_without_effect`, `effect_without_intent`,
`unwitnessed_file_change`, and `kernel_execve_without_hook` are emitted
by the producer's own merge, so an honest bundle always has them. The
verifier therefore requires them: a bundle with an unclosed intent and no
gap disclosing it fails `intent-effect`, and a file whose hash moved with
no gap disclosing it fails `file-continuity`.

This is the stricter of the two readings. The looser one, reporting the
condition as a warning, would let someone delete the gap events and get a
clean report, which turns the disclosure into decoration. The cost is
that a producer who writes events.jsonl by hand has to emit the gaps too;
that cost falls on the producer, which is where it belongs.

`intent_without_effect` is only required for intents whose source is
`claude-pretooluse`. A reconstructed intent, rebuilt from a session log
or a shell history, never promised an outcome, and demanding a gap for
every one of them would bury a real finding under hundreds of empty ones.

## D17. The eBPF probe is assembled in Go, not compiled from C

The standard way to build a cilium/ebpf program is `bpf2go`: write C,
compile with clang, check in the generated object. That makes the build
depend on a C toolchain and puts a binary blob in the repository that a
reader has to take on trust.

The probe here is small enough to avoid both. It makes three helper calls
and writes a fixed 32-byte record, and it reads nothing out of the
tracepoint context, so it is about twenty instructions of `cilium/ebpf/asm`
that anyone auditing the capture path can read in one screen. `go build`
is the whole toolchain.

The price is that the probe cannot parse the tracepoint's `filename`
field, so argv, cwd, and the executable path come from `/proc` in
userspace and are lost when a process exits before they can be read.
Such a record is still written, with an empty `argv`, because an exec
that was witnessed and not characterized is a finding rather than
nothing. See `docs/capture-coverage.md` for what that costs.

## D18. macOS gets no kernel collector at all

Apple's Endpoint Security framework needs an entitlement granted per
developer account, and the older openbsm audit pipeline is deprecated
and disabled by default. Neither is something DEPOSE can ship and have
work on a user's machine.

The collector therefore refuses to start on macOS with an error saying
so, and `docs/capture-coverage.md` records the status as "not supported,
hook only". A stub that loads and records nothing would let a macOS
bundle look kernel-witnessed when it is not, which is worse than the
missing feature.

## D19. A bundle is sealed even when no timestamp authority answers

The writer used to throw when every TSA failed, so a laptop with no
network produced no bundle at all. That is the worst outcome available: a
signature made now binds the content whether or not anyone has dated it
yet, and the anchor, when it arrives, still commits to the same manifest
bytes.

`depose record` now seals with `anchorStatus: "pending"` and warns, and
`--require-anchor` restores the old fail-closed behaviour for producers
whose policy needs it. The verifier reports an unanchored bundle as WARN,
not FAIL: nothing about it is invalid, it is simply weaker evidence, and
the report says exactly how ("the producer's own clock is the only
evidence of when this happened").

## D20. The anchor never touches the seal

`depose anchor` changes nothing the signature covers. Adding the token to
`manifest.timestamps` would have worked, because the signing form strips
that field, but it would mean the evidence a recipient checked yesterday
is not the evidence they check today, and a format whose whole claim is
tamper-evidence should not have a supported way to rewrite the sealed
document.

The one field the command does rewrite in manifest.json is
`anchorStatus`, from `pending` to `anchored`. That is a label outside the
signing form, and leaving it stale would mean a bundle that says pending
while carrying an anchor. `anchorBundle` itself touches no file the
bundle already had.

The anchor goes in `attestations/anchor.json` with its own
countersignature. The countersignature is not decoration: a timestamp
over a public manifest is something anyone can obtain, so without it a
third party could bolt a token onto someone else's bundle and have it
read as the producer's act. The verifier requires the countersigning key
to be the key that signed the manifest.

`anchorStatus` in the manifest is the one thing `depose anchor` rewrites,
and it is a label rather than evidence: it sits outside the signing form
next to `signatures` and `timestamps`, and the verifier derives the real
state from the tokens and the anchor document, which authenticate
themselves.

## D21. TSA order is randomized per run

A fixed endpoint list means the first authority witnesses nearly every
bundle a producer ever makes. That concentrates the request load on one
free service and the trust in one operator, and it means a single
authority's outage stops every seal until the fallback path is exercised
(which, being unexercised, is where the bugs live).

Each run shuffles the list and retries each endpoint with an exponential
backoff before moving on. `preserveOrder` exists for the case where a
producer's policy genuinely ranks its authorities, and the ruleset's
`tsa` list is where that ranking is written down.

## D22. Sigstore and Rekor were removed, not finished

`sign-sigstore.ts`, `rekor.ts`, and `rekor.go` were scaffolds: every
entry point threw, `shouldUseSigstore()` returned a decision nothing
acted on, the verifier's `--signer-identity` flag was parsed and never
enforced, and `rekor-verify` printed a check name for a thing that had
never run. Four documents described the feature as forthcoming.

The choice was to wire it up with sigstore-js or to take it out.
Wiring it up means a new runtime dependency in the CLI, which the
project's own rules forbid, and it means a second signing scheme to
maintain on the trust boundary for a benefit (no long-lived key) that
matters mainly to CI producers.

Taking it out costs nothing that existed. Scaffolding for an
unimplemented security feature is worse than its absence: it puts a
name in the manifest schema, a flag in the verifier's help text, and a
row in the docs, all of which read as capability to someone deciding
whether to trust a bundle. `SignatureBlock.scheme` now accepts only
`ed25519`, and the manifest has no `rekor` field.

## D23. Codex rollout format detection is recorded, not assumed

Codex has changed its session log format at least once and carries no
version marker, so the normalizer decides which grammar it is reading by
looking for the `{timestamp, type, payload}` envelope. A guess that
silently produced an empty timeline would look identical to a session
where the agent did nothing.

The detected grammar goes into `manifest.session.sourceFormat`, inside
the signed form. A reader arguing about what a timeline means needs to
know which parser produced it, and that is a claim the producer should
have to sign rather than one a reader has to reconstruct.

When a rollout parses and yields no conversation turn at all, the
normalizer says so in a warning that names the detected format, because
that is the shape a third format drift will take.

## D24. argvHead matches past a tool's global options

`terraform -chdir=infra/prod destroy -auto-approve` did not match a rule
written as `["terraform", "destroy"]`, because argvHead is a strict
prefix and the subcommand was not at position one. The same hole covered
`git -C /repo push --force` and `kubectl -n staging delete ns prod`. It
surfaced while building examples/kiro-cost-explorer, whose whole point is
that command.

The fix matches argvHead against argv as written and against argv with
the leading run of options removed, and fires on either. Both attempts
are kept because stripping alone would break the rules whose head names
the command's own flags: `["rm", "-rf"]` has to keep matching
`rm -rf /data`.

Only the leading run is stripped, and only up to the first non-option
token. Everything after the subcommand belongs to the subcommand, and a
rule that names those arguments means them. Options that take a
separated value (`-C /repo`) are listed explicitly rather than inferred:
guessing wrong eats the subcommand, and `git -c push` read as an option
and its value would stop the `push` rule firing.
