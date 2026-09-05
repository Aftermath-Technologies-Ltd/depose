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
