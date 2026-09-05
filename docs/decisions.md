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
