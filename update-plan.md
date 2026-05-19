# DEPOSE update plan — to production grade

**Goal.** Make every claim DEPOSE prints on a bundle, in a README, or in a `verify.txt` true under adversarial review. The current foundation is good; the gap is where claims and implementation disagree. We close that gap by fixing root causes, not by softening claims.

**Non-goals.** No new layers, no new packages, no new abstractions for hypothetical use cases. We finish what exists, delete what's wrong, and replace hand-rolled crypto-adjacent code with stdlib or well-vetted libraries. We never widen scope to escape a fix.

**Sequencing rule.** Workstream A blocks everything else — if the bundle a producer creates is not internally correct, nothing downstream matters. B follows A. C/D/E run in parallel after A. F closes the loop.

---

## Workstream A — bundle correctness invariant

The bundle must be a self-contained record where every file means what its name says, every claim in the manifest is independently checkable from the bundle's contents, and every produced bundle passes the verifier. Today this is not true.

### A1. Default rules path is resolved against the CLI package, not CWD [DONE]

**Root cause.** `resolve('../rules/destructive.default.yaml')` in `cli/src/commands/{main,package,explain}.ts` is CWD-relative. From `examples/datatalks-reconstruction/`, it resolves to a non-existent file. `loadDestructiveRules` returns `[]`, no destructive op gets flagged, the headline feature silently fails.

**Fix (root cause).** The default ruleset ships with the `@depose/cli` package as a package resource. Resolution uses `fileURLToPath(import.meta.url)` to locate the rules relative to the installed package, never CWD. The `rules/` directory at repo root moves under `packages/cli/rules/` (or stays where it is and the CLI uses a relative-to-package path); either way, the resolution is package-anchored.

**Verify.** Add `cli/test/commands.rules-default.test.ts` that invokes `depose package` from three different CWDs and asserts `counts.destructiveOperations > 0` for a fixture session with a known `rm -rf`. Example `produce.sh` scripts must NOT pass `--rules` — finding the default is the test.

**Touches.** `packages/cli/src/commands/main.ts:237`, `packages/cli/src/commands/package.ts:79`, `packages/cli/src/commands/explain.ts:83`, new `packages/cli/src/rules-default.ts`.

### A2. Bundle must contain the actual ruleset, not the hash of it [DONE]

**Root cause.** `packages/bundle/src/writer.ts:266` writes `rulesetHash` (a hex string) to a file named `destructive.yaml`. The bundle no longer carries the ruleset; a third-party auditor cannot reconstruct what rules were applied.

**Fix.** The bundle writer takes both the parsed rules and the original ruleset bytes (`rulesetBytes: Buffer`). It writes `rulesetBytes` verbatim to `rules/destructive.yaml`. The manifest's `rulesetHash` is computed from those same bytes. The verifier independently re-hashes `rules/destructive.yaml` and compares to `manifest.rulesetHash` — this becomes a new verifier check, `ruleset-integrity`.

**Verify.** New verifier check `ruleset-integrity` in `apps/verify/cmd/verify.go`. New writer test asserting `sha256(file("rules/destructive.yaml")) === manifest.rulesetHash` and `file("rules/destructive.yaml") === input bytes`.

**Touches.** `packages/bundle/src/writer.ts`, `packages/bundle/src/manifest.ts`, callers in `cli/src/commands/{main,package}.ts`, `apps/verify/cmd/verify.go`.

### A3. Bundle mode is explicit; the verifier enforces the declared contract [DONE]

**Root cause.** `--skip-timestamp` produces a bundle that looks signed (real Ed25519 sig, real chain) but is missing the timestamp — the verifier rejects it because it can't tell whether timestamps were *intentionally* skipped (dev) or *removed* (tamper). Today, every example bundle fails verification for this reason.

**Fix.** Manifest gains `producer.mode: "signed" | "dev-unsigned"`. `dev-unsigned` rules:
- Directory named `incident-unsigned-<id>` (not `incident-<id>`).
- `verify.txt` and `narrative.md` carry a top-of-file `THIS IS A DEVELOPMENT BUNDLE — NOT EVIDENCE` banner.
- `signatures: []` and `timestamps: []` are required (not just allowed).
- Verifier reports the mode loudly and refuses to print "PASS" — it prints `PASS (dev-unsigned — not evidence)`.

`signed` mode is the only mode acceptable for evidence and *requires* both signatures and timestamps. The verifier rejects a `signed`-declared bundle missing either, as today.

**Verify.** Tests in both producers and the Go verifier covering both modes. Example bundles run in `signed` mode in CI against a real TSA (see E1).

**Touches.** `packages/bundle/src/manifest.ts`, `packages/bundle/src/writer.ts`, `apps/verify/manifest/manifest.go`, `apps/verify/cmd/verify.go`, all example `produce.sh`.

### A4. Canonical JSON has a single specification with conformance vectors [DONE]

**Root cause.** The TS canonical JSON and Go's re-marshal must produce byte-identical output for signatures to verify cross-language. There is no specification document and no conformance test. `StripSignatureFields` in Go uses `json.Marshal` without `SetEscapeHTML(false)`, so any manifest containing `<`, `>`, or `&` will mismatch.

**Fix.** Adopt RFC 8785 (JCS — JSON Canonicalization Scheme). It exists for this reason. Write `docs/canonical-json.md` referencing JCS with the subset we use. Both TS (`packages/core/src/events/canonical-json.ts`) and Go (`apps/verify/manifest/`) implement JCS. Add `tests/conformance/canonical-json-vectors.json` with ~30 vectors covering escapes, number forms, key ordering, nested structures, unicode. Both languages run the conformance suite in CI.

**Verify.** Conformance suite passes in TS and Go. New CI job `conformance-canonical-json` blocks merges if vectors disagree.

**Touches.** `packages/core/src/events/canonical-json.ts`, `apps/verify/manifest/manifest.go`, new `tests/conformance/`, new CI job.

### A5. SchemaVersion is enforced [DONE]

**Root cause.** Manifest carries `schemaVersion: 1`. The verifier never checks it.

**Fix.** Verifier rejects any `schemaVersion` it does not support, with a clear error. Compatibility policy in `docs/bundle-format.md`: a verifier supports the range `[N-1, N]`; breaking changes bump N. We are still at v1 — no production bundles exist — so structural changes from A1–A4 land *before* v2 is cut.

**Verify.** Test: forge a v999 manifest, verifier exits non-zero with `unsupported schemaVersion`.

**Touches.** `apps/verify/manifest/manifest.go`, `apps/verify/cmd/verify.go`, `docs/bundle-format.md`.

---

## Workstream B — cryptographic verification is real

### B1. RFC 3161: parse the token, verify the chain, verify the signature [DONE]

**Root cause.** `apps/verify/timestamp/rfc3161.go:97-110` "verifies" a TSA token by **byte-substring scan over the DER blob** for the expected hash. No ASN.1 parsing, no certificate chain validation, no signature verification on `TSTInfo`. A forger can append the expected hash to any DER and pass. This is the most embarrassing defect in the codebase.

**Fix.** Use `github.com/digitorus/timestamp` (maintained, widely used, RFC 3161 compliant). It parses the `TimeStampToken`, exposes the `TSTInfo`, verifies the embedded signing certificate, and verifies the signature. We add:
- Verification of `TSTInfo.messageImprint.hashedMessage == sha256(expected)`.
- Verification of `TSTInfo.hashAlgorithm` is SHA-256 (reject MD5, SHA-1).
- Chain validation against an embedded trust root set (FreeTSA + DigiCert + Sectigo, the TSAs we use). Roots ship inside the verifier binary at `apps/verify/timestamp/roots.go` as `//go:embed`-ed PEM bundle.
- Anti-backdating check remains; tolerance reduced from `1 second` to `0` (we control producer time precision via the producer's hashing, not via wall clock).

**Verify.** Test vectors in `apps/verify/timestamp/testdata/`: a real FreeTSA token, a real DigiCert token, a tampered token (one byte flipped in signature), a forged token (substring-scan attack — must FAIL where today it PASSES). Test both pass and fail paths.

**Touches.** `apps/verify/timestamp/rfc3161.go` (rewrite), `apps/verify/go.mod`, new `apps/verify/timestamp/roots.go`, new test data.

### B2. Ed25519 signs canonical JSON bytes directly, not hex-encoded hashes [DONE]

**Root cause.** `packages/chain/src/sign-ed25519.ts:181` signs `sha256String(manifest)` — a 64-char ASCII hex string. The Go verifier mirrors this oddity at `apps/verify/manifest/manifest.go:148-150` with a comment flagging it as a sharp edge. Ed25519 already handles arbitrary-length messages via internal SHA-512; the pre-hash + hex serves no purpose and introduces a cross-language convention to maintain.

**Fix.** Sign the canonical JSON bytes of the unsigned manifest directly (`crypto.sign(null, canonicalJsonBytes, key)`). Same change on verify side. This eliminates a cross-language seam and a class of bugs. Since we are pre-v1-production, no compatibility shim is needed.

**Verify.** Cross-language fixture: TS signs a fixture canonical JSON; Go verifies. Reverse direction not needed (signing is TS-only). Add to conformance suite from A4.

**Touches.** `packages/chain/src/sign-ed25519.ts`, `apps/verify/manifest/manifest.go`, signing/verification tests.

### B3. CSPRNG everywhere randomness touches evidence [DONE]

**Root cause.** Two `Math.random()` uses leak into the integrity path:
- `packages/chain/src/timestamp-rfc3161.ts:95-100` for the RFC 3161 nonce.
- `packages/core/src/events/ids.ts:86` as a fallback for ULID randomness when `globalThis.crypto` is unavailable.

**Fix.** 
- Nonce: `crypto.randomBytes(8)`.
- ULID fallback: remove it. If `crypto.getRandomValues` is missing, throw — no silent weakening of evidence IDs. (Node ≥20 always has it.)
- Add an ESLint custom rule or a CI grep step: `Math.random` is forbidden under `packages/chain/`, `packages/bundle/`, `packages/core/src/events/`. Tests may use it; production code in those paths may not.

**Verify.** CI grep step. Unit tests for `generateUlid` when crypto is absent (throws). Unit test for nonce uniqueness across 10k calls.

**Touches.** `packages/chain/src/timestamp-rfc3161.ts`, `packages/core/src/events/ids.ts`, new CI step in `ci.yml`.

### B4. Custom PEM and hex code is deleted in favor of stdlib [DONE]

**Root cause.** `apps/verify/manifest/manifest.go:172-206` reimplements PEM decoding by hand and `apps/verify/timestamp/rfc3161.go:155-183` reimplements hex decoding. Both are stdlib (`encoding/pem`, `encoding/hex`). The custom PEM decoder has CRLF-handling and whitespace gaps that are silent correctness traps.

**Fix.** Use `encoding/pem` and `encoding/hex`. Delete the custom helpers and `indexOf`.

**Verify.** Existing signature tests must still pass; add a test with CRLF-style PEM input to confirm the stdlib decoder handles it (the custom one does not).

**Touches.** `apps/verify/manifest/manifest.go`, `apps/verify/timestamp/rfc3161.go`.

---

## Workstream C — distribution and trust

The verifier is the artifact non-producers trust. Today that trust path has no foundation: there are no releases, the verify.txt URL is wrong, and the license forbids use.

### C1. LICENSE file with explicit terms [DONE]

**Root cause.** README says "Proprietary — all rights reserved" but no LICENSE file exists. A public repo with no license grants no rights — even reading the code for evaluation is technically unlicensed.

**Fix.** Decide license and commit `LICENSE`. Two viable paths:
- **AGPL-3.0** — keeps it open, requires source for hosted use. Conventional for trust-critical infra.
- **Business Source License 1.1** with a 2-year conversion to Apache 2.0 — protects commercial moat near-term.

Whichever is chosen, `package.json:license` and `README.md` license badge get updated to match. This is a *decision* — name it, commit it, link the SPDX identifier from `package.json`.

**Touches.** Repo root `LICENSE`, `package.json`, `README.md`.

### C2. Single source of truth for the verifier download URL [DONE]

**Root cause.** `github.com/depose/depose` is hardcoded in three places (`cli/main.ts:120`, `bundle/writer.ts:327`, `verify/go.mod:1`). README badges point to `Aftermath-Technologies-Ltd/depose`. The wrong URL is baked into every `verify.txt`, telling evidence recipients to fetch the verifier from a non-existent location.

**Fix.** Export a single constant `VERIFIER_DOWNLOAD_URL` from `packages/bundle/src/constants.ts`. `writer.ts` references it. `cli/main.ts` references it. Go module path corrected (this is a breaking change to the import path — find/replace in all `.go` files under `apps/verify/`). Add a CI test that greps for stale references.

**Verify.** CI test `scripts/check-urls.sh` fails the build if any hardcoded GitHub URL appears outside the single constant.

**Touches.** New `packages/bundle/src/constants.ts`, `packages/bundle/src/writer.ts`, `packages/cli/src/commands/main.ts`, all `apps/verify/**/*.go` import paths, new CI step.

### C3. Tagged releases with signed verifier binaries [DONE]

**Root cause.** Users must clone and `make build-local` to get the verifier. A self-signed evidence bundle whose verifier the recipient must compile themselves has no chain of trust. A 5-day GH Actions artifact retention is not a distribution channel.

**Fix.** New `.github/workflows/release.yml` triggered on `v*` tags:
1. Cross-compile `depose-verify` for darwin/linux × arm64/amd64.
2. Generate `SHA256SUMS`.
3. Sign with `cosign` keyless (GitHub OIDC → Fulcio short-lived cert → Rekor entry). No long-lived signing keys, no key custody problem.
4. Upload binaries, `SHA256SUMS`, `SHA256SUMS.sig`, and `SHA256SUMS.pem` to GH Releases.
5. SLSA Level 3 provenance attestation via the `slsa-github-generator` action.

`verify.txt` instructions reference the release URL and the cosign verification command.

**Verify.** A dry-run tag (`v0.1.0-rc1`) produces a complete release. `cosign verify-blob` against the published artifacts succeeds.

**Touches.** New `.github/workflows/release.yml`, `apps/verify/Makefile`, `packages/bundle/src/writer.ts` (verify.txt template).

### C4. Key management: Sigstore keyless by default, fingerprint discipline for air-gapped [PARTIAL — air-gapped done; Sigstore producer-side scaffolded]

**Root cause.** `loadOrGenerateKeyPair` auto-generates a key in `~/.depose/keys/`. The recipient has no way to know if the embedded public key is "the right" producer key. There is no fingerprint, no revocation, no rotation, no published key catalog. The `sign-sigstore.ts` skeleton was started and abandoned.

**Fix (default).** Finish `packages/chain/src/sign-sigstore.ts` for Sigstore keyless signing. In CI or any environment with OIDC, the producer signs with an ephemeral key, the cert binds to the OIDC identity (GitHub Actions principal, Google Workspace identity, etc.), and the signature + cert go into the manifest. The verifier validates the cert chain against Fulcio's root and the identity binding against an allowlist the recipient configures (`--signer-identity <regex>`). No long-lived keys, no key custody.

**Fix (air-gapped fallback).** For sealed-environment use where OIDC isn't available, keep the local key flow but add:
- `depose key fingerprint` command — prints SHA-256 of the public key in `ssh-style` format.
- Manifest carries the fingerprint in `producer.keyFingerprint`.
- Producer is expected to publish their fingerprint out-of-band (their .well-known/, a published key catalog).
- Verifier accepts `--expected-key-fingerprint <hex>` flag; fails if the bundle's key doesn't match.

**Verify.** Sigstore path: test against staging Fulcio. Air-gapped path: integration test producing a bundle and verifying with the correct + incorrect fingerprint.

**Touches.** `packages/chain/src/sign-sigstore.ts` (finish), new `packages/cli/src/commands/key.ts`, `apps/verify/cmd/verify.go`, `docs/key-management.md`.

---

## Workstream D — engineering hygiene

These are debt items. None of them adds features. All of them make the codebase honest.

### D1. Delete dev artifacts [DONE]

`git rm` and don't replace:
- `_fix_phase1.py` (359 lines)
- `_fix_remaining.py` (556 lines)
- `debug-yaml.ts`
- `packages/core/src/events/ids.ts.bak`

`.gitignore` additions: `*.bak`, `_fix_*.py`, `debug-*.ts`.

`BUILD_PLAN.md` decision: it's currently in `.gitignore` but on disk. Move design content that's still relevant into `docs/architecture.md` and `docs/bundle-format.md` (which already exist), then delete `BUILD_PLAN.md`. Project plans don't live in repos; design specs do.

### D2. Custom YAML parser → `yaml` package [DONE]

**Root cause.** `packages/core/src/reconstruct/yaml-parser.ts` is 408 lines reinventing a YAML subset. The avoid-a-dep tradeoff was wrong: the hand-rolled parser has dead parameters (lint warnings at lines 59, 307), partial implementation, and no fuzz coverage. The `yaml` npm package is ~250kb gzipped, zero transitive deps, used by millions of projects.

**Fix.** Replace with `yaml`. Delete the custom parser and its tests. The destructive ruleset format is unchanged.

**Verify.** Existing `loadDestructiveRules` tests pass. Add one fuzz test that feeds garbage YAML and asserts a clean error rather than a crash.

### D3. Custom CLI arg parser → `commander` [DONE]

**Root cause.** `main.ts:56-95` doesn't support `--key=value`, declares `string[]` but parser overwrites repeats, and the flag-vs-value heuristic breaks on values starting with `-`. For a CLI that ships to forensics use cases, "trust me, I parsed your flag right" is the wrong posture.

**Fix.** `commander` (zero deps, ~30kb, widely used). Define each command (`reconstruct`, `package`, `install`, `uninstall`, `explain`) with its options. `help` becomes free. Subcommand-specific help becomes free.

**Verify.** All existing CLI tests pass. New tests for `--key=value`, repeated flags, and values starting with `-`.

### D4. Extract shared event-pipeline module [DONE]

**Root cause.** `handleReconstruct` (main.ts) and `handlePackage` (package.ts) share ~150 lines verbatim — JSONL load, shell history, reflog, capture, merge, timeline. `createShellCommandEvent` is byte-for-byte duplicated. Two copies will drift; only one will be tested under stress.

**Fix.** New `packages/cli/src/pipeline.ts` exports `loadAndMergeEvents(opts) → { events, warnings, sessionInfo }`. Both commands call it. `createShellCommandEvent` moves there too.

**Verify.** Existing tests for both commands pass without modification (they exercise the same pipeline).

### D5. Consolidate ESLint config; fail on warnings [DONE]

**Root cause.** `.eslintrc.cjs` and `eslint.config.mjs` coexist; v9 uses the flat config and silently drops the legacy. The flat config is weaker (no `eslint:recommended`, severity warn). Result: 55 warnings, 0 errors, including stale imports everywhere.

**Fix.** Delete `.eslintrc.cjs`. Flat config extends `@eslint/js` recommended + `@typescript-eslint` recommended. Severity for unused imports/vars/types: `error`. Severity for `no-explicit-any`: `error`. CI runs `pnpm lint --max-warnings 0`.

**Verify.** `pnpm lint` exits 0 with zero warnings on a clean checkout.

### D6. CI Node version pin [DONE]

**Root cause.** `ci.yml` uses Node 20, `verify-examples.yml` uses Node 22. Production support unclear.

**Fix.** `package.json:engines.node: ">=20"` is the contract. CI runs a matrix of Node 20 and Node 22 in *both* workflows. README and `engines` updated to reflect actual support.

### D7. Tautology in capture hook [DONE]

`packages/capture-claude/src/hook-entry.ts:72-73` — the conditional `Bash ? 'claude-pretooluse' : 'claude-pretooluse'` is dead. Decide intent: same source for all tools (delete the conditional) or distinct sources per tool (fix the values). Looking at the rest of the file, same-source-for-all is correct. Delete the conditional.

---

## Workstream E — CI is honest

CI must prove every claim the README makes. Today, the verify-examples job claims end-to-end validation but skips the actual verification.

### E1. Wire `depose-verify` into example verification [DONE]

**Root cause.** `.github/workflows/verify-examples.yml` checks files exist with `jq`. It never runs the verifier. The README claims "CI rebuilds both bundles on every push and validates them end-to-end" — this is false today.

**Fix.** `verify-examples.yml` builds the Go verifier, produces each example bundle in `signed` mode (using real FreeTSA — network is available in GH Actions), then runs `./depose-verify verify <bundle>` and asserts exit 0. If FreeTSA is rate-limiting, the workflow uses a local TSA fixture (a deterministic test TSA we control, with its root in the verifier's roots set under a `--allow-test-roots` flag — *only* set in CI). Production verifier binaries do NOT include the test root.

**Verify.** Green CI on a fresh branch. Red CI on a deliberately-tampered bundle (mutate one byte in `events.jsonl`).

**Touches.** `.github/workflows/verify-examples.yml`, `examples/*/produce.sh`, possibly `apps/verify/timestamp/test_roots.go`.

### E2. Cross-language conformance suite in CI

(See A4.) Separate job runs `tests/conformance/` vectors against both the TS canonical-JSON impl and the Go re-marshal. Blocks merges on divergence.

### E3. Crypto invariant grep in CI [DONE]

(See B3.) One-line CI step:

```
! grep -rn "Math.random" packages/chain packages/bundle packages/core/src/events
```

Fails the build if any of those paths import non-CSPRNG randomness.

### E4. Verifier-on-bundle test in the producer's test suite

Already exists at `packages/bundle/test/e2e.acceptance.test.ts`. Extend to cover both `signed` and `dev-unsigned` modes after A3.

---

## Workstream F — threat model alignment

### F1. Re-audit `docs/threat-model.md` against the implementation [DONE]

**Root cause.** With the bugs found in A1–A3 and B1 fixed, the threat model needs a fresh pass. Today, the threat model likely overclaims: it asserts anti-backdating, ruleset integrity, and tamper-evidence — none of which are fully enforced by the current verifier.

**Fix.** After Workstreams A and B land, read `threat-model.md` line by line. Each defensive claim either has a corresponding verifier check + test, or it gets removed. Add explicit non-goals: Windows is not supported (or supported with caveats). Replay attacks on TSA tokens out of scope (single TSA cert is assumed trusted for its validity window). Producer-host compromise: out of scope; DEPOSE captures what the host shows, not ground truth.

### F2. `docs/legal-considerations.md` reviewed against the production format [DONE]

Same exercise. FRE 902(13) self-authentication and Daubert reliability claims need to map to specific verifier checks. If a claim has no test, it doesn't go in the doc.

### F3. Drop launch post until A–E land

`docs/launch/launch-post.md` exists. Don't launch until the demo passes its own verifier (i.e., until A–E are green on `main`).

---

## Execution order

Roughly two weeks of focused work, sequenced to land changes safely. Each step lands as its own PR with green CI.

**Week 1 — correctness foundation**
1. D1 (delete dev artifacts) — clean slate, no behavior change.
2. A1 (default rules path) + A2 (bundle ruleset content) — fixes the silently-broken headline feature. New verifier check.
3. A3 (mode field) — distinguishes dev bundles from evidence bundles. Examples switch to `signed` mode.
4. A4 (canonical-JSON conformance) + A5 (schemaVersion) — eliminates the cross-language fragility *before* it ships.

**Week 2 — crypto and distribution**
5. B1 (RFC 3161 real verification) — closes the most embarrassing security gap.
6. B2 (sign canonical JSON, not hex) + B3 (CSPRNG) + B4 (stdlib PEM/hex) — eliminates the bespoke crypto seams.
7. E1 (verifier wired to CI) + E3 (Math.random grep) — proves the demo works end-to-end.
8. C2 (URL constant) + D5 (ESLint) + D6 (Node) + D7 (tautology) — small, fast cleanups.

**Week 3 — distribution and trust**
9. C1 (LICENSE) — decision + commit.
10. C3 (release pipeline) — signed verifier binaries.
11. D2 (yaml) + D3 (commander) + D4 (shared pipeline) — debt retirement.
12. C4 (Sigstore keyless + fingerprint) — production key management.
13. F1 + F2 (threat model + legal doc audit) — claims now match implementation.

**After all green:** F3 — ship the launch post.

---

## Definition of done

DEPOSE is production-grade when:

1. `bash examples/<name>/produce.sh && ./apps/verify/build/depose-verify verify examples/<name>/depose-output/incident-*` exits 0 for both examples, with the `signed` mode and real RFC 3161 timestamps.
2. The verifier rejects a one-byte mutation in any tracked artifact (`events.jsonl`, `manifest.json`, `rules/destructive.yaml`).
3. The verifier rejects a forged RFC 3161 token that contains the expected hash bytes but no valid TSA cert chain.
4. The bundle's `rules/destructive.yaml` is the actual ruleset and re-hashing it matches `manifest.rulesetHash`.
5. The verifier rejects a bundle whose `producer.keyFingerprint` doesn't match `--expected-key-fingerprint`.
6. `pnpm lint --max-warnings 0` exits 0.
7. A signed `depose-verify` release binary can be downloaded from GH Releases and `cosign verify-blob` against it succeeds.
8. Every claim in `README.md`, `docs/threat-model.md`, and the bundle's `verify.txt` has a corresponding test in CI.

When all eight hold on `main`, the project is ready to be the tool it claims to be: the record you wish you had the moment *after* something went wrong — verifiable off-host, by anyone, with a single signed binary, against claims that survive adversarial review.
