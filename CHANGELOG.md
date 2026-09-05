# Changelog

All notable changes to DEPOSE are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Sealed pending anchor, and `depose anchor <bundle>`.** A bundle whose
  timestamp authorities all fail is now signed and written with
  `anchorStatus: "pending"` instead of not produced at all;
  `--require-anchor` restores fail-closed. `depose anchor` obtains the
  RFC 3161 token later over exactly the bytes the signature covered, and
  leaves manifest.json byte-identical: the anchor goes in
  `attestations/anchor.json` with an Ed25519 countersignature by the
  sealing key, because a timestamp over a public manifest is something
  anyone can obtain. The verifier's new `anchor-status` check reports
  seal time and anchor time separately, WARNs on an unanchored bundle
  rather than failing it, and FAILs when an anchor belongs to a different
  seal, was edited after countersigning, or was countersigned by another
  key. TSA order is now shuffled per run and each endpoint is retried
  with an exponential backoff, and the ruleset's new `tsa` key names the
  authorities (URL plus an expected signer fingerprint) so the choice of
  witness travels with the rules. See
  `docs/bundle-format.md#anchoring`.

- **`depose export --format aat|asqav-receipt|scitt-statement`.** Three
  IETF interchange views of a sealed bundle:
  draft-sharif-agent-audit-trail-00 as JSON Lines with its own recomputed
  hash chain, draft-marques-asqav-compliance-receipts-08 as one signed
  receipt per action with JCS canonicalization and a
  `previousReceiptHash` chain, and a COSE_Sign1 SCITT Signed Statement
  carrying a draft-mih-scitt-agent-action-capsule-04 capsule, ready to
  register with a transparency service. Each exporter is a pure function
  from the bundle (and key) to bytes, with byte-for-byte golden outputs
  for both example incidents and conformance tests written against the
  drafts rather than against the exporter. Deterministic CBOR (RFC 8949
  §4.2.1), COSE_Sign1, and did:key are implemented in `@depose/chain`
  with RFC 8949 Appendix A vectors, so the CLI gains no dependency.
  Every mapping choice, and every DEPOSE field the target format has no
  home for, is in `docs/export-mapping.md`.

- **Intent and effect are a signed pair.** `depose install --claude` now
  registers a PostToolUse hook alongside PreToolUse. The pre half records
  what the agent was about to run and the SHA-256 of every file the call
  names; the post half records the exit status, the duration, and those
  same hashes afterwards, carrying the intent's event id inside its own
  payload so the binding is signed. The verifier gains `intent-effect`
  (every effect names a real intent, no intent closed twice, the unsigned
  correlation agrees with the signed payload, every unclosed intent has a
  gap) and `file-continuity` (a path's recorded outcome matches the next
  recorded pre-state, or a gap discloses the difference). New gap reasons
  `intent_without_effect`, `effect_without_intent`, and
  `unwitnessed_file_change` are required rather than advisory: removing
  one from `events.jsonl` fails a named check. The narrative gives lost
  outcomes their own section ahead of the timeline. See
  `docs/bundle-format.md#intent-and-effect`.
- **Kernel-witnessed execve (Linux, optional).**
  `depose-collect-execve` attaches an eBPF program to the
  `sched:sched_process_exec` tracepoint and records every exec inside the
  agent's process tree, tagged `source: kernel`. The merge attributes
  each to a hook intent by process ancestry and time window; one with no
  matching hook record becomes its own `process_spawn` event plus a
  `kernel_execve_without_hook` gap, which makes the shim gaps in
  threat-model §6.1, §6.3, and §6.4 visible instead of silent. Requires
  `CAP_BPF`; without it the collector writes a `capture_failed` record
  and exits 0. macOS is documented as not supported, hook only. Measured
  userspace cost is 8.0 µs per out-of-tree exec and 31.9 µs per recorded
  one; see `docs/capture-coverage.md`.
- **Signed files map.** `manifest.files` pins every file in the bundle
  tree (raw JSONL, narrative, verify.txt, artifacts) by SHA-256 and
  length. The verifier's new `files-map` check fails on any added,
  deleted, or modified file and on any symlink; `attestation-files`
  binds `signatures.json` and every `.tsr` to the manifest. Schema
  version is now 3; v2 bundles verify with a WARN naming what the map
  did not cover. See `docs/bundle-format.md#files-map`.
- **Hook failures leave evidence.** The Claude PreToolUse hook writes a
  `capture_failed` record (phase, error class, sanitized message,
  monotonic time) before exiting 0, falling back to
  `capture-failed.log` when the record file cannot be written. The
  merger turns each into a `gap` event with reason `capture_failed`,
  counted in the signed manifest and named in the narrative.
- **Verifier check statuses.** Every check reports `PASS`, `FAIL`,
  `SKIPPED`, or `WARN`. A skipped check is never printed as a pass.
- **docs/decisions.md** records design forks and the option taken.
- **Verifier decomposition and tests.** `apps/verify/cmd` is one function
  per check with a driver that stops only after a failure that makes the
  rest meaningless. Table tests run every check against a golden signed
  bundle and thirteen mutations of it (signature flip, manifest field
  tamper, mode-contract violation, key-fingerprint mismatch, ruleset
  tamper, missing file, extra file, files-map mismatch, raw JSONL swap,
  deleted .tsr, chain break, payload rewrite, bad schema).
- **Fuzzing on the trust boundary.** `FuzzParseTSR` (Go) seeded with real
  FreeTSA and DigiCert tokens, plus a seeded mutation loop over the
  TypeScript DER reader. The Go run found a panic in digitorus/pkcs7 on a
  two-byte input; tokens are now strictly DER-validated before the
  library sees them, and the library runs under a recover guard.
- **RFC 6962 Merkle tree.** `manifest.merkleRoot` is the tree head over
  the chain hashes (leaf = SHA-256(0x00 || chainHash), node = SHA-256(0x01
  || l || r)), signed and timestamped alongside `rootHash`. The verifier's
  `merkle-root` check recomputes it; a bundle without one gets WARN.
  Vectors match the certificate-transparency test tree heads.
- **Salted field commitments.** Disclosable payload fields (tool inputs,
  outputs, file contents, environment values by default; the ruleset's
  `disclosable` list overrides) are sealed as
  `{ "$commitment": sha256(jcs([salt, path, value])) }` with the openings in
  `commitments.json`. The verifier's `commitments` check opens every one.
- **`depose disclose` and verifier disclosure mode.** A disclosure
  bundle carries the original manifest, signature, and timestamp, the
  chosen events byte for byte, an RFC 6962 audit path for every sealed
  position, and commitment openings for the chosen fields only.
  `depose-verify verify` detects it and proves membership, byte
  fidelity, and openings with no access to the original;
  `depose-verify consistency` checks that a later disclosure extends an
  earlier one. Negative tests: modified disclosed event, forged audit
  path, wrong salt, root the signature does not cover, dropped
  position, unpinned carried file.
- **Conformance vectors** for the hash chain and the files map / manifest
  signing form (`tests/conformance/`), consumed by both the TypeScript and
  Go suites.

- **CLI bundling.** `pnpm build` now emits a single self-contained
  `depose.mjs` and `depose-hook.mjs` under `packages/cli/dist-bundle/`
  via esbuild. The published tarball no longer depends on private
  `@depose/*` workspace packages and `npm install -g <tarball>` works
  without registry lookups.
- **Key management commands.** `depose key rotate`, `depose key revoke`,
  and `depose key catalog` provide a minimal-viable key lifecycle:
  archive an old key, mark a fingerprint as revoked with reason/date,
  and emit a signed fingerprint catalog.
- **Verifier revocation check.** `depose-verify verify --revocation-list
  <path>` fails closed if the producer key fingerprint appears in the
  catalog. Without the flag, behavior is unchanged.
- **macOS CI.** The `lint-typecheck-test` job now runs on both
  `ubuntu-latest` and `macos-latest` so POSIX mode-bit and
  shim-resolution paths are exercised on both supported OSes.
- **SECURITY.md** with the vulnerability-disclosure address.
- **SBOM emission in CI.** `cyclonedx-npm` (TS) and `cyclonedx-gomod`
  (Go) generate SBOMs uploaded as build artifacts on every push and
  attached to tagged releases.
- **Install-from-pack E2E test in CI.** `scripts/install-from-pack-test.sh`
  packs the CLI, installs it into an isolated prefix, runs
  `depose package` against a synthetic JSONL, verifies the bundle with
  `depose-verify`, and smoke-tests `depose-hook` for module-resolution
  regressions.

### Changed

- **`monoNs` is a decimal string on the wire** (a bigint in TypeScript,
  an int64 in Go). JSON numbers diverge past 2^53. Schema 3 bundles must
  use the string form; schema 2 bundles keep the numeric form.
- **events.jsonl order is enforced, not repaired.** The producer refuses
  to seal an unsorted event list and the verifier rejects an unsorted
  file instead of silently re-sorting it.
- **BUILD_PLAN.md citations removed.** The file never existed in git; the
  normative content the code relied on now lives in
  `docs/bundle-format.md` under stable anchors, and every citation points
  there.
- **Verifier checks now carry a status** (`PASS`, `FAIL`, `SKIPPED`,
  `WARN`) in both the report and `--json` output.

- **`VERIFIER_DOWNLOAD_URL`** is now pinned at build time via the
  `DEPOSE_RELEASE_TAG` environment variable. The release workflow sets
  it to `${GITHUB_REF_NAME}`; dev builds fall back to `releases/latest`.
  Bundles produced from a tagged release now point recipients at the
  verifier release that matched their production, not at the moving
  `latest`.

### Fixed

- **Destructive rules never fired on hook-captured commands.** The hook
  records a Bash tool call as `['bash', '-c', <command>]` and `argvHead`
  rules matched a strict argv prefix, so on active capture no rule could
  fire. Rules now match every simple command inside the shell string,
  after splitting on `&&`, `||`, `;`, `|`, and newlines, recursing into
  subshells and `$(...)`, and stripping `sudo`, `env`, `nice`, `time`,
  `nohup`, `command`, `exec`, `timeout`, `xargs`, `doas`, and
  `VAR=value` prefixes. Each match records which simple command fired
  and its index. Regression fixtures cover both example incidents
  through the hook path plus `sudo rm -rf`, `env X=1 terraform destroy`,
  `cd /prod && rm -rf .`, and subshell/substitution shapes.
- **Shim install would create dangling `rm` symlink.** If
  `apps/capture-shim/depose-shim` was not built, `depose install --shell`
  silently created symlinks (including `rm`) pointing to a non-existent
  binary. Once the user added the bin dir to `PATH`, their shell's `rm`
  was broken. Now fails closed with a clear error pointing at the
  Makefile.
- **`depose install --claude` wrote a non-functional command.**
  `resolveHookBinary()` returned the calling `depose` binary instead of
  the separate `depose-hook` binary; settings.json registered
  `"…/bin/depose" pretooluse` (a subcommand that doesn't exist on
  `depose`). The hook would silently fail every Claude tool call. Hook
  lookup is now anchored on `import.meta.url`.
- **`depose-hook` couldn't load `@depose/capture-claude` after install.**
  The CLI package didn't declare the dep, so workspace hoisting was
  masking a real bug. Either bundled (default) or declared (fallback).
- **Determinism test was non-hermetic.** `scripts/determinism-test.sh`
  used the default `~/.depose/captures` directory; any developer who'd
  ever used the hook would see a false determinism failure. Now uses an
  ephemeral `--capture-dir`.

## [0.1.0] - prior to first tagged release

Initial public surface. See `docs/architecture.md` for the design.
