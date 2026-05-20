# Development

This document covers everything beyond the basics in the top-level
[Development](../README.md#development) section: build internals, test
strategy, the CI matrix, and release artifacts.

---

## Build

```bash
pnpm install        # workspace deps
pnpm build          # tsc --build (project references)
                    #   + apps/capture-shim Go binary
                    #   + packages/cli esbuild self-contained bundle
pnpm typecheck      # tsc --build --noEmit
pnpm lint           # eslint, --max-warnings 0
```

`pnpm build` produces three things:

1. TypeScript transpile output under each `packages/*/dist/`.
2. `apps/capture-shim/depose-shim`: the PATH-intercepting Go shim
   used by `depose install --shell`.
3. `packages/cli/dist-bundle/{depose.mjs,depose-hook.mjs}`: the
   single-file esbuild output that the published npm tarball ships.
   Inlines `@depose/*` workspace deps and `commander` so consumers
   need no runtime dependencies after `npm install -g <tarball>`.

The Go verifier is built separately:

```bash
cd apps/verify && make build-local      # local dev binary
cd apps/verify && make all              # cross-compile darwin/linux × arm64/amd64
```

## Test

```bash
pnpm test           # vitest (TypeScript unit + integration)
pnpm test:go        # apps/verify Go suites (+ apps/capture-shim if present)
pnpm test:all       # both
```

The TypeScript unit tests exercise synthetic fixtures that match the
normalizer's internal expectations. A contract test against real
Claude Code JSONL format also runs against `session-real-format.jsonl`.
The Go verifier has its own canonical-JSON and replay test suites in
`apps/verify/canonical/` and `apps/verify/chain/`.

Cross-language canonical-JSON conformance vectors live in
[`tests/conformance/canonical-json-vectors.json`](../tests/conformance/canonical-json-vectors.json)
and run against both implementations on every PR.

## Determinism

Round-trip determinism is asserted in CI by `scripts/determinism-test.sh`,
which produces a bundle twice with a fixed ULID seed and pinned
timestamps then diffs the outputs. Any nondeterminism (clock leaks,
map iteration order, default `~/.depose/captures` bleed-through, etc.)
fails the build.

## Install-from-pack E2E

`scripts/install-from-pack-test.sh` packs the CLI, installs it into an
isolated prefix, runs `depose package` against a synthetic JSONL,
verifies the bundle with `depose-verify`, and smoke-tests `depose-hook`
for module-resolution regressions. CI runs it on every push to catch
workspace-only failures (missing files in `package.json#files`, bin
entries pointing at unbuilt artifacts, hook unable to load
`@depose/capture-claude` after install).

## CI surface

The `CI` workflow (`.github/workflows/ci.yml`):

- `lint-typecheck-test`: runs on `ubuntu-latest` and `macos-latest`,
  Node 20 and 22; lint, typecheck, TS tests, Go verifier tests,
  install-from-pack E2E. Also enforces two source-tree invariants:
  the verifier download URL has a single source of truth, and
  `Math.random` is forbidden under `packages/chain/src`,
  `packages/bundle/src`, and `packages/core/src/events`.
- `sbom`: emits a CycloneDX SBOM for the TS dep graph (via cdxgen,
  pnpm-aware) and a CycloneDX SBOM for the Go verifier (via
  cyclonedx-gomod). Both upload as build artifacts.
- `verify-binary`: cross-compiles `depose-verify` and uploads the
  binaries as artifacts.
- `determinism`: runs the determinism test.

The `Verify Example Bundles` workflow re-produces both example
bundles end-to-end and runs three semantic tamper tests (payload
string rewrite, `payloadHash` hex flip, `chainHash` hex flip),
asserting the verifier rejects each.

## Release artifacts

Tagged release (`v*`) via `.github/workflows/release.yml`:

- Cross-compiles `depose-verify` for darwin/linux × arm64/amd64.
- Generates `SHA256SUMS` and signs it with cosign keyless
  (OIDC → Fulcio → Rekor).
- Generates SLSA L3 provenance binding the SHA256SUMS contents to the
  workflow run.
- Publishes a GitHub Release with the binaries, `SHA256SUMS`,
  `SHA256SUMS.sig`, `SHA256SUMS.pem`, and the provenance attestation.

Bundles produced from a tagged release pin
`manifest.verifier.downloadUrl` to that release tag, not to the moving
`latest`, so a recipient downloads the verifier that matched the
producer's build.

## Source-tree invariants enforced by CI

- The verifier download URL is defined in
  `packages/bundle/src/constants.ts` and nowhere else. CI greps the
  tree for the obsolete non-canonical URL form and fails the build if
  it reappears outside `constants.ts`. The grep pattern lives in
  `.github/workflows/ci.yml`; do not duplicate it elsewhere.
- `Math.random` is forbidden in evidence paths
  (`packages/chain/src`, `packages/bundle/src`,
  `packages/core/src/events`). All randomness in the signed path must
  come from a CSPRNG.
