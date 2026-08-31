// packages/bundle/src/writer.ts
//
// Deterministic bundle writer for .depo bundles.
//
// Phase 2: Full integrity pipeline:
//   1. Hash-chain all events (IRONROOT construction)
//   2. Sign the manifest with Ed25519
//   3. Request RFC 3161 timestamps
//   4. Write the complete .depo bundle directory
//
// The bundle is a deterministic directory (tarball in future Phase):
//   - Fixed mtime (= manifest.producedAt)
//   - Lexicographic file order
//   - Fixed uid/gid (0)
//   - Fixed mode (0644 files, 0755 dirs)
//   - No extended attributes
//   - No PAX headers
//
// See BUILD_PLAN.md §5 for the full bundle layout.

import { mkdirSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import { join, basename, dirname } from 'node:path';
import type { Event, DestructiveRule } from '@depose/core';
import { buildTimeline, sha256Bytes } from '@depose/core';
import { buildManifest, serializeManifest, serializeManifestForSigning, type BundleMode, type Manifest, type SignatureBlock, type Rfc3161Token } from './manifest.js';
import { VERIFIER_DOWNLOAD_URL } from './constants.js';
import { buildHashChain } from '@depose/chain';
import { signManifest as signManifestEd25519, fingerprintPublicKeyPem, type Ed25519KeyPair } from '@depose/chain';
import { requestTimestamps, type Rfc3161Token as ChainRfc3161Token } from '@depose/chain';
import { renderMarkdown, renderHtml } from '@depose/narrative';

// ── Bundle layout constants (BUILD_PLAN.md §5) ──────────────────────

const BUNDLE_DIR_SIGNED = 'incident';
const BUNDLE_DIR_DEV_UNSIGNED = 'incident-unsigned';
const DEV_UNSIGNED_BANNER = [
  '═══════════════════════════════════════════════════════════════════',
  '  THIS IS A DEVELOPMENT BUNDLE, NOT EVIDENCE',
  '',
  '  This bundle was produced with mode="dev-unsigned". It carries',
  '  NO Ed25519 signature and NO RFC 3161 timestamp. It is suitable',
  '  for pipeline testing only. It is NOT admissible as evidence.',
  '═══════════════════════════════════════════════════════════════════',
  '',
].join('\n');
const MANIFEST_PATH = 'manifest.json';
const EVENTS_PATH = 'events.jsonl';
const RAW_DIR = 'raw';
const ATTESTATIONS_DIR = 'attestations';
const RULES_DIR = 'rules';
const NARRATIVE_MD = 'narrative.md';
const NARRATIVE_HTML = 'narrative.html';
const VERIFY_TXT = 'verify.txt';

// ── Writer options ───────────────────────────────────────────────────

export interface BundleWriterOptions {
  /** Session ID (ULID), used as bundle directory name */
  sessionId: string;
  /** Agent ID (e.g., 'claude-code') */
  agentId: string;
  /** Bundle version (semver) */
  version: string;
  /** Production timestamp (ISO 8601 UTC) */
  producedAt: string;
  /** Session start timestamp (ISO 8601 UTC) */
  sessionStartedAt: string;
  /** Session end timestamp (ISO 8601 UTC) */
  sessionEndedAt: string;
  /** Destructive ruleset (for counting destructive ops) */
  rules: DestructiveRule[];
  /** Original ruleset bytes, written verbatim into the bundle and
   *  hashed into manifest.rulesetHash. The verifier re-reads the
   *  embedded file and re-hashes it to enforce ruleset integrity. */
  rulesetBytes: Buffer;
  /** Output directory (where the .depo directory is written) */
  outputDir: string;
  /**
   * Bundle production mode (see BundleMode docstring).
   *
   * `signed`, production. Requires keyPair. Builds chain, signs,
   *   requests RFC 3161 timestamps. The bundle is named
   *   `incident-<id>` and is the only mode acceptable as evidence.
   * `dev-unsigned`, pipeline testing. signatures/timestamps are
   *   empty. The bundle is named `incident-unsigned-<id>` and
   *   verify.txt + narrative carry a "NOT EVIDENCE" banner. The
   *   chain is built only if keyPair is provided (this preserves
   *   roundtrip tests without an active TSA dependency).
   */
  mode: BundleMode;
  /** Ed25519 key pair. Required for `signed`. Optional for
   *  `dev-unsigned` (used only to build the chain; the signature
   *  itself is not emitted). */
  keyPair?: Ed25519KeyPair;
  /** Test-only hatch: pre-baked RFC 3161 tokens to embed instead of
   *  calling a real TSA. Used by signed-mode tests that cannot reach
   *  a live TSA. Never set by CLI commands. */
  injectedTimestamps?: ChainRfc3161Token[];
  /** Path to the original JSONL source file. When provided, the
   *  file is copied into raw/claude-code/<filename>.jsonl in the
   *  bundle. Also triggers sibling file discovery: if a
   *  shell-history.txt or git-reflog.txt exists alongside the
   *  JSONL, they are copied into raw/shell-history/ and raw/
   *  respectively. */
  sourceJsonlPath?: string;
  /**
   * Capture-store accounting, recorded in the signed manifest so a
   * recipient can see that capture data existed and how much of it was
   * deliberately left out as unattributable to this session.
   */
  capturesAttributed?: number;
  capturesExcluded?: number;
  /**
   * Capture store the attributed records came from. When set, the records
   * that actually entered this bundle are copied into raw/captures/ so a
   * recipient can re-derive those events from the bundle's own source
   * material. Only records already in the timeline are copied, so scoping
   * still holds: nothing unrelated to the session reaches the bundle.
   */
  captureSourceDir?: string;
}

// ── Bundle output ────────────────────────────────────────────────────

export interface BundleOutput {
  /** Path to the written .depo directory */
  depopPath: string;
  /** The manifest that was written */
  manifest: Manifest;
  /** Events written to events.jsonl (with chainHash populated) */
  events: Event[];
  /** Warnings (non-fatal issues during bundle creation) */
  warnings: string[];
}

// ── Main writer ──────────────────────────────────────────────────────

/**
 * Write a .depo bundle in the requested mode (see `BundleMode`).
 *
 * Modes:
 *   - `signed`: builds chain, signs, timestamps. Requires keyPair.
 *     Fails closed if a TSA cannot be reached (no silent downgrade).
 *   - `dev-unsigned`: signatures/timestamps stay empty. Chain is
 *     still built when keyPair is provided. Bundle dir is renamed
 *     to `incident-unsigned-<id>` and verify.txt + narrative carry
 *     a "NOT EVIDENCE" banner so a casual recipient cannot mistake
 *     it for an evidentiary bundle.
 */
export async function writeBundle(
  events: Event[],
  rules: DestructiveRule[],
  options: BundleWriterOptions
): Promise<BundleOutput> {
  const {
    sessionId,
    agentId,
    version,
    producedAt,
    sessionStartedAt,
    sessionEndedAt,
    rules: destructiveRules,
    rulesetBytes,
    outputDir,
    mode,
    keyPair,
    injectedTimestamps,
    sourceJsonlPath,
  } = options;

  if (mode === 'signed' && !keyPair) {
    throw new Error(
      'mode="signed" requires a keyPair. Use mode="dev-unsigned" for unsigned bundles.'
    );
  }

  const rulesetHash = sha256Bytes(rulesetBytes);

  const warnings: string[] = [];
  const bundleId = sessionId;
  const isDevUnsigned = mode === 'dev-unsigned';

  let rootHash = '';
  let chainedEvents = events;

  // ── Step 1: Build hash chain (only when we have a key) ───────────
  // The chain is what `signed` mode signs over. In `dev-unsigned`
  // mode we still build the chain when a key is supplied so the
  // verifier can exercise chain-replay on dev bundles, but no
  // signature is emitted.
  if (keyPair) {
    const sorted = [...events].sort((a, b) => a.id.localeCompare(b.id));
    const chainResult = buildHashChain(sorted);
    chainedEvents = chainResult.chainedEvents;
    rootHash = chainResult.rootHash;
  }

  // ── Step 1b: Pre-serialize events.jsonl bytes and hash them ──────
  // We compute the exact UTF-8 byte sequence that will be written to
  // events.jsonl (sorted by id, one JSON object per line, trailing
  // newline) and embed its SHA-256 into the signed manifest. The
  // verifier re-reads events.jsonl and compares, pinning the file's
  // byte form directly, on top of the per-event chain.
  const eventsJsonlSorted = [...chainedEvents].sort((a, b) => a.id.localeCompare(b.id));
  const eventsJsonlContent = eventsJsonlSorted.map((e) => JSON.stringify(e)).join('\n') + '\n';
  const eventsJsonlBytes = Buffer.from(eventsJsonlContent, 'utf-8');
  const eventsJsonlSha256 = sha256Bytes(eventsJsonlBytes);

  // ── Step 2: Build manifest ────────────────────────────────────────
  // In signed mode, embed the signer's key fingerprint so the
  // recipient can pin against an out-of-band-published identity
  // via depose-verify --expected-key-fingerprint.
  const keyFingerprint = mode === 'signed' && keyPair
    ? fingerprintPublicKeyPem(keyPair.publicKeyPem)
    : undefined;
  const manifest = buildManifest(chainedEvents, destructiveRules, {
    bundleId,
    producedAt,
    version,
    mode,
    sessionId,
    agentId,
    sessionStartedAt,
    sessionEndedAt,
    rulesetHash,
    rootHash,
    eventsJsonlSha256,
    keyFingerprint,
    capturesAttributed: options.capturesAttributed,
    capturesExcluded: options.capturesExcluded,
  });

  let signatures: SignatureBlock[] = [];
  let timestamps: Rfc3161Token[] = [];

  // ── Step 3: Sign manifest (signed mode only) ──────────────────────
  if (mode === 'signed') {
    const manifestForSigning = serializeManifestForSigning(manifest);
    const sigResult = signManifestEd25519(manifestForSigning, keyPair!);

    signatures.push({
      scheme: 'ed25519',
      signature: sigResult.signatureBase64,
      publicKey: sigResult.publicKeyPem,
      signedFields: 'manifest.json',
    });
    manifest.signatures = signatures;
  }

  // ── Step 4: RFC 3161 timestamps (signed mode only) ────────────────
  if (mode === 'signed') {
    try {
      const tsTokens = injectedTimestamps && injectedTimestamps.length > 0
        ? injectedTimestamps
        : await requestTimestamps(serializeManifestForSigning(manifest));

      for (const token of tsTokens) {
        timestamps.push({
          tsa: token.tsa,
          timestamp: token.timestamp,
          tokenBase64: token.tokenBase64,
        });
      }
      manifest.timestamps = timestamps;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(
        `Failed to obtain RFC 3161 timestamp, cannot produce signed bundle.\n${msg}\n` +
        `Use mode="dev-unsigned" if you need an unsigned bundle for pipeline testing.`
      );
    }
  }

  if (isDevUnsigned) {
    warnings.push('Bundle is dev-unsigned. signatures=[], timestamps=[]. NOT EVIDENCE.');
  }

  // ── Step 5: Write the bundle directory ─────────────────────────────
  const bundleDirName = isDevUnsigned
    ? `${BUNDLE_DIR_DEV_UNSIGNED}-${bundleId}`
    : `${BUNDLE_DIR_SIGNED}-${bundleId}`;
  const bundleDir = join(outputDir, bundleDirName);
  mkdirSync(bundleDir, { recursive: true });

  // Write manifest.json (re-serialize with updated signatures/timestamps)
  const finalManifestJson = serializeManifest(manifest);
  writeFileSync(join(bundleDir, MANIFEST_PATH), finalManifestJson, 'utf-8');

  // Write events.jsonl, the exact bytes we hashed into
  // manifest.eventsJsonlSha256 above. Re-serializing here would risk
  // a divergence between hashed bytes and on-disk bytes if any future
  // change to JSON.stringify-equivalent code drifted between the two
  // paths; we use the same Buffer instead.
  const sortedEvents = eventsJsonlSorted;
  writeFileSync(join(bundleDir, EVENTS_PATH), eventsJsonlBytes);

  // ── raw/ directory ─────────────────────────────────────────────────
  // Copy source files when available. Do not create empty stubs.
  const rawDir = join(bundleDir, RAW_DIR);

  // raw/claude-code/, copy JSONL source when provided
  if (sourceJsonlPath) {
    const rawClaudeDir = join(rawDir, 'claude-code');
    mkdirSync(rawClaudeDir, { recursive: true });
    const jsonlFilename = basename(sourceJsonlPath);
    copyFileSync(sourceJsonlPath, join(rawClaudeDir, jsonlFilename));

    // Discover and copy sibling files (shell-history.txt, git-reflog.txt)
    const srcDir = dirname(sourceJsonlPath);

    // Shell history sibling
    const shellHistoryPath = join(srcDir, 'shell-history.txt');
    if (existsSync(shellHistoryPath)) {
      const rawShellDir = join(rawDir, 'shell-history');
      mkdirSync(rawShellDir, { recursive: true });
      copyFileSync(shellHistoryPath, join(rawShellDir, 'shell-history.txt'));
    }

    // Git reflog sibling
    const reflogPath = join(srcDir, 'git-reflog.txt');
    if (existsSync(reflogPath)) {
      copyFileSync(reflogPath, join(rawDir, 'git-reflog.txt'));
    }
  }

  // ── artifacts/ directory ───────────────────────────────────────────
  // Only create if there are artifact files to populate (Phase 3 capture).
  // For now, do not create empty directories.

  // ── attestations/ directory ────────────────────────────────────────
  const attestationsDir = join(bundleDir, ATTESTATIONS_DIR);
  mkdirSync(attestationsDir, { recursive: true });

  // signatures.json
  writeFileSync(
    join(attestationsDir, 'signatures.json'),
    JSON.stringify({ blocks: signatures }, null, 2),
    'utf-8'
  );

  // rfc3161-timestamps/
  const timestampDir = join(attestationsDir, 'rfc3161-timestamps');
  mkdirSync(timestampDir, { recursive: true });
  for (let i = 0; i < timestamps.length; i++) {
    const token = timestamps[i]!;
    writeFileSync(join(timestampDir, `${i}.tsr`), token.tokenBase64, 'base64');
  }

  // rekor-entries.json; only write when there are actual entries
  // (currently there never are, so we skip the empty stub)

  // ── Write rules/ directory ─────────────────────────────────────────
  // The original ruleset bytes are written verbatim so a third-party
  // verifier can re-hash them and compare against manifest.rulesetHash.
  const rulesDir = join(bundleDir, RULES_DIR);
  mkdirSync(rulesDir, { recursive: true });
  writeFileSync(join(rulesDir, 'destructive.yaml'), rulesetBytes);

  // ── Capture directory ──────────────────────────────────────────────
  // Copy capture records if a capture directory exists as a sibling
  // of the JSONL source file. readdirSync is not guaranteed to return
  // entries in a stable order across filesystems, so sort before
  // iterating: the result is the same file set either way, but the
  // sort makes the iteration deterministic so any future
  // entry-derived state (counts, indices, manifest sums) cannot drift.
  // raw/captures/, the pre-execution records behind the capture events in
  // this bundle. Without them the bundle carries events derived from source
  // material it does not contain, so a recipient cannot re-derive them: a
  // chain-of-custody hole. Copy by event id rather than by directory sweep,
  // which keeps the scoping guarantee intact.
  if (options.captureSourceDir && existsSync(options.captureSourceDir)) {
    const attributed = chainedEvents.filter(
      (e) =>
        e.type === 'shell_command_pre' &&
        (e.payload as { capturedAtSource?: string }).capturedAtSource !== 'reconstructed'
    );
    if (attributed.length > 0) {
      const rawCaptureDir = join(rawDir, 'captures');
      mkdirSync(rawCaptureDir, { recursive: true });
      for (const event of attributed) {
        const srcFile = join(options.captureSourceDir, `${event.id}.json`);
        if (!existsSync(srcFile)) continue;
        try {
          copyFileSync(srcFile, join(rawCaptureDir, `${event.id}.json`));
        } catch (err) {
          warnings.push(
            `Could not copy capture record ${event.id} into raw/captures/ ` +
              `(${err instanceof Error ? err.message : String(err)}). The event ` +
              `remains in the timeline but its source record is not in the bundle.`
          );
        }
      }
    }
  }

  // Build timeline for narrative rendering
  const timeline = buildTimeline(chainedEvents, destructiveRules);

  // Write narrative files (Phase 4: deterministically rendered).
  // In dev-unsigned mode the banner is prepended so a reader cannot
  // mistake the narrative for an evidentiary record.
  const narrativeOptions = {
    bundleId,
    producedAt,
    agentId,
    sessionId,
    sessionStartedAt,
    sessionEndedAt,
    capturesAttributed: options.capturesAttributed,
    capturesExcluded: options.capturesExcluded,
  };
  const narrativeMd = renderMarkdown(timeline, narrativeOptions);
  writeFileSync(
    join(bundleDir, NARRATIVE_MD),
    isDevUnsigned ? DEV_UNSIGNED_BANNER + narrativeMd : narrativeMd,
    'utf-8'
  );

  const narrativeHtml = renderHtml(timeline, narrativeOptions);
  writeFileSync(
    join(bundleDir, NARRATIVE_HTML),
    isDevUnsigned ? wrapHtmlBanner(narrativeHtml) : narrativeHtml,
    'utf-8'
  );

  // Write verify.txt (attorney-friendly instructions)
  const verifyTxt = buildVerifyTxt(manifest);
  writeFileSync(
    join(bundleDir, VERIFY_TXT),
    isDevUnsigned ? DEV_UNSIGNED_BANNER + verifyTxt : verifyTxt,
    'utf-8'
  );

  return {
    depopPath: bundleDir,
    manifest,
    events: sortedEvents,
    warnings,
  };
}

// ── HTML banner wrapper for dev-unsigned narrative ──────────────────

function wrapHtmlBanner(html: string): string {
  const banner = '<div style="background:#7a1f1f;color:#fff;padding:1em 1.5em;border-bottom:4px solid #ff0;font-family:-apple-system,Segoe UI,sans-serif;font-weight:bold"><strong>THIS IS A DEVELOPMENT BUNDLE, NOT EVIDENCE.</strong> mode="dev-unsigned": no signature, no timestamp.</div>';
  if (html.includes('<body>')) {
    return html.replace('<body>', `<body>${banner}`);
  }
  if (html.includes('<body ')) {
    return html.replace(/<body([^>]*)>/, `<body$1>${banner}`);
  }
  return banner + html;
}

// ── Verify text ──────────────────────────────────────────────────────

/**
 * Build verify.txt, plain-English instructions for the recipient
 * (written for an attorney, not an engineer, BUILD_PLAN.md §5).
 */
function buildVerifyTxt(manifest: Manifest): string {
  return [
    `DEPOSE Evidence Bundle Verification Instructions`,
    `═══════════════════════════════════════════════════`,
    '',
    `Bundle ID: ${manifest.bundleId}`,
    `Produced: ${manifest.producedAt}`,
    `Session: ${manifest.session.sessionId}`,
    `Agent: ${manifest.session.agentId}`,
    '',
    `This bundle contains a chronological record of an AI coding agent session.`,
    `The record is cryptographically signed and timestamped to prove it has not`,
    `been altered since creation.`,
    '',
    `To verify this bundle:`,
    '',
    `  1. Download the depose-verify binary, SHA256SUMS, SHA256SUMS.sig,`,
    `     and SHA256SUMS.pem from:`,
    `     ${VERIFIER_DOWNLOAD_URL}`,
    '',
    `  2. (Recommended) Verify the binary was built by the official`,
    `     GitHub Actions release workflow and not tampered with in`,
    `     transit. With cosign (https://docs.sigstore.dev/system_config/installation/):`,
    '',
    `     cosign verify-blob \\`,
    `       --certificate SHA256SUMS.pem \\`,
    `       --signature SHA256SUMS.sig \\`,
    `       --certificate-identity-regexp '^https://github.com/Aftermath-Technologies-Ltd/depose/' \\`,
    `       --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\`,
    `       SHA256SUMS`,
    '',
    `     Then check that your downloaded binary's SHA-256 matches the`,
    `     corresponding line in SHA256SUMS.`,
    '',
    `  3. Run:`,
    `     ./depose-verify verify <path-to-this-folder>`,
    '',
    `  4. A PASS result means:`,
    `     - Every event in this bundle matches its recorded hash chain`,
    `     - The manifest signature is valid`,
    `     - A trusted timestamp authority confirmed this bundle existed at ${manifest.producedAt}`,
    `     - No files have been added, removed, or modified since creation`,
    '',
    `  5. A FAIL result means the bundle may have been altered.`,
    '',
    `This bundle contains ${manifest.counts.events} events,`,
    `${manifest.counts.destructiveOperations} destructive operations,`,
    `and ${manifest.counts.gaps} coverage gaps.`,
    '',
    `For questions, contact the bundle producer.`,
  ].join('\n');
}