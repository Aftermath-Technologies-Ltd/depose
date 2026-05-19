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

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Event, DestructiveRule } from '@depose/core';
import { buildTimeline, sha256Bytes } from '@depose/core';
import { buildManifest, serializeManifest, serializeManifestForSigning, type BundleMode, type Manifest, type SignatureBlock, type Rfc3161Token } from './manifest.js';
import { buildHashChain } from '@depose/chain';
import { signManifest as signManifestEd25519, type Ed25519KeyPair } from '@depose/chain';
import { requestTimestamps, type Rfc3161Token as ChainRfc3161Token } from '@depose/chain';
import { renderMarkdown, renderHtml } from '@depose/narrative';

// ── Bundle layout constants (BUILD_PLAN.md §5) ──────────────────────

const BUNDLE_DIR_SIGNED = 'incident';
const BUNDLE_DIR_DEV_UNSIGNED = 'incident-unsigned';
const DEV_UNSIGNED_BANNER = [
  '═══════════════════════════════════════════════════════════════════',
  '  THIS IS A DEVELOPMENT BUNDLE — NOT EVIDENCE',
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
const ARTIFACTS_DIR = 'artifacts';
const ATTESTATIONS_DIR = 'attestations';
const RULES_DIR = 'rules';
const NARRATIVE_MD = 'narrative.md';
const NARRATIVE_HTML = 'narrative.html';
const VERIFY_TXT = 'verify.txt';

// ── Writer options ───────────────────────────────────────────────────

export interface BundleWriterOptions {
  /** Session ID (ULID) — used as bundle directory name */
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
  /** Original ruleset bytes — written verbatim into the bundle and
   *  hashed into manifest.rulesetHash. The verifier re-reads the
   *  embedded file and re-hashes it to enforce ruleset integrity. */
  rulesetBytes: Buffer;
  /** Output directory (where the .depo directory is written) */
  outputDir: string;
  /**
   * Bundle production mode (see BundleMode docstring).
   *
   * `signed` — production. Requires keyPair. Builds chain, signs,
   *   requests RFC 3161 timestamps. The bundle is named
   *   `incident-<id>` and is the only mode acceptable as evidence.
   * `dev-unsigned` — pipeline testing. signatures/timestamps are
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

  // ── Step 2: Build manifest ────────────────────────────────────────
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
        `Failed to obtain RFC 3161 timestamp — cannot produce signed bundle.\n${msg}\n` +
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

  // Write events.jsonl (one event per line, sorted by id)
  const sortedEvents = [...chainedEvents].sort((a, b) => a.id.localeCompare(b.id));
  const eventsJsonl = sortedEvents.map((e) => JSON.stringify(e)).join('\n') + '\n';
  writeFileSync(join(bundleDir, EVENTS_PATH), eventsJsonl, 'utf-8');

  // Write raw/ directory (populated by capture layer in Phase 3)
  const rawClaudeDir = join(bundleDir, RAW_DIR, 'claude-code');
  mkdirSync(rawClaudeDir, { recursive: true });
  const rawCodexDir = join(bundleDir, RAW_DIR, 'codex');
  mkdirSync(rawCodexDir, { recursive: true });
  const rawShellDir = join(bundleDir, RAW_DIR, 'shell-history');
  mkdirSync(rawShellDir, { recursive: true });
  const rawReflogFile = join(bundleDir, RAW_DIR, 'git-reflog.txt');
  writeFileSync(rawReflogFile, '', 'utf-8');
  const rawCaptureDir = join(bundleDir, RAW_DIR, 'capture');
  mkdirSync(rawCaptureDir, { recursive: true });

  // Write artifacts/ directory (populated by capture layer in Phase 3)
  const artifactsPre = join(bundleDir, ARTIFACTS_DIR, 'files-pre');
  mkdirSync(artifactsPre, { recursive: true });
  const artifactsPost = join(bundleDir, ARTIFACTS_DIR, 'files-post');
  mkdirSync(artifactsPost, { recursive: true });

  // Write attestations/ directory
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

  // rekor-entries.json
  writeFileSync(
    join(attestationsDir, 'rekor-entries.json'),
    JSON.stringify({ entries: [] }, null, 2),
    'utf-8'
  );

  // Write rules/ directory.
  // The original ruleset bytes are written verbatim so a third-party
  // verifier can re-hash them and compare against manifest.rulesetHash.
  const rulesDir = join(bundleDir, RULES_DIR);
  mkdirSync(rulesDir, { recursive: true });
  writeFileSync(join(rulesDir, 'destructive.yaml'), rulesetBytes);

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
  const banner = '<div style="background:#7a1f1f;color:#fff;padding:1em 1.5em;border-bottom:4px solid #ff0;font-family:-apple-system,Segoe UI,sans-serif;font-weight:bold"><strong>THIS IS A DEVELOPMENT BUNDLE — NOT EVIDENCE.</strong> mode="dev-unsigned": no signature, no timestamp.</div>';
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
 * Build verify.txt — plain-English instructions for the recipient
 * (written for an attorney, not an engineer — BUILD_PLAN.md §5).
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
    `  1. Download the depose-verify binary from:`,
    `     https://github.com/depose/depose/releases/latest`,
    '',
    `  2. Run:`,
    `     ./depose-verify verify <path-to-this-folder>`,
    '',
    `  3. A PASS result means:`,
    `     - Every event in this bundle matches its recorded hash chain`,
    `     - The manifest signature is valid`,
    `     - A trusted timestamp authority confirmed this bundle existed at ${manifest.producedAt}`,
    `     - No files have been added, removed, or modified since creation`,
    '',
    `  4. A FAIL result means the bundle may have been altered.`,
    '',
    `This bundle contains ${manifest.counts.events} events,`,
    `${manifest.counts.destructiveOperations} destructive operations,`,
    `and ${manifest.counts.gaps} coverage gaps.`,
    '',
    `For questions, contact the bundle producer.`,
  ].join('\n');
}