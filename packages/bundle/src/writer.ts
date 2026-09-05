// packages/bundle/src/writer.ts
//
// Bundle writer for .depo bundles.
//
// Order matters, and it is the reverse of what a naive writer does:
//   1. Hash-chain the events and pin the events.jsonl bytes.
//   2. Write every content file: events.jsonl, raw/, rules/, narrative,
//      verify.txt.
//   3. Walk the tree and build the files map (files-map.ts).
//   4. Put the map in the manifest, sign the manifest, request the
//      RFC 3161 timestamp over the signed form.
//   5. Write manifest.json and the attestations last.
//
// Steps 3 to 5 are why a recipient cannot swap raw/ or truncate the
// narrative without the verifier noticing: the signature covers the
// hash of every file that was on disk when it was made.
//
// See docs/bundle-format.md#directory-layout.

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Event, DestructiveRule } from '@depose/core';
import { buildTimeline, sha256Bytes } from '@depose/core';
import {
  buildManifest,
  serializeManifest,
  serializeManifestForSigning,
  type BundleMode,
  type Manifest,
  type SignatureBlock,
  type Rfc3161Token,
} from './manifest.js';
import { buildFilesMap } from './files-map.js';
import { buildVerifyTxt, wrapHtmlBanner, DEV_UNSIGNED_BANNER } from './verify-txt.js';
import { copyRawSources, copyCaptureRecords } from './writer-sources.js';
import { buildHashChain } from '@depose/chain';
import { signManifest as signManifestEd25519, fingerprintPublicKeyPem, type Ed25519KeyPair } from '@depose/chain';
import { requestTimestamps, type Rfc3161Token as ChainRfc3161Token } from '@depose/chain';
import { renderMarkdown, renderHtml } from '@depose/narrative';

// ── Bundle layout constants ──────────────────────────────────────────

const BUNDLE_DIR_SIGNED = 'incident';
const BUNDLE_DIR_DEV_UNSIGNED = 'incident-unsigned';
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
   *  bundle, along with any shell-history.txt or git-reflog.txt
   *  sibling. */
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
   * that actually entered this bundle are copied into raw/captures/.
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
 *
 * @param events - The merged timeline.
 * @param rules - The destructive ruleset in effect.
 * @param options - Identity, mode, key, and source paths.
 * @returns The bundle path, manifest, chained events, and warnings.
 * @throws Error when signed mode has no key or no TSA can be reached.
 */
export async function writeBundle(
  events: Event[],
  rules: DestructiveRule[],
  options: BundleWriterOptions
): Promise<BundleOutput> {
  const { sessionId, agentId, version, producedAt, sessionStartedAt, sessionEndedAt } = options;
  const { rulesetBytes, outputDir, mode, keyPair, injectedTimestamps, sourceJsonlPath } = options;

  if (mode === 'signed' && !keyPair) {
    throw new Error(
      'mode="signed" requires a keyPair. Use mode="dev-unsigned" for unsigned bundles.'
    );
  }

  const warnings: string[] = [];
  const bundleId = sessionId;
  const isDevUnsigned = mode === 'dev-unsigned';

  // ── Step 1: chain and pin events.jsonl ─────────────────────────────
  // Sorted once by id; the chain, the file bytes, and the manifest
  // counts all read from this one ordering.
  const sortedEvents = [...events].sort((a, b) => a.id.localeCompare(b.id));
  let rootHash = '';
  let chainedEvents = sortedEvents;
  if (keyPair) {
    const chainResult = buildHashChain(sortedEvents);
    chainedEvents = chainResult.chainedEvents;
    rootHash = chainResult.rootHash;
  }
  const eventsJsonlBytes = Buffer.from(
    chainedEvents.map((e) => JSON.stringify(e)).join('\n') + '\n',
    'utf-8'
  );

  const keyFingerprint = mode === 'signed' && keyPair
    ? fingerprintPublicKeyPem(keyPair.publicKeyPem)
    : undefined;
  const manifest = buildManifest(chainedEvents, rules, {
    bundleId,
    producedAt,
    version,
    mode,
    sessionId,
    agentId,
    sessionStartedAt,
    sessionEndedAt,
    rulesetHash: sha256Bytes(rulesetBytes),
    rootHash,
    eventsJsonlSha256: sha256Bytes(eventsJsonlBytes),
    keyFingerprint,
    capturesAttributed: options.capturesAttributed,
    capturesExcluded: options.capturesExcluded,
  });

  // ── Step 2: write every content file ───────────────────────────────
  const bundleDirName = isDevUnsigned
    ? `${BUNDLE_DIR_DEV_UNSIGNED}-${bundleId}`
    : `${BUNDLE_DIR_SIGNED}-${bundleId}`;
  const bundleDir = join(outputDir, bundleDirName);
  mkdirSync(bundleDir, { recursive: true });

  writeFileSync(join(bundleDir, EVENTS_PATH), eventsJsonlBytes);

  const rawDir = join(bundleDir, RAW_DIR);
  if (sourceJsonlPath) {
    copyRawSources(rawDir, sourceJsonlPath);
  }
  if (options.captureSourceDir) {
    warnings.push(...copyCaptureRecords(rawDir, options.captureSourceDir, chainedEvents));
  }

  const rulesDir = join(bundleDir, RULES_DIR);
  mkdirSync(rulesDir, { recursive: true });
  writeFileSync(join(rulesDir, 'destructive.yaml'), rulesetBytes);

  const timeline = buildTimeline(chainedEvents, rules);
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
  const verifyTxt = buildVerifyTxt(manifest);
  writeFileSync(
    join(bundleDir, VERIFY_TXT),
    isDevUnsigned ? DEV_UNSIGNED_BANNER + verifyTxt : verifyTxt,
    'utf-8'
  );

  // The attestations directory exists in every bundle, even when empty.
  const attestationsDir = join(bundleDir, ATTESTATIONS_DIR);
  const timestampDir = join(attestationsDir, 'rfc3161-timestamps');
  mkdirSync(timestampDir, { recursive: true });

  // ── Step 3: files map over everything on disk ──────────────────────
  manifest.files = buildFilesMap(bundleDir);

  // ── Step 4: sign, then timestamp the signed form ───────────────────
  const signatures: SignatureBlock[] = [];
  const timestamps: Rfc3161Token[] = [];
  if (mode === 'signed') {
    const sigResult = signManifestEd25519(serializeManifestForSigning(manifest), keyPair!);
    signatures.push({
      scheme: 'ed25519',
      signature: sigResult.signatureBase64,
      publicKey: sigResult.publicKeyPem,
      signedFields: 'manifest.json',
    });
    manifest.signatures = signatures;

    try {
      const tsTokens = injectedTimestamps && injectedTimestamps.length > 0
        ? injectedTimestamps
        : await requestTimestamps(serializeManifestForSigning(manifest));
      for (const token of tsTokens) {
        timestamps.push({ tsa: token.tsa, timestamp: token.timestamp, tokenBase64: token.tokenBase64 });
      }
      manifest.timestamps = timestamps;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(
        `Failed to obtain RFC 3161 timestamp, cannot produce signed bundle.\n${msg}\n` +
        `Use mode="dev-unsigned" if you need an unsigned bundle for pipeline testing.`,
        { cause: err }
      );
    }
  } else {
    warnings.push('Bundle is dev-unsigned. signatures=[], timestamps=[]. NOT EVIDENCE.');
  }

  // ── Step 5: manifest and attestations last ─────────────────────────
  writeFileSync(join(bundleDir, MANIFEST_PATH), serializeManifest(manifest), 'utf-8');
  writeFileSync(
    join(attestationsDir, 'signatures.json'),
    JSON.stringify({ blocks: signatures }, null, 2),
    'utf-8'
  );
  for (let i = 0; i < timestamps.length; i++) {
    writeFileSync(join(timestampDir, `${i}.tsr`), timestamps[i]!.tokenBase64, 'base64');
  }

  return {
    depopPath: bundleDir,
    manifest,
    events: chainedEvents,
    warnings,
  };
}
