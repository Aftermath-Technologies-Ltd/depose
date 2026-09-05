// packages/bundle/src/writer.ts
//
// Bundle writer for .depo bundles.
//
// Order matters, and it is the reverse of what a naive writer does:
//   1. Commit disclosable fields, hash-chain the events, build the
//      Merkle tree, and pin the events.jsonl bytes (writer-seal.ts).
//   2. Write every content file: events.jsonl, raw/, rules/, narrative,
//      verify.txt.
//   3. Walk the tree and build the files map (files-map.ts).
//   4. Put the map in the manifest, sign the manifest, request the
//      RFC 3161 timestamp over the signed form. A timestamp that cannot
//      be obtained leaves the bundle sealed pending an anchor rather
//      than unproduced; see anchor.ts.
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
import type { BundleWriterOptions, BundleOutput } from './writer-options.js';
import { buildTimeline, sha256Bytes, DEFAULT_DISCLOSABLE, COMMITMENT_ALGORITHM, type CommitmentsFile } from '@depose/core';
import { serializeManifest } from './manifest-io.js';
import { buildManifest } from './manifest.js';
import { buildFilesMap } from './files-map.js';
import { buildVerifyTxt, wrapHtmlBanner, DEV_UNSIGNED_BANNER } from './verify-txt.js';
import { copyRawSources, copyCaptureRecords } from './writer-sources.js';
import { attestManifest } from './writer-attest.js';
import { sealEvents } from './writer-seal.js';
import { fingerprintPublicKeyPem } from '@depose/chain';
import { renderMarkdown, renderHtml } from '@depose/narrative';

// ── Bundle layout constants ──────────────────────────────────────────

const BUNDLE_DIR_SIGNED = 'incident';
const BUNDLE_DIR_DEV_UNSIGNED = 'incident-unsigned';
const MANIFEST_PATH = 'manifest.json';
const EVENTS_PATH = 'events.jsonl';
const RAW_DIR = 'raw';
const ATTESTATIONS_DIR = 'attestations';
const RULES_DIR = 'rules';
const COMMITMENTS_PATH = 'commitments.json';
const NARRATIVE_MD = 'narrative.md';
const NARRATIVE_HTML = 'narrative.html';
const VERIFY_TXT = 'verify.txt';

// ── Main writer ──────────────────────────────────────────────────────

/**
 * Write a .depo bundle in the requested mode (see `BundleMode`).
 *
 * Modes:
 *   - `signed`: builds chain, signs, timestamps. Requires keyPair.
 *     When no TSA answers the bundle is sealed with
 *     `anchorStatus: "pending"` and a warning; pass `requireAnchor` to
 *     fail closed instead.
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
 * @throws Error when signed mode has no key, or when `requireAnchor` is
 *   set and no TSA can be reached.
 */
export async function writeBundle(
  events: Event[],
  rules: DestructiveRule[],
  options: BundleWriterOptions
): Promise<BundleOutput> {
  const { sessionId, agentId, version, producedAt, sessionStartedAt, sessionEndedAt } = options;
  const { rulesetBytes, outputDir, mode, keyPair, injectedTimestamps, sourceJsonlPath } = options;
  const tsaEndpoints = options.tsaEndpoints;
  const requireAnchor = options.requireAnchor === true;

  if (mode === 'signed' && !keyPair) {
    throw new Error(
      'mode="signed" requires a keyPair. Use mode="dev-unsigned" for unsigned bundles.'
    );
  }

  const warnings: string[] = [];
  const bundleId = sessionId;
  const isDevUnsigned = mode === 'dev-unsigned';

  // ── Step 1: commit, chain, tree, and pin events.jsonl ──────────────
  // Sorted once by id; the seal, the file bytes, and the manifest
  // counts all read from this one ordering. Counts and the narrative
  // come from the plaintext events; the seal covers the committed form.
  const sortedEvents = [...events].sort((a, b) => a.id.localeCompare(b.id));
  const seal = sealEvents(sortedEvents, {
    keyPair,
    commitFields: options.commitFields ?? true,
    disclosable: options.disclosable ?? [...DEFAULT_DISCLOSABLE],
  });
  const { sealedEvents, rootHash, eventsJsonlBytes } = seal;

  const keyFingerprint = mode === 'signed' && keyPair
    ? fingerprintPublicKeyPem(keyPair.publicKeyPem)
    : undefined;
  const manifest = buildManifest(sortedEvents, rules, {
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
    merkleRoot: seal.merkleRoot,
    eventsJsonlSha256: seal.eventsJsonlSha256,
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
  if (options.commitFields ?? true) {
    const commitments: CommitmentsFile = {
      schemaVersion: 1,
      algorithm: COMMITMENT_ALGORITHM,
      openings: seal.openings,
    };
    writeFileSync(join(bundleDir, COMMITMENTS_PATH), JSON.stringify(commitments, null, 2) + '\n', 'utf-8');
  }

  const rawDir = join(bundleDir, RAW_DIR);
  if (sourceJsonlPath) {
    copyRawSources(rawDir, sourceJsonlPath);
  }
  if (options.captureSourceDir) {
    warnings.push(...copyCaptureRecords(rawDir, options.captureSourceDir, sortedEvents));
  }

  const rulesDir = join(bundleDir, RULES_DIR);
  mkdirSync(rulesDir, { recursive: true });
  writeFileSync(join(rulesDir, 'destructive.yaml'), rulesetBytes);

  const timeline = buildTimeline(sortedEvents, rules);
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
  const { signatures, timestamps } = await attestManifest(manifest, {
    mode,
    keyPair,
    injectedTimestamps,
    tsaEndpoints,
    requireAnchor,
    bundleDir,
    warnings,
  });

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
    events: sealedEvents,
    warnings,
  };
}

export type { BundleWriterOptions, BundleOutput } from './writer-options.js';
