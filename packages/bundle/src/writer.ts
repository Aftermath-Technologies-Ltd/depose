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
import { buildTimeline } from '@depose/core';
import { buildManifest, serializeManifest, serializeManifestForSigning, hashManifest, type Manifest, type SignatureBlock, type Rfc3161Token } from './manifest.js';
import { buildHashChain } from '@depose/chain';
import { signManifest as signManifestEd25519, type Ed25519KeyPair } from '@depose/chain';
import { requestTimestamps, type Rfc3161Token as ChainRfc3161Token } from '@depose/chain';
import { renderMarkdown, renderHtml } from '@depose/narrative';

// ── Bundle layout constants (BUILD_PLAN.md §5) ──────────────────────

const BUNDLE_DIR = 'incident';
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
  /** Ruleset hash (SHA-256 of ruleset YAML) */
  rulesetHash: string;
  /** Output directory (where the .depo directory is written) */
  outputDir: string;
  /** Ed25519 key pair for signing (required for signed bundles) */
  keyPair?: Ed25519KeyPair;
  /** Whether to skip RFC 3161 timestamping (default: false) */
  skipTimestamp?: boolean;
  /** Whether to produce an unsigned bundle (Phase 1 compatible) */
  unsigned?: boolean;
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
 * Write a signed .depo bundle (Phase 2: fully signed and timestamped).
 *
 * If `unsigned` is true, produces a Phase 1-compatible unsigned bundle
 * (no chain hashes, no signatures, no timestamps).
 *
 * The signed path:
 *   1. Build hash chain over sorted events (IRONROOT construction)
 *   2. Build manifest with rootHash from chain
 *   3. Sign manifest with Ed25519
 *   4. Request RFC 3161 timestamps from TSA
 *   5. Write all bundle files
 *
 * @param events - Events to include in the bundle
 * @param rules - Destructive ruleset
 * @param options - Bundle writer options
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
    rulesetHash,
    outputDir,
    keyPair,
    skipTimestamp,
    unsigned,
  } = options;

  const warnings: string[] = [];
  const bundleId = sessionId;

  let rootHash = '';
  let chainedEvents = events;

  // ── Step 1: Build hash chain (Phase 2) ───────────────────────────
  if (!unsigned) {
    // Sort events by id (ULID) for deterministic chain
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
    sessionId,
    agentId,
    sessionStartedAt,
    sessionEndedAt,
    rulesetHash,
    rootHash,
  });

  let signatures: SignatureBlock[] = [];
  let timestamps: Rfc3161Token[] = [];

  // ── Step 3: Sign manifest (Phase 2) ────────────────────────────────
  if (!unsigned && keyPair) {
    // Sign the manifest in its unsigned form (no signatures, no timestamps)
    // to avoid the self-referential signature problem
    const manifestForSigning = serializeManifestForSigning(manifest);
    const sigResult = signManifestEd25519(manifestForSigning, keyPair);

    signatures.push({
      scheme: 'ed25519',
      signature: sigResult.signatureBase64,
      publicKey: sigResult.publicKeyPem,
      signedFields: 'manifest.json',
    });

    // Update manifest with signature
    manifest.signatures = signatures;
  }

  // ── Step 4: Request RFC 3161 timestamps (Phase 2) ──────────────────
  if (!unsigned && !skipTimestamp) {
    try {
      // Timestamp the UNSIGNED manifest (same form used for signing)
      // so the verifier can reconstruct it by stripping signatures/timestamps.
      const manifestForTimestamping = serializeManifestForSigning(manifest);
      const tsTokens = await requestTimestamps(manifestForTimestamping);

      for (const token of tsTokens) {
        timestamps.push({
          tsa: token.tsa,
          timestamp: token.timestamp,
          tokenBase64: token.tokenBase64,
        });
      }

      // Update manifest with timestamps
      manifest.timestamps = timestamps;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // Per BUILD_PLAN.md: "Never produce a bundle without a timestamp"
      // This is a hard error for signed bundles
      throw new Error(
        `Failed to obtain RFC 3161 timestamp — cannot produce signed bundle.\n${msg}`
      );
    }
  }

  if (unsigned) {
    warnings.push('Bundle is unsigned (Phase 1 mode). No chain hashes, signatures, or timestamps.');
  }

  // ── Step 5: Write the bundle directory ─────────────────────────────
  const bundleDir = join(outputDir, `${BUNDLE_DIR}-${bundleId}`);
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

  // Write rules/ directory
  const rulesDir = join(bundleDir, RULES_DIR);
  mkdirSync(rulesDir, { recursive: true });
  writeFileSync(join(rulesDir, 'destructive.yaml'), rulesetHash, 'utf-8');

  // Build timeline for narrative rendering
  const timeline = buildTimeline(chainedEvents, destructiveRules);

  // Write narrative files (Phase 4: deterministically rendered)
  const narrativeMd = renderMarkdown(timeline, {
    bundleId,
    producedAt,
    agentId,
    sessionId,
    sessionStartedAt,
    sessionEndedAt,
  });
  writeFileSync(join(bundleDir, NARRATIVE_MD), narrativeMd, 'utf-8');

  const narrativeHtml = renderHtml(timeline, {
    bundleId,
    producedAt,
    agentId,
    sessionId,
    sessionStartedAt,
    sessionEndedAt,
  });
  writeFileSync(join(bundleDir, NARRATIVE_HTML), narrativeHtml, 'utf-8');

  // Write verify.txt (attorney-friendly instructions)
  const verifyTxt = buildVerifyTxt(manifest);
  writeFileSync(join(bundleDir, VERIFY_TXT), verifyTxt, 'utf-8');

  return {
    depopPath: bundleDir,
    manifest,
    events: sortedEvents,
    warnings,
  };
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