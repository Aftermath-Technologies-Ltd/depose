// packages/cli/src/commands/package.ts
//
// `depose package --from-claude <path>`, Phase 2 signed bundle production.
//
// Builds a fully signed .depo bundle with:
//   - IRONROOT hash chain
//   - Ed25519 signature
//   - RFC 3161 timestamps (unless --skip-timestamp)
//   - Rekor transparency log (deferred)
//
// Named exports only.

import { resolve } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import {
  buildTimeline,
  formatTimelineSummary,
  loadRuleset,
  generateUlid,
  setFixedUlidSeed,
  DEFAULT_CAPTURE_DIR,
  type AgentId,
} from '@depose/core';
import { writeBundle } from '@depose/bundle';
import { loadOrGenerateKeyPair, fingerprintPublicKeyPem } from '@depose/chain';
import { DEFAULT_RULES_PATH } from '../rules-default.js';
import { loadAndMergeEvents } from '../pipeline.js';
import { captureStoreWarning } from './captures.js';
import { tsaEndpointsFromRuleset } from './anchor.js';
import { CLI_VERSION } from '../version.js';

// ── CLI args interface ─────────────────────────────────────────────

export interface PackageCommandArgs {
  'from-claude'?: string;
  rules?: string;
  ruleset?: string;
  output?: string;
  'output-dir'?: string;
  'session-id'?: string;
  'agent-id'?: string;
  'skip-timestamp'?: boolean;
  'require-anchor'?: boolean;
  'key-dir'?: string;
  /** Pin ULID generation to a deterministic seed (for reproducibility tests). */
  'fixed-seed'?: string;
  /** Override producedAt timestamp (ISO 8601) for reproducibility tests. */
  'produced-at'?: string;
  [key: string]: string | boolean | string[] | undefined;
}

// ── Package command handler ───────────────────────────────────────

/**
 * Handle `depose package --from-claude <path>`.
 *
 * Produces a fully signed .depo bundle with hash chain, Ed25519
 * signature, and RFC 3161 timestamps.
 */
export async function handlePackage(args: PackageCommandArgs): Promise<void> {
  const jsonlPath: string | undefined = typeof args['from-claude'] === 'string' ? args['from-claude'] : undefined;
  const rulesPath = (args['rules'] || args['ruleset']) as string | undefined;
  const outputDir = (args['output'] || args['output-dir']) as string | undefined;
  const sessionId = args['session-id'] as string | undefined;
  const agentId = (args['agent-id'] || 'claude-code') as string;
  const skipTimestamp = args['skip-timestamp'] === true;
  const keyDir = args['key-dir'] as string | undefined;
  const fixedSeed = args['fixed-seed'] as string | undefined;
  const producedAtOverride = args['produced-at'] as string | undefined;

  if (!jsonlPath) {
    console.error('ERROR: --from-claude <path> is required.');
    console.error('');
    console.error('Usage: depose package --from-claude <path> [options]');
    process.exit(1);
    return;
  }

  // Pin ULID generation to a deterministic seed when requested.
  // This is for reproducibility / determinism testing only; production
  // runs must never use --fixed-seed (it destroys the CSPRNG guarantee).
  if (fixedSeed) {
    setFixedUlidSeed(Number(fixedSeed));
    console.log(`FIXED SEED: ${fixedSeed}, ULID generation is deterministic (NOT for production)`);
  }

  // Resolve paths
  const resolvedJsonl = resolve(jsonlPath);
  const resolvedOutput = outputDir ? resolve(outputDir) : resolve('./depose-output');
  const resolvedRules = rulesPath ? resolve(rulesPath) : DEFAULT_RULES_PATH;

  // Validate input
  if (!existsSync(resolvedJsonl)) {
    console.error(`ERROR: Input file not found: ${resolvedJsonl}`);
    process.exit(1);
    return;
  }

  // Load or generate Ed25519 key pair
  console.log('Loading Ed25519 signing key...');
  const keyPair = loadOrGenerateKeyPair(keyDir);
  console.log(`Key fingerprint: ${fingerprintPublicKeyPem(keyPair.publicKeyPem)}`);

  // Load destructive rules. Bytes are passed verbatim to the
  // bundle writer so the verifier can re-hash them against
  // manifest.rulesetHash.
  const ruleset = loadRuleset(resolvedRules);
  const rules = ruleset.rules;
  const rulesetBytes = readFileSync(resolvedRules);

  console.log('Normalizing session data...');
  const {
    events: merged,
    warnings: pipelineWarnings,
    gapCount,
    linkedCount,
    captureRecordCount,
    captureStoreRecordCount,
    captureExcluded,
  } = loadAndMergeEvents({
    jsonlPath: resolvedJsonl,
    sessionId,
    agentId: agentId as AgentId,
    captureDir: args['capture-dir'] as string | undefined,
    includeUnscopedCaptures: args['include-unscoped-captures'] === true,
  });
  const capturesExcluded = Object.values(captureExcluded).reduce((a, b) => a + b, 0);
  if (captureStoreRecordCount > 0) {
    console.log(
      `Capture store: ${captureStoreRecordCount} record(s), ` +
        `${captureRecordCount} attributable to this session, ${capturesExcluded} excluded`
    );
    // Nothing expires on its own, so surface growth where the user is
    // already looking rather than waiting for them to go find it.
    const storeWarning = captureStoreWarning(
      (args['capture-dir'] as string | undefined) ?? DEFAULT_CAPTURE_DIR
    );
    if (storeWarning) console.log(`  WARN: ${storeWarning}`);
  }
  console.log(`Merged ${merged.length} events (${gapCount} gaps, ${linkedCount} linked)`);

  // Build timeline
  const timeline = buildTimeline(merged, rules);
  const summary = formatTimelineSummary(timeline);
  console.log(summary);

  // Build and sign bundle
  const bundleId = sessionId || (merged[0]?.sessionId || generateUlid());
  const sessionStarted = merged.length > 0 ? (merged[0]?.wallTs ?? new Date().toISOString()) : new Date().toISOString();
  const sessionEnded = merged.length > 0 ? (merged[merged.length - 1]?.wallTs ?? new Date().toISOString()) : new Date().toISOString();
  const producedAt = producedAtOverride || new Date().toISOString();

  // --skip-timestamp downgrades the run to dev-unsigned mode. The
  // resulting bundle carries empty signatures + timestamps and is
  // explicitly labelled NOT EVIDENCE. Production runs omit the flag.
  const mode: 'signed' | 'dev-unsigned' = skipTimestamp ? 'dev-unsigned' : 'signed';

  console.log(`Mode: ${mode}`);
  if (mode === 'signed') {
    console.log('Building hash chain...');
    console.log('Signing manifest...');
    console.log('Requesting RFC 3161 timestamps...');
  } else {
    console.log('Building hash chain... (dev-unsigned: no signature, no timestamp)');
  }

  try {
    const { depopPath, manifest, warnings: bundleWarnings } = await writeBundle(merged, rules, {
      sessionId: bundleId,
      agentId,
      version: CLI_VERSION,
      producedAt,
      sessionStartedAt: sessionStarted,
      sessionEndedAt: sessionEnded,
      rules,
      rulesetBytes,
      disclosable: ruleset.disclosable,
      outputDir: resolvedOutput,
      mode,
      keyPair,
      sourceJsonlPath: resolvedJsonl,
      capturesAttributed: captureRecordCount,
      capturesExcluded,
      captureSourceDir: (args['capture-dir'] as string | undefined) ?? DEFAULT_CAPTURE_DIR,
      tsaEndpoints: tsaEndpointsFromRuleset(ruleset.tsa),
      requireAnchor: args['require-anchor'] === true,
    });

    for (const w of [...pipelineWarnings, ...bundleWarnings]) {
      console.log(`  WARN: ${w}`);
    }

    console.log('');
    console.log(`${mode === 'signed' ? 'Signed' : 'Dev-unsigned'} bundle written to: ${depopPath}`);
    console.log(`Manifest: ${JSON.stringify({
      bundleId: manifest.bundleId,
      mode: manifest.producer.mode,
      events: manifest.counts.events,
      destructiveOps: manifest.counts.destructiveOperations,
      gaps: manifest.counts.gaps,
      rootHash: manifest.rootHash ? manifest.rootHash.slice(0, 16) + '...' : '(empty)',
      signatures: manifest.signatures.length,
      timestamps: manifest.timestamps.length,
      anchorStatus: manifest.anchorStatus ?? 'anchored',
    }, null, 2)}`);
    if (manifest.anchorStatus === 'pending') {
      console.log('');
      console.log('This bundle is SEALED PENDING ANCHOR: signed, but nothing dates it yet.');
      console.log(`Run "depose anchor ${depopPath}" once the network is back.`);
    }
    console.log('');
    console.log('To verify: ./depose-verify verify ' + depopPath);
  } catch (err) {
    console.error('');
    console.error(`FATAL: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

