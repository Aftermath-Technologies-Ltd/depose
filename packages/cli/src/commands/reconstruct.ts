// packages/cli/src/commands/reconstruct.ts
//
// `depose reconstruct`: dev-unsigned bundle from a session JSONL.
// Deprecated in favour of `depose record`, kept so existing scripts and
// docs do not break. Split out of main.ts, which was carrying the command
// wiring and three handlers in one file.

import { resolve } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { buildTimeline, formatTimelineSummary, loadDestructiveRules, generateUlid, DEFAULT_CAPTURE_DIR, type AgentId } from '@depose/core';
import { writeBundle } from '@depose/bundle';
import { DEFAULT_RULES_PATH } from '../rules-default.js';
import { loadAndMergeEvents } from '../pipeline.js';
import { CLI_VERSION } from '../version.js';
import type { CliArgs } from './cli-args.js';

export async function handleReconstruct(args: CliArgs): Promise<void> {
  const jsonlPath: string | undefined = typeof args['from-claude'] === 'string' ? args['from-claude'] : undefined;
  const rulesPath = (args['rules'] || args['ruleset']) as string | undefined;
  const outputDir = (args['output'] || args['output-dir']) as string | undefined;
  const sessionId = args['session-id'] as string | undefined;
  const agentId = (args['agent-id'] || 'claude-code') as string;

  if (!jsonlPath) {
    console.error('ERROR: --from-claude <path> is required.');
    console.error('');
    console.error('Usage: depose reconstruct --from-claude <path> [options]');
    process.exit(1);
    return;
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

  // Load destructive rules. Bytes are passed verbatim to the
  // bundle writer so the verifier can re-hash them against
  // manifest.rulesetHash.
  const rules = loadDestructiveRules(resolvedRules);
  const rulesetBytes = readFileSync(resolvedRules);

  // Load + normalize + merge all sources through the shared pipeline.
  const {
    events: merged,
    warnings,
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

  // Build timeline + emit human-readable summary.
  const timeline = buildTimeline(merged, rules);
  const summary = formatTimelineSummary(timeline);
  console.log(summary);
  console.log('');
  const capturesExcluded = Object.values(captureExcluded).reduce((a, b) => a + b, 0);
  if (captureStoreRecordCount > 0) {
    console.log(
      `Capture store: ${captureStoreRecordCount} record(s), ` +
        `${captureRecordCount} attributable to this session, ${capturesExcluded} excluded`
    );
  }
  console.log(`Gaps: ${gapCount}`);
  console.log(`Linked: ${linkedCount}`);
  console.log(`Warnings: ${warnings.length}`);
  for (const w of warnings) {
    console.log(`  WARN: ${w}`);
  }
  console.log('');

  const bundleId = sessionId || (merged[0]?.sessionId || generateUlid());
  const sessionStarted = merged.length > 0 ? (merged[0]?.wallTs ?? new Date().toISOString()) : new Date().toISOString();
  const sessionEnded = merged.length > 0 ? (merged[merged.length - 1]?.wallTs ?? new Date().toISOString()) : new Date().toISOString();
  const producedAt = new Date().toISOString();

  const { depopPath, manifest } = await writeBundle(merged, rules, {
    sessionId: bundleId,
    agentId,
    version: CLI_VERSION,
    producedAt,
    sessionStartedAt: sessionStarted,
    sessionEndedAt: sessionEnded,
    rules,
    rulesetBytes,
    outputDir: resolvedOutput,
    mode: 'dev-unsigned',
    sourceJsonlPath: resolvedJsonl,
    capturesAttributed: captureRecordCount,
    capturesExcluded,
    captureSourceDir: (args['capture-dir'] as string | undefined) ?? DEFAULT_CAPTURE_DIR,
  });

  console.log(`Bundle written to: ${depopPath}`);
  console.log(`Manifest: ${JSON.stringify({
    bundleId: manifest.bundleId,
    events: manifest.counts.events,
    destructiveOps: manifest.counts.destructiveOperations,
    gaps: manifest.counts.gaps,
    rootHash: manifest.rootHash || '(empty)',
  }, null, 2)}`);
}

// ── Install command (Phase 3, active capture) ──────────────────────

