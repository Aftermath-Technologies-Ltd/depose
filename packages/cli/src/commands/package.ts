// packages/cli/src/commands/package.ts
//
// `depose package --from-claude <path>` — Phase 2 signed bundle production.
//
// Builds a fully signed .depo bundle with:
//   - IRONROOT hash chain
//   - Ed25519 signature
//   - RFC 3161 timestamps (unless --skip-timestamp)
//   - Rekor transparency log (deferred)
//
// Named exports only (BUILD_PLAN.md §3.1).

import { resolve, join, dirname } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import {
  normalizeClaudeCodeJsonl,
  parseShellHistory,
  parseGitReflog,
  reflogToEvents,
  mergeEvents,
  buildTimeline,
  formatTimelineSummary,
  loadDestructiveRules,
  generateUlid,
  ulidFromTime,
  sha256,
  normalizeCaptureRecords,
  type Event,
  type ShellCommandPrePayload,
  type AgentId,
} from '@depose/core';
import { writeBundle } from '@depose/bundle';
import { loadOrGenerateKeyPair } from '@depose/chain';
import { DEFAULT_RULES_PATH } from '../rules-default.js';

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
  'key-dir'?: string;
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

  if (!jsonlPath) {
    console.error('ERROR: --from-claude <path> is required.');
    console.error('');
    console.error('Usage: depose package --from-claude <path> [options]');
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

  // Load or generate Ed25519 key pair
  console.log('Loading Ed25519 signing key...');
  const keyPair = loadOrGenerateKeyPair(keyDir);
  console.log(`Public key: ${keyPair.publicKeyPem.split('\n')[1]?.slice(0, 20)}...`);

  // Load destructive rules (bytes are also retained for the bundle so
  // the verifier can re-hash them against manifest.rulesetHash).
  const rules = loadDestructiveRules(resolvedRules);
  const rulesetBytes = readFileSync(resolvedRules);

  // Read and normalize JSONL
  console.log('Normalizing session data...');
  const jsonl = readFileSync(resolvedJsonl, 'utf-8');
  const { events: claudeEvents, warnings: normalizeWarnings } = normalizeClaudeCodeJsonl(jsonl, {
    sessionId,
    agentId: agentId as AgentId,
  });

  // Load shell history (if available)
  const shellHistoryPath = join(dirname(resolvedJsonl), 'shell-history.txt');
  let shellEvents: Event[] = [];
  if (existsSync(shellHistoryPath)) {
    const shellHistory = readFileSync(shellHistoryPath, 'utf-8');
    const shellCommands = parseShellHistory(shellHistory);
    const shellSessionId = sessionId || claudeEvents[0]?.sessionId || generateUlid();
    const shellMonoOffset = claudeEvents.length;
    const shellStart = claudeEvents[0]?.wallTs || new Date().toISOString();
    shellEvents = [];
    for (const cmd of shellCommands) {
      const monoNs = shellMonoOffset + shellEvents.length;
      const wallTs = cmd.timestamp || shellStart;
      shellEvents.push(createShellCommandEvent(cmd, shellSessionId, 'shell', monoNs, wallTs));
    }
  }

  // Load git reflog (if available)
  const reflogPath = join(dirname(resolvedJsonl), 'git-reflog.txt');
  let reflogEvents: Event[] = [];
  if (existsSync(reflogPath)) {
    const reflog = readFileSync(reflogPath, 'utf-8');
    const reflogEntries = parseGitReflog(reflog);
    const reflogSessionId = sessionId || claudeEvents[0]?.sessionId || generateUlid();
    const reflogOffset = claudeEvents.length + shellEvents.length;
    const { events: reflogResult } = reflogToEvents(reflogEntries, {
      sessionId: reflogSessionId,
      agentId: 'shell',
      monoOffset: reflogOffset,
    });
    reflogEvents = reflogResult;
  }

  // Load pre-execution capture records (Phase 3)
  const captureDirFromArgs = args['capture-dir'] as string | undefined;
  const captureResult = normalizeCaptureRecords(captureDirFromArgs, {
    sessionId: sessionId || claudeEvents[0]?.sessionId || generateUlid(),
    agentId: agentId as AgentId,
    monoOffset: claudeEvents.length + shellEvents.length + reflogEvents.length,
  });
  const captureEvents = captureResult.events;
  if (captureResult.recordCount > 0) {
    console.log(`Loaded ${captureResult.recordCount} pre-execution capture records`);
  }
  for (const w of captureResult.warnings) {
    console.log(`  WARN: ${w}`);
  }

  // Merge all sources
  const { events: merged, warnings: mergeWarnings, gapCount, linkedCount } = mergeEvents(
    {
      claudeCodeEvents: claudeEvents,
      shellHistoryEvents: shellEvents,
      reflogEvents: reflogEvents,
      captureEvents,
    },
    {
      sessionId: sessionId || claudeEvents[0]?.sessionId || generateUlid(),
      agentId: agentId as AgentId,
    }
  );

  console.log(`Merged ${merged.length} events (${gapCount} gaps, ${linkedCount} linked)`);

  // Build timeline
  const timeline = buildTimeline(merged, rules);
  const summary = formatTimelineSummary(timeline);
  console.log(summary);

  // Build and sign bundle
  const bundleId = sessionId || (claudeEvents[0]?.sessionId || generateUlid());
  const sessionStarted = merged.length > 0 ? (merged[0]?.wallTs ?? new Date().toISOString()) : new Date().toISOString();
  const sessionEnded = merged.length > 0 ? (merged[merged.length - 1]?.wallTs ?? new Date().toISOString()) : new Date().toISOString();
  const producedAt = new Date().toISOString();

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
      version: '0.1.0',
      producedAt,
      sessionStartedAt: sessionStarted,
      sessionEndedAt: sessionEnded,
      rules,
      rulesetBytes,
      outputDir: resolvedOutput,
      mode,
      keyPair,
    });

    for (const w of [...normalizeWarnings, ...mergeWarnings, ...bundleWarnings]) {
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
    }, null, 2)}`);
    console.log('');
    console.log('To verify: ./depose-verify verify ' + depopPath);
  } catch (err) {
    console.error('');
    console.error(`FATAL: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

// ── Helpers ──────────────────────────────────────────────────────────

function createShellCommandEvent(
  cmd: {
    timestamp: string | null;
    command: string;
    argv: string[];
    cwd: string | null;
    exitCode: number | null;
    durationMs: number | null;
  },
  sessionId: string,
  agentId: 'shell',
  monoNs: number,
  wallTs: string
): Event {
  const id = ulidFromTime(Date.now());
  const prePayload: ShellCommandPrePayload = {
    argv: cmd.argv,
    cwd: cmd.cwd || '',
    envHash: '',
    envSubset: {},
    ttyId: null,
    user: process.env.USER || '',
    hostname: process.env.HOSTNAME || '',
    parentProcessTree: [],
    fileArgs: [],
    source: 'shell-shim',
    captureSchemaVersion: 1,
  };
  const preHash = sha256(prePayload);
  const preEvent: Event = {
    id,
    wallTs,
    monoNs,
    sessionId,
    agentId,
    parentEventId: null,
    type: 'shell_command_pre',
    payload: prePayload,
    payloadHash: preHash,
  };
  return preEvent;
}