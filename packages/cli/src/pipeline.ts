// packages/cli/src/pipeline.ts
//
// Shared event-loading pipeline used by both `depose reconstruct`
// and `depose package`. Previously these two commands carried ~150
// lines of duplicated JSONL/shell-history/reflog/capture loading and
// merging. Two copies drift; only one gets tested under stress.
//
// This module is intentionally narrow: it loads, normalizes, and
// merges. It does NOT write bundles, render narratives, or take
// any CLI-shaped args. Both callers pass plain options in and read
// the merged result.

import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import {
  normalizeClaudeCodeJsonl,
  parseShellHistory,
  parseGitReflog,
  reflogToEvents,
  mergeEvents,
  generateUlid,
  ulidFromTime,
  sha256,
  normalizeCaptureRecords,
  type Event,
  type ShellCommandPrePayload,
  type AgentId,
  type CaptureExclusionReason,
} from '@depose/core';

export interface PipelineOptions {
  /** Absolute path to the Claude Code JSONL session file. */
  jsonlPath: string;
  /** Optional ULID; auto-generated when missing. */
  sessionId?: string;
  /** Agent identifier (e.g. "claude-code"). */
  agentId: AgentId;
  /** Optional capture directory override. */
  captureDir?: string;
  /**
   * Merge capture records that carry no session id. Off by default:
   * records written before the session id existed, and shim records that
   * never had one, cannot be tied to this session by anything recorded.
   * Including them on a guess puts unrelated activity into signed evidence.
   */
  includeUnscopedCaptures?: boolean;
}

export interface PipelineResult {
  /** Merged, ordered events ready to hand to writeBundle. */
  events: Event[];
  /** Warnings collected from each loader and the merger. */
  warnings: string[];
  /** Number of gap events emitted by mergeEvents. */
  gapCount: number;
  /** Number of cross-source links the merger established. */
  linkedCount: number;
  /** Number of pre-execution capture records merged into the timeline. */
  captureRecordCount: number;
  /** Records present in the capture store before scoping was applied. */
  captureStoreRecordCount: number;
  /** Records deliberately left out of the bundle, by reason. */
  captureExcluded: Record<CaptureExclusionReason, number>;
}

/**
 * Load, normalize, and merge all event sources for a session.
 *
 * Sources, each optional except the JSONL:
 *   - <dir>/<input>.jsonl       Claude Code session
 *   - <dir>/shell-history.txt, Bash/zsh history near the session
 *   - <dir>/git-reflog.txt      reflog snapshot at incident time
 *   - $DEPOSE_CAPTURE_DIR       pre-execution capture records (Phase 3)
 *
 * Returns the merged event timeline and per-source warnings. The
 * caller decides what to do with them (print, fail closed, etc.).
 */
export function loadAndMergeEvents(opts: PipelineOptions): PipelineResult {
  const { jsonlPath, sessionId, agentId, captureDir, includeUnscopedCaptures } = opts;
  const warnings: string[] = [];

  // 1. Claude Code JSONL (the spine).
  const jsonl = readFileSync(jsonlPath, 'utf-8');
  const {
    events: claudeEvents,
    warnings: normalizeWarnings,
    agentSessionId,
  } = normalizeClaudeCodeJsonl(jsonl, {
    sessionId,
    agentId,
  });
  warnings.push(...normalizeWarnings);

  // 2. Shell history sibling file (best-effort).
  const sessionRoot = sessionId || claudeEvents[0]?.sessionId || generateUlid();
  const sessionStart = claudeEvents[0]?.wallTs || new Date().toISOString();
  const shellHistoryPath = join(dirname(jsonlPath), 'shell-history.txt');
  let shellEvents: Event[] = [];
  if (existsSync(shellHistoryPath)) {
    const shellHistory = readFileSync(shellHistoryPath, 'utf-8');
    const shellCommands = parseShellHistory(shellHistory);
    const baseOffset = claudeEvents.length;
    for (let i = 0; i < shellCommands.length; i++) {
      const cmd = shellCommands[i]!;
      const monoNs = baseOffset + i;
      const wallTs = cmd.timestamp || sessionStart;
      shellEvents.push(createShellCommandEvent(cmd, sessionRoot, monoNs, wallTs));
    }
  }

  // 3. Git reflog sibling file (best-effort).
  const reflogPath = join(dirname(jsonlPath), 'git-reflog.txt');
  let reflogEvents: Event[] = [];
  if (existsSync(reflogPath)) {
    const reflog = readFileSync(reflogPath, 'utf-8');
    const reflogEntries = parseGitReflog(reflog);
    const baseOffset = claudeEvents.length + shellEvents.length;
    const { events: reflogResult } = reflogToEvents(reflogEntries, {
      sessionId: sessionRoot,
      agentId: 'shell',
      monoOffset: baseOffset,
    });
    reflogEvents = reflogResult;
  }

  // 4. Pre-execution capture records (active capture).
  // Scoped to this session. The store is machine-wide and long-lived, so
  // an unscoped read merges every project the user has touched into an
  // evidence bundle. Records that cannot be attributed are counted, not
  // dropped silently and not included on a guess.
  const sessionEnd = claudeEvents[claudeEvents.length - 1]?.wallTs;
  const captureResult = normalizeCaptureRecords(captureDir, {
    sessionId: sessionRoot,
    agentId,
    monoOffset: claudeEvents.length + shellEvents.length + reflogEvents.length,
    scope: {
      agentSessionId,
      startsAt: sessionStart,
      endsAt: sessionEnd ?? sessionStart,
      includeUnattributed: includeUnscopedCaptures === true,
    },
  });
  warnings.push(...captureResult.warnings);

  const excludedTotal = Object.values(captureResult.excluded).reduce((a, b) => a + b, 0);
  if (excludedTotal > 0) {
    warnings.push(
      `${excludedTotal} of ${captureResult.storeRecordCount} capture record(s) were not ` +
        `attributable to this session and were excluded: ` +
        Object.entries(captureResult.excluded)
          .filter(([, n]) => n > 0)
          .map(([reason, n]) => `${n} ${reason}`)
          .join(', ') +
        `. Pass --include-unscoped-captures to merge unattributed records anyway.`
    );
  }

  // 5. Merge all sources into a single ordered timeline.
  const {
    events: merged,
    warnings: mergeWarnings,
    gapCount,
    linkedCount,
  } = mergeEvents(
    {
      claudeCodeEvents: claudeEvents,
      shellHistoryEvents: shellEvents,
      reflogEvents,
      captureEvents: captureResult.events,
    },
    { sessionId: sessionRoot, agentId }
  );
  warnings.push(...mergeWarnings);

  return {
    events: merged,
    warnings,
    gapCount,
    linkedCount,
    captureRecordCount: captureResult.recordCount,
    captureStoreRecordCount: captureResult.storeRecordCount,
    captureExcluded: captureResult.excluded,
  };
}

/**
 * Construct a synthetic shell_command_pre event from a parsed
 * shell-history line. Shared with reconstruct/package because both
 * commands need to splice these into the Claude timeline.
 */
export function createShellCommandEvent(
  cmd: {
    timestamp: string | null;
    command: string;
    argv: string[];
    cwd: string | null;
    exitCode: number | null;
    durationMs: number | null;
  },
  sessionId: string,
  monoNs: number,
  wallTs: string
): Event {
  const id = ulidFromTime(new Date(wallTs).getTime());
  const prePayload: ShellCommandPrePayload = {
    argv: cmd.argv,
    cwd: cmd.cwd || '',
    envHash: '',
    envSubset: {},
    ttyId: null,
    user: '',
    hostname: '',
    parentProcessTree: [],
    fileArgs: [],
    source: 'reconstructed',
    captureSchemaVersion: 2,
    // Rebuilt from a shell-history line, so the time is the history
    // entry's own timestamp, not an observation made at capture time.
    capturedAt: wallTs,
    capturedAtSource: 'reconstructed',
    sessionId,
  };
  const preHash = sha256(prePayload);
  return {
    id,
    wallTs,
    monoNs: BigInt(monoNs),
    sessionId,
    agentId: 'shell',
    parentEventId: null,
    type: 'shell_command_pre',
    payload: prePayload,
    payloadHash: preHash,
  };
}
