// packages/core/src/normalize/capture.ts
//
// Normalizer for pre-execution capture records from $DEPOSE_CAPTURE_DIR.
// Reads the hook's and shim's JSON records and converts them to Events.
//
// Two rules this module exists to enforce:
//
//   1. An event carries the time its command was captured, never the time
//      the bundle was produced. The ± 5s match window in mergeEvents makes
//      a production-time stamp equivalent to no timestamp at all.
//   2. A bundle contains the session it was asked to reconstruct and
//      nothing else. The capture store is machine-wide and long-lived, so
//      reading it unfiltered puts every project the user has touched into
//      an evidence bundle destined for disclosure.
//
// Two record kinds live in the store: command records (shell_command_pre)
// and capture_failed records, which the hook writes when it could not
// capture. Both are scoped the same way. Scoping lives in capture-scope.ts.

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { Event, AgentId, CaptureFailedPayload } from '../events/schema.js';
import { generateUlid, isValidUlid } from '../events/ids.js';
import { sha256 } from '../events/canonical-json.js';
import {
  upgradeRecord,
  resolveWindow,
  classify,
  readCaptureFailed,
  type CaptureExclusionReason,
  type CaptureScope,
} from './capture-scope.js';

export type { CaptureExclusionReason, CaptureScope } from './capture-scope.js';

/** Sidecar the hook appends to when it cannot write a record file. */
export const CAPTURE_FAILED_SIDECAR = 'capture-failed.log';

/**
 * Default capture directory.
 */
export const DEFAULT_CAPTURE_DIR = join(homedir(), '.depose', 'captures');

/**
 * Options for capture record normalization.
 */
export interface CaptureNormalizeOptions {
  /** Session ID (ULID) to assign to capture events (default: generated ULID) */
  sessionId?: string;
  /** Agent ID (default: 'claude-code') */
  agentId?: AgentId;
  /** Monotonic nanosecond offset for capture events */
  monoOffset?: number;
  /** Clock function, retained for tests. Never used for event times. */
  clock?: () => number;
  /**
   * Scope filter. Omit to read the whole store, which is only correct for
   * callers that have already narrowed the directory themselves.
   */
  scope?: CaptureScope;
}

/**
 * Result of capture record normalization.
 */
export interface CaptureNormalizeResult {
  /** Normalized events (shell_command_pre and capture_failed), scoped to the session */
  events: Event[];
  /** Number of capture records that became events */
  recordCount: number;
  /** Number of records read from the store, before scoping */
  storeRecordCount: number;
  /** Records deliberately left out, by reason */
  excluded: Record<CaptureExclusionReason, number>;
  /** Warnings about processing issues */
  warnings: string[];
}

/**
 * Normalize capture records from $DEPOSE_CAPTURE_DIR into Events.
 *
 * Reads capture record JSONs from the capture directory, keeps the ones
 * attributable to `options.scope`, and converts those to
 * `shell_command_pre` Events timestamped with their real capture time.
 * capture_failed records become `capture_failed` Events, which the merger
 * turns into gap events. Records that belong to another session, or that
 * cannot be attributed at all, are counted in `excluded` rather than merged
 * in, so the caller can disclose them instead of either hiding or including
 * them.
 *
 * v1 records (which predate `capturedAt` and `sessionId`) are upgraded on
 * read: the capture time falls back to the record file's mtime and is
 * marked `derived-from-mtime`.
 *
 * @param captureDir - Directory containing capture record JSONs.
 *                        Falls back to $DEPOSE_CAPTURE_DIR or default.
 * @param options - Normalization options, including the session scope.
 * @returns Scoped events plus the counts needed to disclose what was left out.
 */
export function normalizeCaptureRecords(
  captureDir?: string,
  options: CaptureNormalizeOptions = {}
): CaptureNormalizeResult {
  const dir = captureDir || process.env.DEPOSE_CAPTURE_DIR || DEFAULT_CAPTURE_DIR;
  const {
    sessionId = generateUlid(),
    agentId = 'claude-code',
    monoOffset = 0,
    scope,
  } = options;

  const events: Event[] = [];
  const warnings: string[] = [];
  const excluded: Record<CaptureExclusionReason, number> = {
    'other-session': 0,
    unattributed: 0,
    'outside-session-window': 0,
    malformed: 0,
  };
  let recordCount = 0;
  let storeRecordCount = 0;

  if (!existsSync(dir)) {
    return { events, recordCount, storeRecordCount, excluded, warnings };
  }

  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f: string) => f.endsWith('.json'))
      .sort();
  } catch {
    warnings.push(
      `Cannot read capture directory: ${dir}. Check it exists and is readable; ` +
        `pass --capture-dir to point at a different store.`
    );
    return { events, recordCount, storeRecordCount, excluded, warnings };
  }

  const bounds = resolveWindow(scope);

  for (const file of files) {
    storeRecordCount++;
    const filePath = join(dir, file);

    let raw: unknown;
    let mtimeMs: number;
    try {
      raw = JSON.parse(readFileSync(filePath, 'utf-8'));
      mtimeMs = statSync(filePath).mtimeMs;
    } catch (err) {
      excluded.malformed++;
      warnings.push(
        `Capture record ${file}: parse error (${err instanceof Error ? err.message : String(err)})`
      );
      continue;
    }

    const ulid = file.slice(0, -'.json'.length);
    if (!isValidUlid(ulid)) {
      excluded.malformed++;
      warnings.push(
        `Capture record ${file}: filename is not a valid ULID, so it cannot ` +
          `supply an event id. Remove it from the store.`
      );
      continue;
    }

    const failed = readCaptureFailed(raw);
    if (failed) {
      const decision = classify(failed, scope, bounds);
      if (decision !== 'include') {
        excluded[decision]++;
        continue;
      }
      events.push(captureFailedEvent(ulid, failed, sessionId, agentId, monoOffset + recordCount));
      recordCount++;
      continue;
    }

    const payload = upgradeRecord(raw, mtimeMs);
    if (!payload) {
      excluded.malformed++;
      warnings.push(`Capture record ${file}: missing or invalid argv`);
      continue;
    }

    const decision = classify(payload, scope, bounds);
    if (decision !== 'include') {
      excluded[decision]++;
      continue;
    }

    events.push({
      id: ulid,
      wallTs: payload.capturedAt,
      // Tie-breaker only. Real ordering comes from wallTs; this keeps
      // same-millisecond captures stable, and files are read in ULID order,
      // which is capture order.
      monoNs: BigInt(monoOffset + recordCount),
      sessionId,
      agentId: payload.source === 'shell-shim' ? 'shell' : agentId,
      parentEventId: null,
      type: 'shell_command_pre',
      payload,
      payloadHash: sha256(payload),
    });
    recordCount++;
  }

  // The sidecar holds failures the hook could not write as files. Each line
  // carries the ULID the hook would have used, so the event id is stable.
  const sidecarPath = join(dir, CAPTURE_FAILED_SIDECAR);
  if (existsSync(sidecarPath)) {
    for (const line of readFileSync(sidecarPath, 'utf-8').split('\n')) {
      if (line.trim().length === 0) continue;
      storeRecordCount++;
      let entry: { ulid?: unknown; payload?: unknown };
      try {
        entry = JSON.parse(line) as { ulid?: unknown; payload?: unknown };
      } catch {
        excluded.malformed++;
        warnings.push(`${CAPTURE_FAILED_SIDECAR}: unparseable line skipped`);
        continue;
      }
      const failed = readCaptureFailed(entry.payload);
      const ulid = typeof entry.ulid === 'string' && isValidUlid(entry.ulid) ? entry.ulid : null;
      if (!failed || !ulid) {
        excluded.malformed++;
        warnings.push(`${CAPTURE_FAILED_SIDECAR}: malformed entry skipped`);
        continue;
      }
      const decision = classify(failed, scope, bounds);
      if (decision !== 'include') {
        excluded[decision]++;
        continue;
      }
      events.push(captureFailedEvent(ulid, failed, sessionId, agentId, monoOffset + recordCount));
      recordCount++;
    }
  }

  return { events, recordCount, storeRecordCount, excluded, warnings };
}

function captureFailedEvent(
  id: string,
  payload: CaptureFailedPayload,
  sessionId: string,
  agentId: AgentId,
  monoNs: number
): Event {
  return {
    id,
    wallTs: payload.capturedAt,
    monoNs: BigInt(monoNs),
    sessionId,
    agentId,
    parentEventId: null,
    type: 'capture_failed',
    payload,
    payloadHash: sha256(payload),
  };
}
