// packages/core/src/normalize/capture.ts
//
// Normalizer for pre-execution capture records from $DEPOSE_CAPTURE_DIR.
// Reads ShellCommandPrePayload JSON files and converts them to Event objects.
//
// BUILD_PLAN.md §6 (Phase 3): "Each capture record matches to a tool
// result via (cwd, argv, wallTs ± 5s) and links via event.correlation.linkedShellCommandPreId."
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

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type {
  Event,
  ShellCommandPrePayload,
  AgentId,
} from '../events/schema.js';
import { generateUlid, isValidUlid } from '../events/ids.js';
import { sha256 } from '../events/canonical-json.js';

// ── Capture record normalizer ────────────────────────────────────────

/**
 * Why a capture record was left out of the bundle.
 */
export type CaptureExclusionReason =
  /** Record belongs to a different agent session. */
  | 'other-session'
  /** Record has no session id and could not be attributed to this session. */
  | 'unattributed'
  /** Record fell outside the session's time bounds. */
  | 'outside-session-window'
  /** Record was unreadable or structurally invalid. */
  | 'malformed';

/**
 * Session the bundle is being built for. Captures that cannot be tied to
 * it are excluded and counted rather than merged in.
 */
export interface CaptureScope {
  /** Agent session id taken from the session JSONL. */
  agentSessionId: string | null;
  /** ISO 8601 start of the session, inclusive of a grace margin. */
  startsAt?: string;
  /** ISO 8601 end of the session, inclusive of a grace margin. */
  endsAt?: string;
  /**
   * Include records that carry no session id when they fall inside the
   * session window. Off by default: an inferred association is not the
   * same as a recorded one, and this data ends up in signed evidence.
   */
  includeUnattributed?: boolean;
}

/**
 * Options for capture record normalization.
 */
export interface CaptureNormalizeOptions {
  /** Session ID to assign to capture events (default: generated ULID) */
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
  /** Normalized shell_command_pre events, scoped to the session */
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
 * Default capture directory.
 */
export const DEFAULT_CAPTURE_DIR = join(homedir(), '.depose', 'captures');

/** Grace margin applied to session bounds when matching captures, in ms. */
const SESSION_WINDOW_MARGIN_MS = 60_000;

/**
 * Normalize capture records from $DEPOSE_CAPTURE_DIR into Events.
 *
 * Reads capture record JSONs from the capture directory, keeps the ones
 * attributable to `options.scope`, and converts those to
 * `shell_command_pre` Events timestamped with their real capture time.
 * Records that belong to another session, or that cannot be attributed at
 * all, are counted in `excluded` rather than merged in, so the caller can
 * disclose them instead of either hiding or including them.
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
      // Tie-breaker only. Real ordering now comes from wallTs; this just
      // keeps same-millisecond captures stable, and files are read in ULID
      // order, which is capture order. Deriving nanoseconds from the
      // millisecond timestamp would exceed Number.MAX_SAFE_INTEGER and
      // silently lose precision, so the counter stays.
      monoNs: monoOffset + recordCount,
      sessionId,
      agentId: payload.source === 'shell-shim' ? 'shell' : agentId,
      parentEventId: null,
      type: 'shell_command_pre',
      payload,
      payloadHash: sha256(payload),
    });
    recordCount++;
  }

  return { events, recordCount, storeRecordCount, excluded, warnings };
}

// ── Internal ─────────────────────────────────────────────────────────

/**
 * Bring a record read from disk up to the v2 shape; or return null if it
 * is not a usable capture record.
 *
 * v1 records carry no capture time. Their filenames cannot supply one
 * either: generateUlid() randomized the timestamp prefix, so existing
 * capture ULIDs decode to times between 1970 and the year 10888. The
 * file's mtime is the only real signal left, and it is marked as derived
 * so a reconstructed time is never mistaken for a recorded one.
 */
function upgradeRecord(
  raw: unknown,
  mtimeMs: number
): ShellCommandPrePayload | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const record = raw as Partial<ShellCommandPrePayload>;
  if (!record.argv || !Array.isArray(record.argv)) return null;

  const recordedAt = typeof record.capturedAt === 'string' ? record.capturedAt : null;
  const usable = recordedAt !== null && !Number.isNaN(Date.parse(recordedAt));

  return {
    ...(record as ShellCommandPrePayload),
    capturedAt: usable ? recordedAt : new Date(mtimeMs).toISOString(),
    capturedAtSource: usable ? 'recorded' : 'derived-from-mtime',
    sessionId: typeof record.sessionId === 'string' ? record.sessionId : null,
  };
}

/** Resolve the scope's time bounds to epoch ms, if it declares any. */
function resolveWindow(scope?: CaptureScope): { start: number; end: number } | null {
  if (!scope?.startsAt || !scope.endsAt) return null;
  const start = Date.parse(scope.startsAt);
  const end = Date.parse(scope.endsAt);
  if (Number.isNaN(start) || Number.isNaN(end)) return null;
  return {
    start: start - SESSION_WINDOW_MARGIN_MS,
    end: end + SESSION_WINDOW_MARGIN_MS,
  };
}

/**
 * Decide whether a record belongs in this bundle. Session id is the only
 * recorded attribution; the time window is a secondary filter for records
 * the caller has explicitly opted to include without one.
 */
function classify(
  payload: ShellCommandPrePayload,
  scope: CaptureScope | undefined,
  bounds: { start: number; end: number } | null
): 'include' | CaptureExclusionReason {
  if (!scope) return 'include';

  if (payload.sessionId !== null && scope.agentSessionId !== null) {
    return payload.sessionId === scope.agentSessionId ? 'include' : 'other-session';
  }

  if (payload.sessionId !== null && scope.agentSessionId === null) {
    // The record knows its session but the bundle does not, so nothing can
    // be matched against anything.
    return scope.includeUnattributed ? 'include' : 'unattributed';
  }

  if (!scope.includeUnattributed) return 'unattributed';

  if (bounds) {
    const capturedMs = Date.parse(payload.capturedAt);
    if (Number.isNaN(capturedMs) || capturedMs < bounds.start || capturedMs > bounds.end) {
      return 'outside-session-window';
    }
  }

  return 'include';
}
