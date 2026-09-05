// packages/core/src/normalize/capture-scope.ts
//
// Session scoping for capture-store records: which records belong to the
// bundle being built, and how a record read from disk is brought up to
// the current shape. The reader loop lives in capture.ts.

import type { ShellCommandPrePayload, CaptureFailedPayload } from '../events/schema.js';

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

/** Epoch-ms bounds resolved from a scope. */
export interface ScopeBounds {
  start: number;
  end: number;
}

/** Grace margin applied to session bounds when matching captures, in ms. */
const SESSION_WINDOW_MARGIN_MS = 60_000;

/**
 * Bring a command record read from disk up to the v2 shape; or return
 * null if it is not a usable capture record.
 *
 * v1 records carry no capture time. Their filenames cannot supply one
 * either: generateUlid() used to randomize the timestamp prefix, so old
 * capture ULIDs decode to times between 1970 and the year 10888. The
 * file's mtime is the only real signal left, and it is marked as derived
 * so a reconstructed time is never mistaken for a recorded one.
 *
 * @param raw - Parsed JSON from the record file.
 * @param mtimeMs - The record file's mtime, used for v1 records.
 * @returns The v2 payload, or null when the object is not a command record.
 */
export function upgradeRecord(raw: unknown, mtimeMs: number): ShellCommandPrePayload | null {
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

/**
 * Validate a capture_failed record read from the store.
 *
 * @param raw - Parsed JSON from a record file or a sidecar line.
 * @returns The payload, or null when the object is not a capture_failed record.
 */
export function readCaptureFailed(raw: unknown): CaptureFailedPayload | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const record = raw as Partial<CaptureFailedPayload>;
  if (record.kind !== 'capture_failed') return null;
  if (typeof record.phase !== 'string' || typeof record.errorClass !== 'string') return null;
  if (typeof record.message !== 'string' || typeof record.capturedAt !== 'string') return null;
  if (Number.isNaN(Date.parse(record.capturedAt))) return null;
  return {
    kind: 'capture_failed',
    phase: record.phase,
    errorClass: record.errorClass,
    message: record.message,
    monoNs: typeof record.monoNs === 'string' ? record.monoNs : '0',
    capturedAt: record.capturedAt,
    sessionId: typeof record.sessionId === 'string' ? record.sessionId : null,
    toolName: typeof record.toolName === 'string' ? record.toolName : null,
    source: 'claude-pretooluse',
    captureSchemaVersion: 3,
  };
}

/**
 * Resolve the scope's time bounds to epoch ms, if it declares any.
 *
 * @param scope - The session scope.
 * @returns Bounds widened by the grace margin, or null when undeclared.
 */
export function resolveWindow(scope?: CaptureScope): ScopeBounds | null {
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
 *
 * @param record - The record's session id and capture time.
 * @param scope - The session scope, or undefined to include everything.
 * @param bounds - Resolved time bounds, or null when the scope has none.
 * @returns 'include' or the exclusion reason.
 */
export function classify(
  record: { sessionId: string | null; capturedAt: string },
  scope: CaptureScope | undefined,
  bounds: ScopeBounds | null
): 'include' | CaptureExclusionReason {
  if (!scope) return 'include';

  if (record.sessionId !== null && scope.agentSessionId !== null) {
    return record.sessionId === scope.agentSessionId ? 'include' : 'other-session';
  }

  if (record.sessionId !== null && scope.agentSessionId === null) {
    // The record knows its session but the bundle does not, so nothing can
    // be matched against anything.
    return scope.includeUnattributed ? 'include' : 'unattributed';
  }

  if (!scope.includeUnattributed) return 'unattributed';

  if (bounds) {
    const capturedMs = Date.parse(record.capturedAt);
    if (Number.isNaN(capturedMs) || capturedMs < bounds.start || capturedMs > bounds.end) {
      return 'outside-session-window';
    }
  }

  return 'include';
}
