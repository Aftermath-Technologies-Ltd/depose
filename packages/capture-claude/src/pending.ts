// packages/capture-claude/src/pending.ts
//
// The marker that carries an intent's event id from the PreToolUse hook to
// the PostToolUse hook. The two run as separate processes with nothing
// shared but the capture directory, so the id has to go through the disk.
//
// One file per in-flight call under <captureDir>/pending/, named by session
// and input hash. The post hook consumes it and deletes it. A marker left
// behind by a call whose post hook never ran is swept on the next write, so
// an interrupted session does not accumulate them forever.

import {
  writeFileSync,
  readFileSync,
  mkdirSync,
  chmodSync,
  existsSync,
  readdirSync,
  statSync,
  unlinkSync,
} from 'node:fs';
import { join } from 'node:path';
import { getCaptureDir } from './capture-record.js';

/** What the pre hook leaves for the post hook. */
export interface PendingIntent {
  /** Event id of the shell_command_pre record the pre hook wrote. */
  ulid: string;
  /** ISO 8601 time the intent was captured, used to compute duration. */
  capturedAt: string;
  /** Pre-execution hashes, copied into the effect so the pair reads on its own. */
  files: Array<{ path: string; preSha256: string | null; sizeBytes: number | null }>;
}

/** Markers older than this are swept; a tool call does not run for an hour. */
const PENDING_TTL_MS = 60 * 60 * 1000;

/**
 * Directory holding in-flight intent markers.
 *
 * @returns The path, created with 0700 if it did not exist.
 */
export function getPendingDir(): string {
  const dir = join(getCaptureDir(), 'pending');
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
    chmodSync(dir, 0o700);
  }
  return dir;
}

/**
 * Record an in-flight intent so the post hook can close it.
 *
 * Never throws: a lost marker costs the effect its recorded intent id, and
 * the merge can still correlate on inputHash. Failing the pre hook over it
 * would be worse.
 *
 * @param sessionId - Claude Code's session id, or empty when unknown.
 * @param inputHash - canonicalInputHash of the call.
 * @param intent - The intent's id, capture time, and pre-state file hashes.
 */
export function writePendingIntent(
  sessionId: string,
  inputHash: string,
  intent: PendingIntent
): void {
  try {
    const dir = getPendingDir();
    sweep(dir);
    const path = join(dir, markerName(sessionId, inputHash));
    writeFileSync(path, JSON.stringify(intent), 'utf-8');
    chmodSync(path, 0o600);
  } catch {
    // The effect falls back to inputHash correlation.
  }
}

/**
 * Take the marker for a call, if one is there.
 *
 * @param sessionId - Claude Code's session id, or empty when unknown.
 * @param inputHash - canonicalInputHash of the call.
 * @returns The intent the pre hook recorded, or null.
 */
export function takePendingIntent(sessionId: string, inputHash: string): PendingIntent | null {
  let path: string;
  try {
    path = join(getPendingDir(), markerName(sessionId, inputHash));
    if (!existsSync(path)) return null;
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return null;
  } finally {
    try {
      unlinkSync(path);
    } catch {
      // Sweeping picks it up later.
    }
  }
  if (typeof parsed !== 'object' || parsed === null) return null;
  const marker = parsed as Partial<PendingIntent>;
  if (typeof marker.ulid !== 'string' || typeof marker.capturedAt !== 'string') return null;
  return {
    ulid: marker.ulid,
    capturedAt: marker.capturedAt,
    files: Array.isArray(marker.files) ? marker.files : [],
  };
}

/** Session ids come from another process, so nothing but the safe set survives. */
function markerName(sessionId: string, inputHash: string): string {
  const safe = (sessionId || 'no-session').replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
  return `${safe}.${inputHash}.json`;
}

function sweep(dir: string): void {
  const cutoff = Date.now() - PENDING_TTL_MS;
  for (const file of readdirSync(dir)) {
    const path = join(dir, file);
    try {
      if (statSync(path).mtimeMs < cutoff) unlinkSync(path);
    } catch {
      // Another hook process may have taken it first.
    }
  }
}
