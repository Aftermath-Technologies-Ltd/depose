// packages/capture-claude/src/capture-failed.ts
//
// When the hook throws, it must leave evidence before exiting 0. This
// module writes a capture_failed record to the capture store; if that
// write fails too, it appends a line to a sidecar file instead. Only if
// both fail does the failure go unrecorded, and the hook still exits 0
// because blocking the agent is never acceptable.

import { appendFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { generateUlid, CAPTURE_FAILED_SIDECAR } from '@depose/core';
import type { CaptureFailedPayload } from '@depose/core';
import { getCaptureDir } from './capture-record.js';

/** Phases of a hook run, named so a capture_failed record says where it died. */
export type HookPhase =
  | 'read-input'
  | 'parse-input'
  | 'env'
  | 'file-hash'
  | 'process-tree'
  | 'tty'
  | 'pending'
  | 'write-record';

/** What the hook knew when it failed. */
export interface HookFailure {
  phase: HookPhase;
  error: unknown;
  sessionId: string | null;
  toolName: string | null;
  /** Which half of the hook failed. Defaults to the pre-execution half. */
  source?: 'claude-pretooluse' | 'claude-posttooluse';
}

/** Where the failure record landed, or that it could not be recorded. */
export type CaptureFailedOutcome =
  | { written: 'record'; path: string; ulid: string }
  | { written: 'sidecar'; path: string; ulid: string }
  | { written: 'none'; ulid: string };

const MAX_MESSAGE_CHARS = 300;

/**
 * Reduce an error message to something safe to put in signed evidence:
 * first line only, control characters removed, the home directory
 * replaced with `~`, and capped in length.
 *
 * @param message - The raw error message.
 * @returns The sanitized message.
 */
export function sanitizeErrorMessage(message: string): string {
  const firstLine = message.split(/\r?\n/, 1)[0] ?? '';
  const printable = firstLine.replace(/[\x00-\x1f\x7f]/g, ' ');
  const home = homedir();
  const withoutHome = home ? printable.split(home).join('~') : printable;
  return withoutHome.length > MAX_MESSAGE_CHARS
    ? withoutHome.slice(0, MAX_MESSAGE_CHARS - 3) + '...'
    : withoutHome;
}

/**
 * Build the capture_failed payload for a hook failure.
 *
 * @param failure - The phase, error, and session context.
 * @param monoNs - process.hrtime.bigint() at the failure.
 * @returns The payload to record.
 */
export function buildCaptureFailedPayload(failure: HookFailure, monoNs: bigint): CaptureFailedPayload {
  const err = failure.error;
  const errorClass = err instanceof Error ? err.constructor.name || 'Error' : typeof err;
  const message = err instanceof Error ? err.message : String(err);
  return {
    kind: 'capture_failed',
    phase: failure.phase,
    errorClass,
    message: sanitizeErrorMessage(message),
    monoNs: monoNs.toString(),
    capturedAt: new Date().toISOString(),
    sessionId: failure.sessionId,
    toolName: failure.toolName,
    source: failure.source ?? 'claude-pretooluse',
    captureSchemaVersion: 3,
  };
}

/**
 * Record a hook failure in the capture store.
 *
 * Tries `<captureDir>/<ulid>.json` first. If that throws, appends one JSON
 * line `{ulid, payload}` to `<captureDir>/capture-failed.log`. Never
 * throws: the caller is on its way to exit 0 and must not be stopped.
 *
 * @param failure - The phase, error, and session context.
 * @returns Where the record landed.
 */
export function writeCaptureFailedRecord(failure: HookFailure): CaptureFailedOutcome {
  const ulid = generateUlid();
  const payload = buildCaptureFailedPayload(failure, process.hrtime.bigint());
  let dir: string;
  try {
    dir = getCaptureDir();
  } catch {
    return { written: 'none', ulid };
  }

  const recordPath = join(dir, `${ulid}.json`);
  try {
    writeFileSync(recordPath, JSON.stringify(payload, null, 2), 'utf-8');
    chmodSync(recordPath, 0o600);
    return { written: 'record', path: recordPath, ulid };
  } catch {
    // Fall through to the sidecar.
  }

  const sidecarPath = join(dir, CAPTURE_FAILED_SIDECAR);
  try {
    appendFileSync(sidecarPath, JSON.stringify({ ulid, payload }) + '\n', { mode: 0o600 });
    return { written: 'sidecar', path: sidecarPath, ulid };
  } catch {
    return { written: 'none', ulid };
  }
}
