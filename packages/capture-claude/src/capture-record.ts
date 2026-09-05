// packages/capture-claude/src/capture-record.ts
//
// Writes capture records (ShellCommandPrePayload JSON) to $DEPOSE_CAPTURE_DIR.
// Each record is written as a separate file named by ULID.
//
// The hook writes a ShellCommandPrePayload JSON to $DEPOSE_CAPTURE_DIR/<ulid>.json.

import { writeFileSync, mkdirSync, chmodSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { ShellCommandPrePayload, ToolCallEffectPayload } from '@depose/core';

/**
 * The shapes the capture store holds. `command` is the pre-execution
 * record, which predates the `kind` discriminator and so carries none.
 */
export type CaptureRecordKind = 'command' | 'effect' | 'execve' | 'capture_failed';

/**
 * Default capture directory path.
 * Override with $DEPOSE_CAPTURE_DIR.
 */
export const DEFAULT_CAPTURE_DIR = join(homedir(), '.depose', 'captures');

/**
 * Get the active capture directory (from env or default).
 * Creates it with 0700 permissions if it doesn't exist.
 */
export function getCaptureDir(): string {
  const dir = process.env.DEPOSE_CAPTURE_DIR || DEFAULT_CAPTURE_DIR;
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
    chmodSync(dir, 0o700);
  }
  return dir;
}

/**
 * Write a capture record to $DEPOSE_CAPTURE_DIR/<ulid>.json.
 *
 * The file is written with 0600 permissions (docs/threat-model.md §3.1).
 *
 * @param ulid - ULID for this capture record (used as filename)
 * @param payload - The ShellCommandPrePayload to write
 * @returns The path where the record was written
 */
export function writeCaptureRecord(
  ulid: string,
  payload: ShellCommandPrePayload
): string {
  const dir = getCaptureDir();
  const path = join(dir, `${ulid}.json`);
  const json = JSON.stringify(payload, null, 2);
  writeFileSync(path, json, 'utf-8');
  chmodSync(path, 0o600);
  return path;
}

/**
 * Write an effect record to $DEPOSE_CAPTURE_DIR/<ulid>.json.
 *
 * Same store and same permissions as the intent half; the reader tells the
 * two apart by the record's `kind`.
 *
 * @param ulid - ULID for this effect record (used as filename).
 * @param payload - The ToolCallEffectPayload to write.
 * @returns The path where the record was written.
 */
export function writeEffectRecord(ulid: string, payload: ToolCallEffectPayload): string {
  const dir = getCaptureDir();
  const path = join(dir, `${ulid}.json`);
  writeFileSync(path, JSON.stringify(payload, null, 2), 'utf-8');
  chmodSync(path, 0o600);
  return path;
}

/** One record read back out of the capture store. */
export interface StoredCaptureRecord {
  ulid: string;
  path: string;
  /**
   * The record as it was written. The store holds four shapes (see
   * CaptureRecordKind), so this is `unknown` rather than one of them:
   * typing every record as a command record was true when there was only
   * one kind and became a lie the moment the post hook and the kernel
   * collector started writing into the same directory. Narrow it with
   * `recordKind` and the readers in packages/core.
   */
  payload: unknown;
}

/**
 * Which of the store's four shapes a record is, decided the way the
 * normalizer decides it: by the `kind` discriminator, with a command
 * record being the one shape that predates the field and so carries none.
 *
 * @param payload - A parsed record.
 * @returns The kind, or null when the object is none of them.
 */
export function recordKind(payload: unknown): CaptureRecordKind | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const kind = (payload as { kind?: unknown }).kind;
  if (kind === 'capture_failed' || kind === 'effect' || kind === 'execve') {
    return kind;
  }
  if (Array.isArray((payload as { argv?: unknown }).argv)) return 'command';
  return null;
}

/**
 * Read all capture records from $DEPOSE_CAPTURE_DIR, sorted by filename
 * (ULID), which is capture order.
 *
 * Payloads come back as `unknown` because the store holds four shapes;
 * use `readCommandRecords` when you want the pre-execution ones, or
 * narrow with `recordKind`.
 *
 * @returns Every parsed record, with malformed files skipped.
 */
export function readCaptureRecords(): StoredCaptureRecord[] {
  const dir = getCaptureDir();
  if (!existsSync(dir)) return [];

  const files = readdirSync(dir)
    .filter((f: string) => f.endsWith('.json'))
    .sort();

  const records: StoredCaptureRecord[] = [];
  for (const file of files) {
    const filePath = join(dir, file);
    try {
      const content = readFileSync(filePath, 'utf-8');
      records.push({
        ulid: file.replace('.json', ''),
        payload: JSON.parse(content) as unknown,
        path: filePath,
      });
    } catch {
      // Skip malformed records
    }
  }
  return records;
}

/**
 * The pre-execution command records in the store, typed.
 *
 * This is the shape almost every caller wants, and giving it its own
 * reader is what lets `readCaptureRecords` be honest about the other
 * three: a single reader that claimed everything was a command record
 * was correct when that was the only kind and became wrong the moment
 * the post hook and the kernel collector started writing here.
 *
 * @returns The command records, in capture order.
 */
export function readCommandRecords(): Array<{
  ulid: string;
  path: string;
  payload: ShellCommandPrePayload;
}> {
  const out: Array<{ ulid: string; path: string; payload: ShellCommandPrePayload }> = [];
  for (const record of readCaptureRecords()) {
    if (recordKind(record.payload) === 'command') {
      out.push({ ulid: record.ulid, path: record.path, payload: record.payload as ShellCommandPrePayload });
    }
  }
  return out;
}
