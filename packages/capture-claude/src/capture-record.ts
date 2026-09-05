// packages/capture-claude/src/capture-record.ts
//
// Writes capture records (ShellCommandPrePayload JSON) to $DEPOSE_CAPTURE_DIR.
// Each record is written as a separate file named by ULID.
//
// The hook writes a ShellCommandPrePayload JSON to $DEPOSE_CAPTURE_DIR/<ulid>.json.

import { writeFileSync, mkdirSync, chmodSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { ShellCommandPrePayload } from '@depose/core';

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
 * Read all capture records from $DEPOSE_CAPTURE_DIR.
 * Returns parsed ShellCommandPrePayload objects sorted by filename (ULID).
 */
export function readCaptureRecords(): Array<{
  ulid: string;
  path: string;
  payload: ShellCommandPrePayload;
}> {
  const dir = getCaptureDir();
  if (!existsSync(dir)) return [];

  const files = readdirSync(dir)
    .filter((f: string) => f.endsWith('.json'))
    .sort();

  const records: Array<{ ulid: string; path: string; payload: ShellCommandPrePayload }> = [];
  for (const file of files) {
    const filePath = join(dir, file);
    try {
      const content = readFileSync(filePath, 'utf-8');
      const payload = JSON.parse(content) as ShellCommandPrePayload;
      records.push({
        ulid: file.replace('.json', ''),
        path: filePath,
        payload,
      });
    } catch {
      // Skip malformed records
    }
  }
  return records;
}