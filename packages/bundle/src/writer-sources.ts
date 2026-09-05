// packages/bundle/src/writer-sources.ts
//
// Copying source material into raw/: the session JSONL and its sibling
// shell-history and reflog files, and the capture records behind the
// capture events that entered the timeline.

import { mkdirSync, copyFileSync, existsSync } from 'node:fs';
import { join, basename, dirname } from 'node:path';
import type { Event, GapPayload, ShellCommandPrePayload } from '@depose/core';

/**
 * Copy the session JSONL and any sibling shell-history.txt / git-reflog.txt
 * into raw/. Empty directories are never created.
 *
 * @param rawDir - Absolute path of the bundle's raw/ directory.
 * @param sourceJsonlPath - The session JSONL the bundle was built from.
 */
export function copyRawSources(rawDir: string, sourceJsonlPath: string): void {
  const rawClaudeDir = join(rawDir, 'claude-code');
  mkdirSync(rawClaudeDir, { recursive: true });
  copyFileSync(sourceJsonlPath, join(rawClaudeDir, basename(sourceJsonlPath)));

  const srcDir = dirname(sourceJsonlPath);
  const shellHistoryPath = join(srcDir, 'shell-history.txt');
  if (existsSync(shellHistoryPath)) {
    const rawShellDir = join(rawDir, 'shell-history');
    mkdirSync(rawShellDir, { recursive: true });
    copyFileSync(shellHistoryPath, join(rawShellDir, 'shell-history.txt'));
  }

  const reflogPath = join(srcDir, 'git-reflog.txt');
  if (existsSync(reflogPath)) {
    copyFileSync(reflogPath, join(rawDir, 'git-reflog.txt'));
  }
}

/**
 * Copy the capture records behind the capture-derived events in the
 * timeline into raw/captures/, by event id. Copying by id rather than by
 * directory sweep keeps the session scoping intact: nothing unrelated to
 * the session reaches the bundle.
 *
 * Two event kinds qualify: shell_command_pre events whose capture was
 * recorded (not reconstructed), and gap events with reason capture_failed,
 * whose id is the failure record's ULID.
 *
 * @param rawDir - Absolute path of the bundle's raw/ directory.
 * @param captureSourceDir - The capture store the events came from.
 * @param events - The chained events in the bundle.
 * @returns Warnings for records that could not be copied.
 */
export function copyCaptureRecords(
  rawDir: string,
  captureSourceDir: string,
  events: Event[]
): string[] {
  const warnings: string[] = [];
  if (!existsSync(captureSourceDir)) return warnings;

  const attributed = events.filter(isCaptureDerived);
  if (attributed.length === 0) return warnings;

  const rawCaptureDir = join(rawDir, 'captures');
  let created = false;
  for (const event of attributed) {
    const srcFile = join(captureSourceDir, `${event.id}.json`);
    if (!existsSync(srcFile)) continue;
    if (!created) {
      mkdirSync(rawCaptureDir, { recursive: true });
      created = true;
    }
    try {
      copyFileSync(srcFile, join(rawCaptureDir, `${event.id}.json`));
    } catch (err) {
      warnings.push(
        `Could not copy capture record ${event.id} into raw/captures/ ` +
          `(${err instanceof Error ? err.message : String(err)}). The event ` +
          `remains in the timeline but its source record is not in the bundle.`
      );
    }
  }
  return warnings;
}

function isCaptureDerived(event: Event): boolean {
  if (event.type === 'shell_command_pre') {
    return (event.payload as ShellCommandPrePayload).capturedAtSource !== 'reconstructed';
  }
  if (event.type === 'gap') {
    return (event.payload as GapPayload).reason === 'capture_failed';
  }
  return false;
}
