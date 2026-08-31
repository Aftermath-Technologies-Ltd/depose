// packages/cli/src/commands/captures.ts
//
// `depose captures` subcommands: inspect and prune the local capture store.
//
// The store is append-only and machine-wide. Nothing ever removed records,
// so a developer running the hook for three months accumulated 9,391 files
// and 38MB in one flat directory. There was no way to see that, and no
// supported way to trim it.
//
// Pruning deletes forensic records, so it is explicit by construction:
// `--older-than` is required, the default is a dry run, and `--yes` is
// needed to actually unlink anything. Automatic expiry is deliberately not
// offered. Silently destroying capture data is the wrong default for a
// tool whose product is being able to prove what happened.

import { readdirSync, statSync, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { DEFAULT_CAPTURE_DIR } from '@depose/core';

export interface CapturesCommandArgs {
  'capture-dir'?: string;
  /** Retention window, e.g. "90d", "12h", "30m". Required for prune. */
  'older-than'?: string;
  /** Actually delete. Without it, prune reports what it would remove. */
  yes?: boolean;
  [key: string]: string | boolean | string[] | undefined;
}

/**
 * Warn when the capture store has grown past the point where it is a
 * liability rather than a resource. Called by the bundle-producing
 * commands so the growth is visible during normal use.
 */
export const CAPTURE_STORE_WARN_RECORDS = 5_000;

/** Warn above this many bytes in the capture store. */
export const CAPTURE_STORE_WARN_BYTES = 25 * 1024 * 1024;

interface StoreStats {
  records: number;
  bytes: number;
  oldest: Date | null;
  newest: Date | null;
}

function resolveCaptureDir(args: CapturesCommandArgs): string {
  return (
    (args['capture-dir'] as string | undefined) ||
    process.env.DEPOSE_CAPTURE_DIR ||
    DEFAULT_CAPTURE_DIR
  );
}

/**
 * Parse a retention window like "90d", "12h", "30m", "45s" into milliseconds.
 *
 * @param value - Duration string: an integer followed by s, m, h, or d.
 * @returns The duration in milliseconds.
 * @throws If the string is not a supported duration.
 */
export function parseDuration(value: string): number {
  const match = /^(\d+)([smhd])$/.exec(value.trim());
  if (!match) {
    throw new Error(
      `Invalid duration ${JSON.stringify(value)}. ` +
        `Use an integer followed by s, m, h, or d (for example: 90d, 12h, 30m).`
    );
  }
  const amount = Number(match[1]);
  const unitMs: Record<string, number> = {
    s: 1000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
  };
  return amount * unitMs[match[2]!]!;
}

/**
 * Measure a capture store: record count, bytes on disk, and age range.
 *
 * @param dir - Capture directory to inspect.
 * @returns Counts and timestamps; zeroed when the directory does not exist.
 */
export function statCaptureStore(dir: string): StoreStats {
  const stats: StoreStats = { records: 0, bytes: 0, oldest: null, newest: null };
  if (!existsSync(dir)) return stats;

  for (const file of readdirSync(dir)) {
    if (!file.endsWith('.json')) continue;
    let info;
    try {
      info = statSync(join(dir, file));
    } catch {
      continue;
    }
    stats.records++;
    stats.bytes += info.size;
    const mtime = new Date(info.mtimeMs);
    if (!stats.oldest || mtime < stats.oldest) stats.oldest = mtime;
    if (!stats.newest || mtime > stats.newest) stats.newest = mtime;
  }
  return stats;
}

/**
 * Build the growth warning for a capture store, or null when it is within
 * bounds. Returned rather than printed so callers decide where it goes.
 *
 * @param dir - Capture directory to inspect.
 * @returns A warning line, or null when the store is a reasonable size.
 */
export function captureStoreWarning(dir: string): string | null {
  const { records, bytes } = statCaptureStore(dir);
  if (records < CAPTURE_STORE_WARN_RECORDS && bytes < CAPTURE_STORE_WARN_BYTES) {
    return null;
  }
  return (
    `Capture store at ${dir} holds ${records} record(s) (${formatBytes(bytes)}). ` +
    `Nothing expires automatically. Run \`depose captures prune --older-than 90d\` ` +
    `to review what can be removed.`
  );
}

/**
 * Handle `depose captures list`: report the size and age of the store.
 *
 * @param args - Command arguments; honours --capture-dir.
 */
export function handleCapturesList(args: CapturesCommandArgs): void {
  const dir = resolveCaptureDir(args);
  const { records, bytes, oldest, newest } = statCaptureStore(dir);

  console.log(`Capture store: ${dir}`);
  console.log(`  Records: ${records}`);
  console.log(`  Size:    ${formatBytes(bytes)}`);
  console.log(`  Oldest:  ${oldest ? oldest.toISOString() : '(none)'}`);
  console.log(`  Newest:  ${newest ? newest.toISOString() : '(none)'}`);

  const warning = captureStoreWarning(dir);
  if (warning) {
    console.log('');
    console.log(`WARNING: ${warning}`);
  }
}

/**
 * Handle `depose captures prune --older-than <duration>`.
 *
 * Reports what would be removed and exits without deleting unless --yes is
 * passed. Records are matched on file mtime.
 *
 * @param args - Command arguments; --older-than is required.
 */
export function handleCapturesPrune(args: CapturesCommandArgs): void {
  const dir = resolveCaptureDir(args);
  const olderThan = args['older-than'] as string | undefined;

  if (!olderThan) {
    console.error('ERROR: --older-than <duration> is required.');
    console.error('');
    console.error('Pruning deletes capture records permanently, so the retention');
    console.error('window must be stated explicitly. Example:');
    console.error('  depose captures prune --older-than 90d');
    process.exit(1);
    return;
  }

  let windowMs: number;
  try {
    windowMs = parseDuration(olderThan);
  } catch (err) {
    console.error(`ERROR: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
    return;
  }

  if (!existsSync(dir)) {
    console.log(`Capture store ${dir} does not exist. Nothing to prune.`);
    return;
  }

  const cutoff = Date.now() - windowMs;
  const doomed: Array<{ path: string; size: number; mtime: Date }> = [];

  for (const file of readdirSync(dir)) {
    if (!file.endsWith('.json')) continue;
    const path = join(dir, file);
    let info;
    try {
      info = statSync(path);
    } catch {
      continue;
    }
    if (info.mtimeMs < cutoff) {
      doomed.push({ path, size: info.size, mtime: new Date(info.mtimeMs) });
    }
  }

  const bytes = doomed.reduce((total, record) => total + record.size, 0);

  if (doomed.length === 0) {
    console.log(`No capture records older than ${olderThan} in ${dir}.`);
    return;
  }

  if (!args.yes) {
    console.log(`Would remove ${doomed.length} record(s) (${formatBytes(bytes)}) from ${dir}`);
    console.log(`  Older than: ${olderThan} (before ${new Date(cutoff).toISOString()})`);
    console.log('');
    console.log('This is a dry run. Nothing was deleted.');
    console.log(`Re-run with --yes to remove them: depose captures prune --older-than ${olderThan} --yes`);
    return;
  }

  let removed = 0;
  for (const record of doomed) {
    try {
      unlinkSync(record.path);
      removed++;
    } catch (err) {
      console.error(
        `  WARN: could not remove ${record.path} ` +
          `(${err instanceof Error ? err.message : String(err)})`
      );
    }
  }

  console.log(`Removed ${removed} of ${doomed.length} record(s) (${formatBytes(bytes)}) from ${dir}`);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
