// packages/core/src/normalize/capture.ts
//
// Normalizer for pre-execution capture records from $DEPOSE_CAPTURE_DIR.
// Reads ShellCommandPrePayload JSON files and converts them to Event objects.
//
// BUILD_PLAN.md §6 (Phase 3): "Each capture record matches to a tool
// result via (cwd, argv, wallTs ± 5s) and links via linkedShellCommandPreId."

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type {
  Event,
  ShellCommandPrePayload,
  AgentId,
} from '../events/schema.js';
import { generateUlid, ulidFromTime } from '../events/ids.js';
import { sha256 } from '../events/canonical-json.js';

// ── Capture record normalizer ────────────────────────────────────────

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
  /** Clock function for wallTs (defaults to Date.now) */
  clock?: () => number;
}

/**
 * Result of capture record normalization.
 */
export interface CaptureNormalizeResult {
  /** Normalized shell_command_pre events */
  events: Event[];
  /** Number of capture records processed */
  recordCount: number;
  /** Warnings about processing issues */
  warnings: string[];
}

/**
 * Default capture directory.
 */
export const DEFAULT_CAPTURE_DIR = join(homedir(), '.depose', 'captures');

/**
 * Normalize capture records from $DEPOSE_CAPTURE_DIR into Events.
 *
 * Reads all JSON files from the capture directory, parses them as
 * ShellCommandPrePayload, and creates shell_command_pre Events.
 *
 * @param captureDir - Directory containing capture record JSONs.
 *                        Falls back to $DEPOSE_CAPTURE_DIR or default.
 * @param options - Normalization options.
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
    clock = Date.now,
  } = options;

  const events: Event[] = [];
  const warnings: string[] = [];
  let recordCount = 0;

  if (!existsSync(dir)) {
    return { events, recordCount, warnings };
  }

  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f: string) => f.endsWith('.json'))
      .sort();
  } catch {
    warnings.push(`Cannot read capture directory: ${dir}`);
    return { events, recordCount, warnings };
  }

  for (const file of files) {
    const filePath = join(dir, file);
    try {
      const content = readFileSync(filePath, 'utf-8');
      const payload = JSON.parse(content) as ShellCommandPrePayload;

      // Validate minimum required fields
      if (!payload.argv || !Array.isArray(payload.argv)) {
        warnings.push(`Capture record ${file}: missing or invalid argv`);
        continue;
      }

      const ulid = file.replace('.json', '');
      const wallTs = new Date(clock()).toISOString();
      const monoNs = monoOffset + recordCount;

      const event: Event = {
        id: ulid || generateUlid(),
        wallTs,
        monoNs,
        sessionId,
        agentId: payload.source === 'shell-shim' ? 'shell' : agentId,
        parentEventId: null,
        type: 'shell_command_pre',
        payload,
        payloadHash: sha256(payload),
      };

      events.push(event);
      recordCount++;
    } catch (err) {
      warnings.push(
        `Capture record ${file}: parse error (${err instanceof Error ? err.message : String(err)})`
      );
    }
  }

  return { events, recordCount, warnings };
}