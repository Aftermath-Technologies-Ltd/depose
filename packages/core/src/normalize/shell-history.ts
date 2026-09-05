// packages/core/src/normalize/shell-history.ts
//
// Normalize shell history (bash, zsh, fish) into DEPOSE Event[].
//
// Shell history files contain one command per line (with optional
// timestamps from HISTTIMEFORMAT in bash, or similar mechanisms
// in zsh and fish).
//
// This normalizer emits shell_command_pre and shell_command_post
// events for each command found.
//
// See docs/bundle-format.md#event-schema.

import { parseFishHistory } from './shell-history-fish.js';
import { tokenize } from './shell-tokenize.js';

// ── Shell history line formats ──────────────────────────────────────

/**
 * Represents a single command from shell history.
 */
export interface ShellHistoryCommand {
  /** ISO 8601 timestamp (null if not available) */
  timestamp: string | null;
  /** The command as a single string (e.g., "terraform destroy -auto-approve") */
  command: string;
  /** Parsed argv (tokenized, respecting quotes) */
  argv: string[];
  /** Working directory (null if not available) */
  cwd: string | null;
  /** Exit code (null if not available) */
  exitCode: number | null;
  /** Duration in milliseconds (null if not available) */
  durationMs: number | null;
}

/**
 * Parser function: takes a shell history file content (string) and
 * returns an array of ShellHistoryCommand.
 */
export type ShellHistoryParser = (content: string) => ShellHistoryCommand[];

// ── Bash history parser ──────────────────────────────────────────────
//
// Bash history formats:
//
//   Without HISTTIMEFORMAT (plain commands):
//     ls -la
//     git push --force
//
//   With HISTTIMEFORMAT (timestamped):
//     1684417200  ls -la
//     1684417201  git push --force
//
//   With HISTTIMEFORMAT full (ISO):
//     2025-05-18 15:30:00  ls -la
//
//   With history file markers (zsh):
//     : 1684417200:0;ls -la
//
//   With fish history (~/.local/share/fish/fish_history):
//     - cmd: terraform destroy -auto-approve
//       when: 1747583400

/**
 * Parse bash/zsh history (plain or timestamped with epoch seconds).
 *
 * Supports:
 *   - Plain: "command\n"
 *   - Epoch timestamped: "1684417200  command\n"
 *   - Colon-prefixed (zsh): ": 1684417200:0;command\n"
 *   - HISTTIMEFORMAT comment lines: "#1684417200\ncommand\n", where the
 *     time is on its own line above the command it belongs to
 *
 * Compound commands separated by |, &&, ||, or ; produce one
 * ShellHistoryCommand per stage, each sharing the same timestamp.
 *
 * `cwd` is always null. History files record no working directory, and
 * filling it with the producer's own would put an unobserved value into
 * signed evidence.
 *
 * @param content - The history file contents.
 * @returns One entry per command stage, in file order.
 */
export function parseBashHistory(content: string): ShellHistoryCommand[] {
  const lines = content.split('\n').filter((l) => l.trim().length > 0);
  const commands: ShellHistoryCommand[] = [];
  let pendingTimestamp: string | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    let timestamp: string | null = pendingTimestamp;
    let commandStr = trimmed;
    pendingTimestamp = null;

    // A bare "#<epoch>" line is bash's HISTTIMEFORMAT marker for the
    // command on the next line, not a command of its own.
    const marker = trimmed.match(/^#(\d{9,11})$/);
    if (marker) {
      pendingTimestamp = new Date(Number(marker[1]) * 1000).toISOString();
      continue;
    }

    // Try zsh format: : EPOCH:SECONDS;command
    const zshMatch = trimmed.match(/^:\s*(\d+):\d+;(.+)$/);
    if (zshMatch) {
      timestamp = new Date(Number(zshMatch[1]) * 1000).toISOString();
      commandStr = zshMatch[2] ?? '';
    } else {
      // Try epoch timestamp: EPOCH command
      const epochMatch = trimmed.match(/^(\d{9,11})\s+(.+)$/);
      if (epochMatch) {
        const epochMs = Number(epochMatch[1]);
        // If it looks like milliseconds (13 digits), convert
        const tsMs = epochMs > 1e12 ? epochMs : epochMs * 1000;
        timestamp = new Date(tsMs).toISOString();
        commandStr = epochMatch[2] || '';
      }
    }

    // Tokenize into stages (pipe/and/or/semi separated)
    const stages = tokenize(commandStr);

    // Each stage becomes its own ShellHistoryCommand with the same timestamp
    for (const stageArgv of stages) {
      // Reconstruct the command string for this stage from its tokens
      const stageCommand = reconstructCommand(stageArgv);
      commands.push({
        timestamp,
        command: stageCommand,
        argv: stageArgv,
        cwd: null,
        exitCode: null,
        durationMs: null,
      });
    }
  }

  return commands;
}

/**
 * Reconstruct a command string from an argv array.
 * Uses simple space-join (not perfectly faithful to original quoting,
 * but sufficient for the command field).
 */
function reconstructCommand(argv: string[]): string {
  return argv.map((arg) => {
    // Quote args that contain spaces or special characters
    if (/[\s|&;$"'\\]/.test(arg)) {
      return `'${arg.replace(/'/g, "'\\''")}'`;
    }
    return arg;
  }).join(' ');
}

/**
 * Parse shell history content (auto-detects format).
 * Tries zsh format first, then epoch timestamp, then plain.
 */
export function parseShellHistory(content: string): ShellHistoryCommand[] {
  return looksLikeFishHistory(content) ? parseFishHistory(content) : parseBashHistory(content);
}

/**
 * Whether a history file is fish's format.
 *
 * A `- cmd:` line at the start of a line is the entry marker and appears
 * in no bash or zsh history, so one is enough to tell the two apart.
 *
 * @param content - The history file contents.
 * @returns True when the file is fish history.
 */
export function looksLikeFishHistory(content: string): boolean {
  return /^- cmd:/m.test(content);
}

export { parseFishHistory, unescapeFishValue } from './shell-history-fish.js';
export { tokenize } from './shell-tokenize.js';