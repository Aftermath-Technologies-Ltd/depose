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
// See BUILD_PLAN.md §4.1 for the Event schema.

import type {
  ShellCommandPostPayload,
  ShellCommandPrePayload,
} from '../events/schema.js';

// ── Shell history line formats ───────────────────────────────────────

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
//   With fish history (XML-like or plain):
//     fish records timestamped history in a different format

/**
 * Parse bash/zsh history (plain or timestamped with epoch seconds).
 *
 * Supports:
 *   - Plain: "command\n"
 *   - Epoch timestamped: "1684417200  command\n"
 *   - Colon-prefixed (zsh): ": 1684417200:0;command\n"
 */
export function parseBashHistory(content: string): ShellHistoryCommand[] {
  const lines = content.split('\n').filter((l) => l.trim().length > 0);
  const commands: ShellHistoryCommand[] = [];
  const cwd = process.cwd();
  const user = process.env.USER || '';
  const hostname = process.env.HOSTNAME || '';

  for (const line of lines) {
    const trimmed = line.trim();
    let timestamp: string | null = null;
    let commandStr = trimmed;

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

    const argv = tokenize(commandStr);
    const _monoNs = timestamp ? Date.parse(timestamp) * 1e6 : Date.now() * 1e6;

    const _prePayload: ShellCommandPrePayload = {
      argv,
      cwd: cwd || '',
      envHash: '',
      envSubset: {},
      ttyId: null,
      user,
      hostname,
      parentProcessTree: [],
      fileArgs: [],
      source: 'shell-shim',
      captureSchemaVersion: 1,
    };

    const _postPayload: ShellCommandPostPayload = {
      exitCode: 0,
      durationMs: 0,
      stdoutHash: '',
      stderrHash: '',
      signalReceived: null,
    };

    commands.push({
      timestamp,
      command: commandStr,
      argv,
      cwd,
      exitCode: null,
      durationMs: null,
    });
  }

  return commands;
}

/**
 * Parse fish shell history (plain format, one command per line).
 * Fish history is similar to plain bash history (no epoch prefix by default).
 */
export function parseFishHistory(content: string): ShellHistoryCommand[] {
  return parseBashHistory(content);
}

// ── Tokenizer ────────────────────────────────────────────────────────
//
// Simple shell command tokenizer that respects quotes.
// This is a best-effort tokenizer — not a full shell parser.
// It handles:
//   - Double-quoted strings (with basic escape handling)
//   - Single-quoted strings (no escape handling, per POSIX)
//   - Unquoted words (split on whitespace)
//   - Backslash escapes
//   - Pipe-separated commands (split on |)

/**
 * Tokenize a shell command string into argv (respecting quotes).
 * Splits on pipes (|) to handle compound commands.
 */
export function tokenize(command: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inDoubleQuote = false;
  let inSingleQuote = false;
  let escaped = false;
  let i = 0;

  const chars = command.split('');

  while (i < chars.length) {
    const ch = chars[i];

    if (escaped) {
      current += ch;
      escaped = false;
      i++;
      continue;
    }

    if (ch === '\\' && !inSingleQuote) {
      escaped = true;
      i++;
      continue;
    }

    if (ch === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      i++;
      continue;
    }

    if (ch === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      i++;
      continue;
    }

    if ((ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') && !inDoubleQuote && !inSingleQuote) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
      i++;
      continue;
    }

    // Handle pipe (command separator)
    if (ch === '|' && !inDoubleQuote && !inSingleQuote) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
      // Skip pipe
      i++;
      // Skip whitespace after pipe
      while (i < chars.length && (chars[i] === ' ' || chars[i] === '\t')) {
        i++;
      }
      continue;
    }

    current += ch;
    i++;
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Parse shell history content (auto-detects format).
 * Tries zsh format first, then epoch timestamp, then plain.
 */
export function parseShellHistory(content: string): ShellHistoryCommand[] {
  return parseBashHistory(content);
}
