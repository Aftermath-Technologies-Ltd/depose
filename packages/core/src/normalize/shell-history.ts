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
//   With fish history (XML-like or plain):
//     fish records timestamped history in a different format

/**
 * Parse bash/zsh history (plain or timestamped with epoch seconds).
 *
 * Supports:
 *   - Plain: "command\n"
 *   - Epoch timestamped: "1684417200  command\n"
 *   - Colon-prefixed (zsh): ": 1684417200:0;command\n"
 *
 * Compound commands separated by |, &&, ||, or ; produce one
 * ShellHistoryCommand per stage, each sharing the same timestamp.
 */
export function parseBashHistory(content: string): ShellHistoryCommand[] {
  const lines = content.split('\n').filter((l) => l.trim().length > 0);
  const commands: ShellHistoryCommand[] = [];
  const cwd = process.cwd();

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
        cwd,
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
 * Parse fish shell history.
 *
 * Fish uses a YAML-like format in ~/.local/share/fish/fish_history
 * that is fundamentally different from bash/zsh line-oriented history.
 * This parser does not yet support the fish format; calling it will
 * throw an informative error so callers know they need to implement
 * or delegate fish history parsing rather than silently producing
 * wrong results.
 *
 * To add fish support, implement the actual fish YAML history parser
 * here and remove this throw.
 */
export function parseFishHistory(_content: string): ShellHistoryCommand[] {
  throw new Error(
    'Fish history parsing is not yet implemented. ' +
    'Fish uses a YAML-like history format that differs from bash/zsh. ' +
    'Please use parseBashHistory() directly if you have bash-compatible history, ' +
    'or contribute a fish history parser to DEPOSE.'
  );
}

// ── Tokenizer ────────────────────────────────────────────────────────
//
// Shell command tokenizer that respects quotes and splits on
// command separators (|, &&, ||, ;).
//
// This is a best-effort tokenizer, not a full shell parser.
// It handles:
//   - Double-quoted strings (with basic escape handling)
//   - Single-quoted strings (no escape handling, per POSIX)
//   - Unquoted words (split on whitespace)
//   - Backslash escapes
//   - Command separators: |, &&, ||, ;
//
// Returns string[][]; one inner array per command stage.
// E.g. "echo foo | grep bar" → [["echo", "foo"], ["grep", "bar"]]
// E.g. "a && b" → [["a"], ["b"]]

/**
 * Tokenize a shell command string into argv stages (respecting quotes).
 *
 * Splits on command separators (|, &&, ||, ;) to produce one argv
 * array per pipeline stage. Each inner array is the argv for one
 * stage.
 *
 * @returns Array of argv arrays. Simple commands yield a single-element
 *          outer array. Pipelined commands yield one element per stage.
 */
export function tokenize(command: string): string[][] {
  const stages: string[][] = [];
  let currentTokens: string[] = [];
  let current = '';
  let inDoubleQuote = false;
  let inSingleQuote = false;
  let escaped = false;
  let i = 0;

  const chars = command.split('');

  // Flush the current token into currentTokens
  const flushToken = () => {
    if (current.length > 0) {
      currentTokens.push(current);
      current = '';
    }
  };

  // Flush currentTokens into stages and start a new stage
  const flushStage = () => {
    flushToken();
    if (currentTokens.length > 0) {
      stages.push(currentTokens);
    }
    currentTokens = [];
  };

  while (i < chars.length) {
    const ch = chars[i];

    // Handle escape sequences
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

    // Quotes, only when not inside the other kind
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

    // Inside quotes, everything is literal
    if (inDoubleQuote || inSingleQuote) {
      current += ch;
      i++;
      continue;
    }

    // ── Command separators (unquoted) ─────────────────────────────

    // && (AND operator)
    if (ch === '&' && i + 1 < chars.length && chars[i + 1] === '&') {
      flushStage();
      i += 2;
      // Skip whitespace after separator
      while (i < chars.length && (chars[i] === ' ' || chars[i] === '\t')) {
        i++;
      }
      continue;
    }

    // || (OR operator)
    if (ch === '|' && i + 1 < chars.length && chars[i + 1] === '|') {
      flushStage();
      i += 2;
      // Skip whitespace after separator
      while (i < chars.length && (chars[i] === ' ' || chars[i] === '\t')) {
        i++;
      }
      continue;
    }

    // | (pipe)
    if (ch === '|') {
      flushStage();
      i++;
      // Skip whitespace after pipe
      while (i < chars.length && (chars[i] === ' ' || chars[i] === '\t')) {
        i++;
      }
      continue;
    }

    // ; (semicolon)
    if (ch === ';') {
      flushStage();
      i++;
      // Skip whitespace after semicolon
      while (i < chars.length && (chars[i] === ' ' || chars[i] === '\t')) {
        i++;
      }
      continue;
    }

    // ── Whitespace ─────────────────────────────────────────────────

    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      flushToken();
      i++;
      continue;
    }

    // ── Regular character ──────────────────────────────────────────

    current += ch;
    i++;
  }

  // Flush remaining
  flushStage();

  // If no stages were produced (e.g., empty string), return empty outer array
  if (stages.length === 0 && currentTokens.length === 0) {
    // Even empty input yields at most one stage with zero tokens,
    // but for backward compat, return [[]] only if there was content
    // Actually: empty input should return empty array of stages
    return [];
  }

  // Don't include empty stages at the end (e.g. trailing ;)
  return stages.filter((s) => s.length > 0);
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Parse shell history content (auto-detects format).
 * Tries zsh format first, then epoch timestamp, then plain.
 */
export function parseShellHistory(content: string): ShellHistoryCommand[] {
  return parseBashHistory(content);
}