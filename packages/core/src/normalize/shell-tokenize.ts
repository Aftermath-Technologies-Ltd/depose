// packages/core/src/normalize/shell-tokenize.ts
//
// The quote-aware tokenizer the history parsers use to recover argv from
// a command string.
//
// This is deliberately not the tokenizer destructive-rule matching uses:
// that one is in reconstruct/shell-split.ts and understands heredocs,
// subshells, and command substitution, because a rule that misses one of
// those misses the command it was written for. Here the input is a single
// history line and the job is argv recovery, not evasion resistance.

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
