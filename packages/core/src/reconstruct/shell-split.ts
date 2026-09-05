// packages/core/src/reconstruct/shell-split.ts
//
// Split a shell command string into the simple commands a POSIX shell
// would run. Destructive-rule matching runs over each simple command
// independently, so `cd /prod && rm -rf .` and `sudo rm -rf /data` fire
// the same rules as a bare `rm -rf`.
//
// This is a tokenizer plus a list splitter, not a full shell grammar.
// It understands quoting, backslash escapes, comments, heredocs,
// redirections, the list operators (&&, ||, |, |&, ;, &, newline),
// subshells, $(...) and backtick command substitution. Anything it
// cannot parse degrades to "one more word in the current command"
// rather than being dropped, so a rule can only miss by seeing extra
// tokens, never by losing the verb.
//
// See docs/bundle-format.md#destructive-rule-matching for the contract.

import { findClose } from './shell-scan.js';
import { readRedirection, consumeHeredocBodies } from './shell-redirect.js';

// ── Types ─────────────────────────────────────────────────────────────

/** Where a simple command sat in the compound command it came from. */
export type SimpleCommandOrigin = 'top' | 'subshell' | 'substitution' | 'shell-c';

/** One argv a shell would hand to execve, before wrapper stripping. */
export interface RawSimpleCommand {
  argv: string[];
  origin: SimpleCommandOrigin;
}

const LIST_OPERATORS = ['&&', '||', '|&', ';;', '|', ';', '&'] as const;
const REDIRECT_OPERATORS = ['&>>', '<<<', '<<-', '>>', '<<', '>&', '<&', '&>', '>|', '>', '<'] as const;

export interface ParseState {
  src: string;
  pos: number;
  out: RawSimpleCommand[];
  origin: SimpleCommandOrigin;
  argv: string[];
  word: string;
  hasWord: boolean;
  /** Heredoc delimiters waiting for the end of the current line. */
  pendingHeredocs: Array<{ delimiter: string; stripTabs: boolean }>;
  /** Consume the next word as a redirection target rather than an argument. */
  redirectTargetPending: boolean;
}

// ── Public API ────────────────────────────────────────────────────────

/**
 * Split a shell command string into simple commands in source order.
 *
 * Commands inside subshells, `$(...)`, and backticks are emitted where
 * they appear. The list operators and redirections themselves are not
 * part of any argv.
 *
 * @param command - The command string as a shell would receive it.
 * @param origin - Where the string came from (top-level by default).
 * @returns The simple commands, each with the argv the shell would build.
 */
export function splitShellCommand(
  command: string,
  origin: SimpleCommandOrigin = 'top'
): RawSimpleCommand[] {
  const state: ParseState = {
    src: command,
    pos: 0,
    out: [],
    origin,
    argv: [],
    word: '',
    hasWord: false,
    pendingHeredocs: [],
    redirectTargetPending: false,
  };
  parseList(state);
  flushCommand(state);
  return state.out;
}

// ── List parsing ──────────────────────────────────────────────────────

function parseList(state: ParseState): void {
  const { src } = state;
  while (state.pos < src.length) {
    const ch = src[state.pos]!;

    if (ch === "'") {
      readSingleQuoted(state);
      continue;
    }
    if (ch === '"') {
      readDoubleQuoted(state);
      continue;
    }
    if (ch === '\\') {
      readBackslash(state);
      continue;
    }
    if (ch === '`') {
      readSubstitution(state, '`', '`');
      continue;
    }
    if (ch === '$' && src[state.pos + 1] === '(') {
      readSubstitution(state, '$(', ')');
      continue;
    }
    if (ch === '#' && !state.hasWord) {
      skipToLineEnd(state);
      continue;
    }
    if (ch === '(' && !state.hasWord && state.argv.length === 0) {
      readSubshell(state);
      continue;
    }
    if (ch === ')') {
      // Unbalanced close at this level: the caller of a nested parse
      // stops here; at the top level it is stray punctuation.
      if (state.origin !== 'top') return;
      state.pos++;
      continue;
    }
    if (ch === '\n') {
      state.pos++;
      flushCommand(state);
      consumeHeredocBodies(state);
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      state.pos++;
      flushWord(state);
      continue;
    }

    const redirect = matchOperator(src, state.pos, REDIRECT_OPERATORS);
    if (redirect !== null) {
      readRedirection(state, redirect);
      continue;
    }
    const listOp = matchOperator(src, state.pos, LIST_OPERATORS);
    if (listOp !== null) {
      state.pos += listOp.length;
      flushCommand(state);
      continue;
    }

    state.word += ch;
    state.hasWord = true;
    state.pos++;
  }
}

function matchOperator(src: string, pos: number, ops: readonly string[]): string | null {
  for (const op of ops) {
    if (src.startsWith(op, pos)) return op;
  }
  return null;
}

// ── Words ─────────────────────────────────────────────────────────────

export function flushWord(state: ParseState): void {
  if (!state.hasWord) return;
  const word = state.word;
  state.word = '';
  state.hasWord = false;
  if (state.redirectTargetPending) {
    state.redirectTargetPending = false;
    return;
  }
  // Brace-group punctuation is not an argument.
  if (state.argv.length === 0 && (word === '{' || word === '}' || word === '!')) return;
  if (word === '}' ) return;
  state.argv.push(word);
}

function flushCommand(state: ParseState): void {
  flushWord(state);
  state.redirectTargetPending = false;
  if (state.argv.length > 0) {
    state.out.push({ argv: state.argv, origin: state.origin });
  }
  state.argv = [];
}

function readSingleQuoted(state: ParseState): void {
  const { src } = state;
  const end = src.indexOf("'", state.pos + 1);
  const stop = end === -1 ? src.length : end;
  state.word += src.slice(state.pos + 1, stop);
  state.hasWord = true;
  state.pos = end === -1 ? src.length : end + 1;
}

function readDoubleQuoted(state: ParseState): void {
  const { src } = state;
  state.pos++;
  state.hasWord = true;
  while (state.pos < src.length) {
    const ch = src[state.pos]!;
    if (ch === '"') {
      state.pos++;
      return;
    }
    if (ch === '\\' && state.pos + 1 < src.length) {
      const next = src[state.pos + 1]!;
      if (next === '"' || next === '\\' || next === '$' || next === '`') {
        state.word += next;
        state.pos += 2;
        continue;
      }
      if (next === '\n') {
        state.pos += 2;
        continue;
      }
    }
    if (ch === '`') {
      readSubstitution(state, '`', '`');
      continue;
    }
    if (ch === '$' && src[state.pos + 1] === '(') {
      readSubstitution(state, '$(', ')');
      continue;
    }
    state.word += ch;
    state.pos++;
  }
}

function readBackslash(state: ParseState): void {
  const { src } = state;
  const next = src[state.pos + 1];
  if (next === undefined) {
    state.pos++;
    return;
  }
  state.pos += 2;
  if (next === '\n') return;
  state.word += next;
  state.hasWord = true;
}

function skipToLineEnd(state: ParseState): void {
  const end = state.src.indexOf('\n', state.pos);
  state.pos = end === -1 ? state.src.length : end;
}

// ── Nesting ───────────────────────────────────────────────────────────

function readSubstitution(state: ParseState, open: string, close: string): void {
  const { src } = state;
  const innerStart = state.pos + open.length;
  const closeAt = findClose(src, innerStart, open, close);
  const inner = src.slice(innerStart, closeAt);
  const nested = splitShellCommand(inner, 'substitution');
  state.out.push(...nested);
  // The substitution stays in the word as literal text so the enclosing
  // argv still reads like the command the agent wrote.
  state.word += src.slice(state.pos, Math.min(closeAt + close.length, src.length));
  state.hasWord = true;
  state.pos = Math.min(closeAt + close.length, src.length);
}

function readSubshell(state: ParseState): void {
  const { src } = state;
  const innerStart = state.pos + 1;
  const closeAt = findClose(src, innerStart, '(', ')');
  const inner = src.slice(innerStart, closeAt);
  state.out.push(...splitShellCommand(inner, 'subshell'));
  state.pos = Math.min(closeAt + 1, src.length);
}
