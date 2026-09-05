// packages/core/src/reconstruct/shell-redirect.ts
//
// Redirections and heredocs: the constructs that change what the next
// token means without being part of the command's argv.
//
// `rm -rf /data > /dev/null` runs `rm -rf /data`, and a matcher that
// took `/dev/null` as an argument would still fire but would report the
// wrong command. `cat <<EOF` swallows every line until its delimiter,
// and a splitter that missed that would read the body as commands.
//
// Nothing here recurses into the splitter, which is why it lives apart
// from shell-split.ts.

import { flushWord, type ParseState } from './shell-split.js';

// ── Redirections and heredocs ─────────────────────────────────────────

export function readRedirection(state: ParseState, op: string): void {
  // A file-descriptor prefix (`2>`) is part of the redirection, not an argument.
  if (state.hasWord && /^\d+$/.test(state.word)) {
    state.word = '';
    state.hasWord = false;
  } else {
    flushWord(state);
  }
  state.pos += op.length;
  if (op === '<<' || op === '<<-') {
    const delimiter = readHeredocDelimiter(state);
    if (delimiter !== null) {
      state.pendingHeredocs.push({ delimiter, stripTabs: op === '<<-' });
    }
    return;
  }
  state.redirectTargetPending = true;
}

function readHeredocDelimiter(state: ParseState): string | null {
  const { src } = state;
  while (state.pos < src.length && (src[state.pos] === ' ' || src[state.pos] === '\t')) state.pos++;
  let delimiter = '';
  while (state.pos < src.length) {
    const ch = src[state.pos]!;
    if (ch === "'" || ch === '"') {
      const end = src.indexOf(ch, state.pos + 1);
      const stop = end === -1 ? src.length : end;
      delimiter += src.slice(state.pos + 1, stop);
      state.pos = end === -1 ? src.length : end + 1;
      continue;
    }
    if (ch === '\\' && state.pos + 1 < src.length) {
      delimiter += src[state.pos + 1];
      state.pos += 2;
      continue;
    }
    if (/[\s;&|<>()]/.test(ch)) break;
    delimiter += ch;
    state.pos++;
  }
  return delimiter.length > 0 ? delimiter : null;
}

export function consumeHeredocBodies(state: ParseState): void {
  const { src } = state;
  while (state.pendingHeredocs.length > 0) {
    const { delimiter, stripTabs } = state.pendingHeredocs.shift()!;
    while (state.pos < src.length) {
      const lineEnd = src.indexOf('\n', state.pos);
      const stop = lineEnd === -1 ? src.length : lineEnd;
      let line = src.slice(state.pos, stop);
      if (stripTabs) line = line.replace(/^\t+/, '');
      state.pos = lineEnd === -1 ? src.length : lineEnd + 1;
      if (line === delimiter) break;
    }
  }
}
