// packages/core/src/reconstruct/shell-scan.ts
//
// Finding where a shell construct ends, without caring what is inside it.
//
// Both scanners here are pure functions over a string: they take an
// index and return an index. That is what separates them from the rest
// of shell-split.ts, which builds commands and recurses into itself for
// subshells and substitutions. Getting the end of a construct wrong is
// how `$(rm -rf /)` becomes an ordinary-looking word, so these are kept
// where they can be read on their own.

/**
 * Find the index of the closing delimiter for a construct opened at
 * `start`, skipping quoted regions and nested openers of the same kind.
 * Returns src.length when unbalanced so the caller consumes the rest.
 */
export function findClose(src: string, start: number, open: string, close: string): number {
  let depth = 1;
  let i = start;
  while (i < src.length) {
    const ch = src[i]!;
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === "'") {
      const end = src.indexOf("'", i + 1);
      i = end === -1 ? src.length : end + 1;
      continue;
    }
    if (ch === '"') {
      i = skipDoubleQuoted(src, i + 1);
      continue;
    }
    if (open !== close && src.startsWith(open, i)) {
      depth++;
      i += open.length;
      continue;
    }
    if (open !== close && ch === '(' && open === '$(') {
      depth++;
      i++;
      continue;
    }
    if (src.startsWith(close, i)) {
      depth--;
      if (depth === 0) return i;
      i += close.length;
      continue;
    }
    i++;
  }
  return src.length;
}

function skipDoubleQuoted(src: string, from: number): number {
  let i = from;
  while (i < src.length) {
    const ch = src[i]!;
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === '"') return i + 1;
    i++;
  }
  return src.length;
}
