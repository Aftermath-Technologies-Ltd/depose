// packages/core/src/reconstruct/yaml-parser.ts
//
// Minimal YAML parser for destructive ruleset files.
//
// This is a purpose-built parser that handles the subset of YAML
// used in destructive ruleset files (BUILD_PLAN.md §4.4):
//   - Top-level key-value pairs
//   - Arrays (with - prefix)
//   - Nested objects (2-space indent)
//   - Strings (quoted and unquoted)
//   - Numbers
//   - Inline arrays ([...])
//
// Does NOT support:
//   - Multi-line strings (|, >)
//   - Anchors/aliases
//   - Comments
//
// This is intentional: we only need to parse destructive ruleset YAML,
// not full YAML. A full parser would be overkill and a dependency.

/**
 * Parse a destructive ruleset YAML string into a JavaScript object.
 */
export function parse(input: string): unknown {
  const lines = input
    .split('\n')
    .map((l) => stripComment(l))
    .filter((l): l is string => l.trim().length > 0);

  return parseBlock(lines, 0, 0)[0];
}

// ── Parser ──

function parseBlock(lines: string[], start: number, indent: number): [unknown, number] {
  if (start >= lines.length) {
    return [null, start];
  }

  const firstLine = lines[start];
  const trimmed = firstLine!.trim();

  // Check if this is an array
  if (trimmed.startsWith('- ')) {
    return parseArray(lines, start, indent);
  }

  // Check if this is a key-value pair
  const kvMatch = trimmed.match(/^(\S+):\s*(.*)$/);
  if (kvMatch) {
    return parseObject(lines, start, indent);
  }

  // Fallback: treat as a scalar
  return [parseScalar(trimmed), start + 1];
}

function parseArray(lines: string[], start: number, parentIndent: number): [unknown[], number] {
  const items: unknown[] = [];
  let i = start;

  // Determine the indent of the first array item
  const firstIndent = lineIndentation(lines[start]!);
  const itemIndent = firstIndent;

  while (i < lines.length) {
    const line = lines[i]!;
    if (line === undefined) break;
    const lineIndent = lineIndentation(line);
    const trimmed = line.trim();

    // If we've outdented past the array, stop
    if (lineIndent < itemIndent && i > start) {
      break;
    }

    // Skip empty lines
    if (trimmed.length === 0) {
      i++;
      continue;
    }

    // Check if this is an array item at the right indent
    if (lineIndent === itemIndent && trimmed.startsWith('- ')) {
      const afterDash = trimmed.slice(2).trim();

      // Check if it's a nested object (key: value after -)
      const kvMatch = afterDash.match(/^(\S+):\s*(.*)$/);
      if (kvMatch && !isEmptyValue(kvMatch[2] ?? '')) {
        // It's a key:value on the - line, start of an inline object
        const [obj, next] = parseInlineObject(lines, i, itemIndent);
        items.push(obj);
        i = next;
        continue;
      }
      if (kvMatch && isEmptyValue(kvMatch[2] ?? '')) {
        // key: with no value on same line — check next lines for nested content
        const baseIndent = lineIndent + 2;
        // Peek at next line
        if (i + 1 < lines.length && lineIndentation(lines[i + 1]!) >= baseIndent) {
          // Nested block follows
          const key = kvMatch[1]!;
          const [val, next] = parseBlock(lines, i + 1, baseIndent);
          const obj: Record<string, unknown> = {};
          obj[key] = val;
          // Continue parsing sibling keys in this object
          i = next;
          // Read more keys at baseIndent
          while (i < lines.length) {
            const nextLine = lines[i]!;
            const nextIndent = lineIndentation(nextLine);
            const nextTrimmed = nextLine.trim();
            if (nextIndent < baseIndent || nextTrimmed.length === 0) break;
            if (nextIndent === baseIndent || nextIndent === baseIndent - 2) {
              // Another key at the same level as the first key
              const innerKv = nextTrimmed.match(/^(\S+):\s*(.*)$/);
              if (innerKv) {
                const innerKey = innerKv[1]!;
                const innerVal = innerKv[2] ?? '';
                if (isEmptyValue(innerVal)) {
                  // Check for nested content
                  const innerBase = nextIndent + 2;
                  if (i + 1 < lines.length && lineIndentation(lines[i + 1]!) >= innerBase) {
                    const [nested, nxt] = parseBlock(lines, i + 1, innerBase);
                    (obj as Record<string, unknown>)[innerKey] = nested;
                    i = nxt;
                  } else {
                    (obj as Record<string, unknown>)[innerKey] = null;
                    i++;
                  }
                } else {
                  (obj as Record<string, unknown>)[innerKey] = parseValue(innerVal, lines, i + 1, nextIndent + 2);
                  i++;
                }
              } else {
                i++;
              }
            } else {
              break;
            }
          }
          items.push(obj);
          continue;
        } else {
          // key: with no value and no nested content
          const obj: Record<string, unknown> = {};
          obj[kvMatch[1]!] = null;
          items.push(obj);
          i++;
          continue;
        }
      }

      // Also check for key: with empty value that has nested children
      if (kvMatch && isEmptyValue(kvMatch[2] ?? '')) {
        const [obj, next] = parseInlineObject(lines, i, itemIndent);
        items.push(obj);
        i = next;
        continue;
      }

      // It's a scalar array item
      items.push(parseScalar(afterDash));
      i++;
      continue;
    }

    // Not an array item at the right indent level — stop
    if (lineIndent < itemIndent) {
      break;
    }

    i++;
  }

  return [items, i];
}

function parseInlineObject(lines: string[], start: number, parentItemIndent: number): [Record<string, unknown>, number] {
  const obj: Record<string, unknown> = {};
  let i = start;

  // Parse the first key on the - line
  const firstLine = lines[i] ?? '';
  const afterDash = firstLine.trim().slice(2).trim();
  const kvMatch = afterDash.match(/^(\S+):\s*(.*)$/);
  const baseIndent = parentItemIndent + 2;

  if (kvMatch) {
    const key = kvMatch[1]!;
    const valueStr = kvMatch[2] ?? '';
    if (isEmptyValue(valueStr)) {
      // Check if next line has nested content
      if (i + 1 < lines.length && lineIndentation(lines[i + 1]!) >= baseIndent) {
        const [val, next] = parseBlock(lines, i + 1, baseIndent);
        obj[key] = val;
        i = next;
      } else {
        obj[key] = null;
        i++;
      }
    } else {
      obj[key] = parseValue(valueStr, lines, i + 1, baseIndent);
      i++;
    }
  } else {
    i++;
  }

  // Parse subsequent keys (deeper indent or same indent as baseIndent)
  while (i < lines.length) {
    const line = lines[i]!;
    if (line === undefined) break;
    const lineIndent = lineIndentation(line);
    const trimmed = line.trim();

    if (lineIndent < baseIndent || trimmed.length === 0) {
      break;
    }

    // Check for - prefix (would start a new array item at parent level)
    if (lineIndent === parentItemIndent && trimmed.startsWith('- ')) {
      break;
    }

    const innerKv = trimmed.match(/^(\S+):\s*(.*)$/);
    if (innerKv) {
      const key = innerKv[1]!;
      const valueStr = innerKv[2] ?? '';
      if (isEmptyValue(valueStr)) {
        // Check if next line has nested content
        const innerBase = lineIndent + 2;
        if (i + 1 < lines.length && lineIndentation(lines[i + 1]!) >= innerBase) {
          const [val, next] = parseBlock(lines, i + 1, innerBase);
          obj[key] = val;
          i = next;
        } else {
          obj[key] = null;
          i++;
        }
      } else {
        obj[key] = parseValue(valueStr, lines, i + 1, lineIndent + 2);
        i++;
      }
    } else {
      i++;
    }
  }

  return [obj, i];
}

function parseObject(lines: string[], start: number, indent: number): [Record<string, unknown>, number] {
  const obj: Record<string, unknown> = {};
  let i = start;

  while (i < lines.length) {
    const line = lines[i]!;
    if (line === undefined) break;
    const lineIndent = lineIndentation(line);
    const trimmed = line.trim();

    // If indent is less than expected, we've left this block
    if (lineIndent < indent && i > start) {
      break;
    }

    // Skip array items (they're handled separately)
    if (trimmed.startsWith('- ')) {
      // This could be a key's value (an array)
      // But only if we're at the right indent level for a nested array
      break;
    }

    const kvMatch = trimmed.match(/^(\S+):\s*(.*)$/);
    if (kvMatch) {
      const key = kvMatch[1]!;
      const valueStr = kvMatch[2] ?? '';
      if (isEmptyValue(valueStr)) {
        // Check if next line has nested content
        const childIndent = lineIndent + 2;
        if (i + 1 < lines.length && lineIndentation(lines[i + 1]!) >= childIndent) {
          const [val, next] = parseBlock(lines, i + 1, childIndent);
          obj[key] = val;
          i = next;
        } else {
          obj[key] = null;
          i++;
        }
      } else {
        obj[key] = parseValue(valueStr, lines, i + 1, lineIndent + 2);
        i++;
      }
    } else {
      i++;
    }
  }

  return [obj, i];
}

/**
 * Parse a value that appears on the same line as a key.
 * Handles inline arrays like ["a", "b", "c"].
 */
function parseValue(valueStr: string, lines: string[], nextLine: number, childIndent: number): unknown {
  const trimmed = valueStr.trim();

  // Inline array: [item1, item2, ...]
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    const inner = trimmed.slice(1, -1).trim();
    if (inner.length === 0) return [];
    return inner.split(',').map((s) => parseScalar(s.trim()));
  }

  // Inline array that might wrap (not ending with ]) — check next lines
  if (trimmed.startsWith('[') && !trimmed.endsWith(']')) {
    let full = trimmed;
    let j = nextLine;
    while (j < lines.length) {
      const nextTrimmed = lines[j]!.trimEnd();
      full += ' ' + nextTrimmed.trim();
      j++;
      if (nextTrimmed.endsWith(']')) break;
    }
    const inner = full.slice(1, full.indexOf(']')).trim();
    if (inner.length === 0) return [];
    return inner.split(',').map((s) => parseScalar(s.trim()));
  }

  return parseScalar(trimmed);
}

// ── Scalar parsing ──

function parseScalar(value: string): unknown {
  const trimmed = value.trim();

  // Empty string
  if (trimmed.length === 0) {
    return null;
  }

  // Quoted string (double or single quotes)
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    // Unescape basic YAML escapes
    const inner = trimmed.slice(1, -1);
    return inner
      .replace(/\\n/g, '\n')
      .replace(/\\t/g, '\t')
      .replace(/\\(.)/g, '$1');
  }

  // Boolean
  if (trimmed === 'true' || trimmed === 'True' || trimmed === 'TRUE') return true;
  if (trimmed === 'false' || trimmed === 'False' || trimmed === 'FALSE') return false;
  if (trimmed === 'null' || trimmed === 'Null' || trimmed === 'NULL' || trimmed === '~') return null;

  // Number (integer or float)
  if (/^\d+(\.\d+)?$/.test(trimmed) || /^-\d+(\.\d+)?$/.test(trimmed)) {
    return trimmed.includes('.') ? parseFloat(trimmed) : parseInt(trimmed, 10);
  }

  // Unquoted string
  return trimmed;
}

// ── Helpers ──

function isEmptyValue(value: string): boolean {
  return value.trim().length === 0 || value.trim() === '|' || value.trim() === '>';
}

function lineIndentation(line: string): number {
  const match = line.match(/^(\s*)/);
  return match ? match[1]!.length : 0;
}

function stripComment(line: string): string {
  // Remove inline comments (not inside quotes)
  let inQuote = false;
  let quoteChar = '';
  let result = '';

  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (inQuote) {
      result += ch;
      if (ch === quoteChar && (i === 0 || line[i - 1] !== '\\')) {
        inQuote = false;
      }
    } else {
      if (ch === '"' || ch === "'") {
        inQuote = true;
        quoteChar = ch;
        result += ch;
      } else if (ch === '#') {
        // Rest of line is a comment
        break;
      } else {
        result += ch;
      }
    }
  }

  return result;
}