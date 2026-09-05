// packages/core/src/reconstruct/pcre-regex.ts
//
// Rulesets are written with PCRE-style inline flags (`(?i)` and friends)
// because that is what the people writing them expect. JavaScript puts
// flags outside the pattern, so they are lifted here.
//
// Compilation happens once, when the ruleset is parsed
// (destructive-rules.ts), and the result is stored on the rule: matching
// runs the whole ruleset against every simple command of every event, so
// a per-token `new RegExp` turned a 40-rule ruleset over a large session
// into hundreds of thousands of constructions.

/**
 * Convert a PCRE-style regex string to a JavaScript RegExp.
 *
 * Leading inline flags such as (?i), (?m), (?s) are lifted into the
 * corresponding JavaScript flags.
 *
 * @param pattern - The pattern as written in the ruleset.
 * @returns The compiled RegExp, or null for a pattern JavaScript cannot
 *   compile. A rule with an uncompilable pattern does not fire, which is
 *   what it did before compilation moved to parse time.
 */
export function pcreToJsRegex(pattern: string): RegExp | null {
  try {
    let flags = '';
    let cleaned = pattern;
    const leadingFlags = /^\(\?([ims]+)\)/;
    const match = cleaned.match(leadingFlags);
    if (match && match[1]) {
      for (const ch of match[1]) {
        if (ch === 'i' || ch === 'm' || ch === 's') {
          flags += ch;
        }
      }
      cleaned = cleaned.replace(leadingFlags, '');
    }
    return new RegExp(cleaned, flags);
  } catch {
    return null;
  }
}
