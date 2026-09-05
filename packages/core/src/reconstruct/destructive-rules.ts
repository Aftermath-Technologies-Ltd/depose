// packages/core/src/reconstruct/destructive-rules.ts
//
// Load destructive operation rules from a YAML ruleset.
//
// Ruleset format (see docs/bundle-format.md#destructive-ruleset):
//   version: 1
//   rules:
//     - id: terraform-destroy
//       matcher:
//         argvHead: ["terraform", "destroy"]
//       severity: critical
//
// Matching lives in destructive-match.ts.

import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';

// ── Ruleset types ────────────────────────────────────────────────────

/** Severity levels a rule can declare. */
export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low';

/**
 * A single destructive operation rule.
 */
export interface DestructiveRule {
  id: string;
  matcher: RuleMatcher;
  severity: RuleSeverity;
}

/**
 * Rule matching criteria.
 * At least one criterion must be present.
 */
export interface RuleMatcher {
  /** Exact argv prefix match (e.g., ["terraform", "destroy"]) */
  argvHead?: string[];
  /** Any argv token must contain one of these strings (case-sensitive) */
  argvContainsAny?: string[];
  /** Regex to match against any argv token (as a single string) */
  anyArgvRegex?: string;
  /** Regex to match against stdin content (for gh api graphql cases) */
  stdinRegex?: string;
}

/**
 * A rule match result. One per rule that fired on an event.
 */
export interface RuleMatch {
  ruleId: string;
  severity: RuleSeverity;
  /** The argv tokens the criterion matched against. */
  matchedArgv: string[];
  /** Which matcher criteria fired, joined with '+'. */
  matchedField: string;
  /**
   * Zero-based index of the simple command that matched, counted in
   * source order across the compound command the event recorded.
   */
  simpleCommandIndex: number;
  /** The simple command's argv after wrapper stripping. */
  simpleCommand: string[];
  /** How many simple commands the recorded command expanded to. */
  simpleCommandCount: number;
  /** Wrappers stripped to reach the verb (sudo, env, VAR=, ...). */
  strippedWrappers: string[];
}

// ── Ruleset loading ──────────────────────────────────────────────────

/**
 * Load destructive rules from a YAML file (absolute path).
 *
 * Returns an empty ruleset if the file doesn't exist (graceful degradation).
 *
 * @param filePath - Absolute path to the ruleset YAML.
 * @returns The parsed rules, or [] when the file cannot be read.
 */
export function loadDestructiveRules(filePath: string): DestructiveRule[] {
  try {
    const content = readFileSync(filePath, 'utf-8');
    return parseDestructiveRulesYaml(content);
  } catch {
    return [];
  }
}

/**
 * Load destructive rules from a YAML string.
 *
 * @param yaml - Ruleset YAML text.
 * @returns The rules that parsed; malformed entries are skipped.
 */
export function parseDestructiveRulesYaml(yaml: string): DestructiveRule[] {
  const parsed = parseYaml(yaml);
  const ruleset = parsed as { version?: number; rules?: Record<string, unknown>[] };
  const rules: DestructiveRule[] = [];

  if (!ruleset?.rules) {
    return [];
  }

  for (const rule of ruleset.rules) {
    const parsedRule = parseSingleRule(rule);
    if (parsedRule) {
      rules.push(parsedRule);
    }
  }

  return rules;
}

/**
 * Parse a single rule object (from YAML).
 */
function parseSingleRule(rule: Record<string, unknown>): DestructiveRule | null {
  const id = rule.id as string | undefined;
  const severity = rule.severity as DestructiveRule['severity'] | undefined;
  const matcher = rule.matcher as Record<string, unknown> | undefined;

  if (!id || !severity || !matcher) {
    return null;
  }

  const parsedSeverity =
    severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low'
      ? severity
      : 'medium';

  return {
    id,
    severity: parsedSeverity,
    matcher: {
      argvHead: (matcher.argvHead as string[] | undefined)?.map(String),
      argvContainsAny: (matcher.argvContainsAny as string[] | undefined)?.map(String),
      anyArgvRegex: matcher.anyArgvRegex as string | undefined,
      stdinRegex: matcher.stdinRegex as string | undefined,
    },
  };
}
