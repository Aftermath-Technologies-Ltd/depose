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

/**
 * Payload fields committed by default when sealing: tool inputs (including
 * the copies an assistant message carries in toolCalls), tool outputs,
 * file contents, environment values. Event ids, timestamps, the tool
 * name, and gap reasons are never committed. Prompt and assistant text
 * are not committed by default; add prompt.text and
 * assistant_message.content to the ruleset's disclosable list when they
 * are sensitive.
 */
export const DEFAULT_DISCLOSABLE: readonly string[] = [
  'assistant_message.toolCalls',
  'tool_call_intent.toolInput',
  'tool_call_executed.toolInput',
  'shell_command_pre.argv',
  'shell_command_pre.envSubset',
  'tool_result.output',
  'tool_result.error',
  'file_diff.diff',
  'file_diff.contentPost',
];

/** A parsed ruleset: the destructive rules and the disclosable fields. */
export interface Ruleset {
  rules: DestructiveRule[];
  /** `<eventType>.<payloadField>` entries; DEFAULT_DISCLOSABLE when the file has none. */
  disclosable: string[];
}

// ── Ruleset loading ──────────────────────────────────────────────────

/**
 * Parse a full ruleset: rules plus the `disclosable` field list.
 *
 * @param yaml - Ruleset YAML text.
 * @returns Rules and disclosable entries (defaults when the key is absent).
 * @throws Error when `disclosable` is present but not a list of strings.
 */
export function parseRulesetYaml(yaml: string): Ruleset {
  const parsed = parseYaml(yaml) as { disclosable?: unknown } | null;
  const rules = parseDestructiveRulesYaml(yaml);
  const raw = parsed?.disclosable;
  if (raw === undefined || raw === null) {
    return { rules, disclosable: [...DEFAULT_DISCLOSABLE] };
  }
  if (!Array.isArray(raw) || raw.some((x) => typeof x !== 'string')) {
    throw new Error(
      'ruleset "disclosable" must be a list of "<eventType>.<payloadField>" strings; ' +
      'remove the key to use the defaults'
    );
  }
  return { rules, disclosable: raw as string[] };
}


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
 * Load a full ruleset (rules plus disclosable fields) from a YAML file.
 *
 * @param filePath - Absolute path to the ruleset YAML.
 * @returns The ruleset; empty rules and default disclosable fields when
 *          the file cannot be read.
 * @throws Error when the file parses but `disclosable` is malformed.
 */
export function loadRuleset(filePath: string): Ruleset {
  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch {
    return { rules: [], disclosable: [...DEFAULT_DISCLOSABLE] };
  }
  return parseRulesetYaml(content);
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
