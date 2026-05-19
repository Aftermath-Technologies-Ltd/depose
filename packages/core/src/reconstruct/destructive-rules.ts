// packages/core/src/reconstruct/destructive-rules.ts
//
// Load and match destructive operation rules from YAML ruleset.
//
// Ruleset format (see BUILD_PLAN.md §4.4):
//   version: 1
//   rules:
//     - id: terraform-destroy
//       matcher:
//         argvHead: ["terraform", "destroy"]
//       severity: critical
//
// Each rule matches against shell_command_pre payloads.
// A command can match multiple rules (all matching rules are reported).
//
// See BUILD_PLAN.md §4.1 for the Event schema (shell_command_pre).

import { readFileSync } from 'node:fs';
import { parse as parseYaml } from './yaml-parser.js';
import type {
  Event,
  ShellCommandPrePayload,
  ProcessNode,
} from '../events/schema.js';

// ── Ruleset types ────────────────────────────────────────────────────

/**
 * A single destructive operation rule.
 */
export interface DestructiveRule {
  id: string;
  matcher: RuleMatcher;
  severity: 'critical' | 'high' | 'medium' | 'low';
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
 * A rule match result.
 */
export interface RuleMatch {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  matchedArgv: string[];
  matchedField: string;
}

// ── Ruleset loading ──────────────────────────────────────────────────

/**
 * Load destructive rules from a YAML file (absolute path).
 *
 * Returns an empty ruleset if the file doesn't exist (graceful degradation).
 */
export function loadDestructiveRules(filePath: string): DestructiveRule[] {
  try {
    const content = readFileSync(filePath, 'utf-8');
    return parseDestructiveRulesYaml(content);
  } catch {
    // File doesn't exist or can't be read — return empty ruleset
    return [];
  }
}

/**
 * Load destructive rules from a YAML string.
 */
export function parseDestructiveRulesYaml(yaml: string): DestructiveRule[] {
  const parsed = parseYaml(yaml);
  const ruleset = parsed as { version?: number; rules?: Record<string, unknown>[] };
  const rules: DestructiveRule[] = [];

  if (!ruleset?.rules) {
    return [];
  }

  for (const rule of ruleset.rules) {
    const parsed = parseSingleRule(rule);
    if (parsed) {
      rules.push(parsed);
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

// ── PCRE-to-JS regex conversion ──────────────────────────────────────

/**
 * Convert a PCRE-style regex string to a JavaScript RegExp.
 *
 * Handles inline flags like (?i), (?m), (?s) by extracting them and
 * applying them as JavaScript RegExp flags. PCRE inline flags like
 * (?i) at the start of a pattern are stripped and converted to the
 * corresponding JS flag ('i' for case-insensitive, 'm' for multiline,
 * 's' for dotAll).
 */
function pcreToJsRegex(pattern: string): RegExp | null {
  try {
    let flags = '';
    let cleaned = pattern;

    // Extract leading inline flags: (?i), (?im), (?ims), etc.
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

// ── Rule matching ────────────────────────────────────────────────────

/**
 * Match a shell_command_pre event against a ruleset.
 *
 * Returns all matching rules (a command can match multiple rules).
 */
export function matchDestructiveRules(
  event: Event,
  rules: DestructiveRule[]
): RuleMatch[] {
  if (event.type !== 'shell_command_pre') {
    return [];
  }

  const payload = event.payload as ShellCommandPrePayload;
  const matches: RuleMatch[] = [];

  for (const rule of rules) {
    const match = matchRuleAgainstPayload(rule, payload);
    if (match) {
      matches.push(match);
    }
  }

  return matches;
}

/**
 * Check if a single rule matches a shell_command_pre payload.
 *
 * When a rule defines multiple matcher criteria, ALL defined criteria
 * must match (AND logic). A rule with argvHead + argvContainsAny
 * requires both to match, not just one.
 */
function matchRuleAgainstPayload(
  rule: DestructiveRule,
  payload: ShellCommandPrePayload
): RuleMatch | null {
  const { argv } = payload;
  const { argvHead, argvContainsAny, anyArgvRegex, stdinRegex } = rule.matcher;

  let matchedField = '';
  let matchedArgv = argv;

  // Check argvHead (prefix match) — if defined, must match
  if (argvHead && argvHead.length > 0) {
    const head = argv.slice(0, argvHead.length);
    const matches = argvHead.every((term, i) =>
      head[i]?.toLowerCase() === term.toLowerCase()
    );
    if (!matches) {
      return null;
    }
    matchedField = matchedField ? `${matchedField}+argvHead` : 'argvHead';
  }

  // Check argvContainsAny (any token contains any of the strings) — if defined, must match
  if (argvContainsAny && argvContainsAny.length > 0) {
    const found = argv.some((arg) =>
      argvContainsAny.some((term) => arg.includes(term))
    );
    if (!found) {
      return null;
    }
    matchedField = matchedField ? `${matchedField}+argvContainsAny` : 'argvContainsAny';
  }

  // Check anyArgvRegex (regex matches any argv token) — if defined, must match
  if (anyArgvRegex && anyArgvRegex.length > 0) {
    const regex = pcreToJsRegex(anyArgvRegex);
    if (!regex) {
      return null;
    }
    const found = argv.some((arg) => regex.test(arg));
    if (!found) {
      return null;
    }
    matchedArgv = argv.filter((arg) => regex.test(arg));
    matchedField = matchedField ? `${matchedField}+anyArgvRegex` : 'anyArgvRegex';
  }

  // Check stdinRegex (for gh api graphql cases) — if defined, must match
  if (stdinRegex && stdinRegex.length > 0) {
    // Phase 1: stdin content is not captured in shell_command_pre payloads.
    // We do a best-effort check: see if any argv token contains the pattern.
    const regex = pcreToJsRegex(stdinRegex);
    if (!regex) {
      return null;
    }
    const fullCommand = argv.join(' ');
    if (!regex.test(fullCommand)) {
      return null;
    }
    matchedField = matchedField ? `${matchedField}+stdinRegex` : 'stdinRegex';
  }

  // At least one criterion must have been defined and matched
  if (!matchedField) {
    return null;
  }

  return {
    ruleId: rule.id,
    severity: rule.severity,
    matchedArgv,
    matchedField,
  };
}

// ── Destructive operations index ─────────────────────────────────────

/**
 * Build an index of destructive operations from a list of events.
 *
 * Returns an array of { event, rules } pairs for all events
 * that matched at least one destructive rule.
 */
export function buildDestructiveOpsIndex(
  events: Event[],
  rules: DestructiveRule[]
): Array<{ event: Event; matches: RuleMatch[] }> {
  const index: Array<{ event: Event; matches: RuleMatch[] }> = [];

  for (const event of events) {
    const matches = matchDestructiveRules(event, rules);
    if (matches.length > 0) {
      index.push({ event, matches });
    }
  }

  return index;
}
