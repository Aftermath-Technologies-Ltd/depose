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
import { parse as parseYaml } from 'yaml';
import type {
  Event,
  ShellCommandPrePayload,
  ToolCallIntentPayload,
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
    // File doesn't exist or can't be read, return empty ruleset
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
  // Two sources of "the agent tried to run a destructive shell command":
  //   1. shell_command_pre, produced when the active capture layer
  //      (Claude PreToolUse hook or shell shim) intercepts the
  //      execution. Best quality: argv is already pre-tokenized.
  //   2. tool_call_intent, produced when we reconstruct from the
  //      Claude Code JSONL alone (no active capture). The command
  //      is a free-form string the agent emitted; we tokenize it
  //      ourselves so the headline use case ("agent ran `rm -rf`
  //      against your prod data") doesn't silently report 0
  //      destructive operations just because the user wasn't
  //      running the active hook at the time.
  let payload: ShellCommandPrePayload | null = null;

  if (event.type === 'shell_command_pre') {
    payload = event.payload as ShellCommandPrePayload;
  } else if (event.type === 'tool_call_intent') {
    payload = synthShellPayloadFromToolCallIntent(event.payload as ToolCallIntentPayload);
  }

  if (!payload) {
    return [];
  }

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
 * Build a synthetic ShellCommandPrePayload from a tool_call_intent
 * event when the tool is a shell-like tool (Bash) with a `command`
 * string. Returns null when the intent isn't shell-like, so non-shell
 * tools (Edit, Write, Read, etc.) don't waste rule cycles.
 *
 * The argv tokenizer is a small POSIX-shell-ish splitter: whitespace
 * separates tokens, single and double quotes group; backslash-escapes
 * are passed through unchanged inside the token (good enough for the
 * destructive patterns DEPOSE cares about, `rm -rf`, `terraform
 * destroy`, `psql -c "DROP TABLE …"`). Anything fancier would risk
 * false negatives by silently dropping characters.
 */
function synthShellPayloadFromToolCallIntent(
  intent: ToolCallIntentPayload
): ShellCommandPrePayload | null {
  if (!intent || typeof intent.toolName !== 'string') return null;
  if (intent.toolName.toLowerCase() !== 'bash') return null;
  const input = intent.toolInput as { command?: unknown } | null | undefined;
  if (!input || typeof input.command !== 'string' || input.command.length === 0) {
    return null;
  }
  const argv = tokenizeShellCommand(input.command);
  if (argv.length === 0) return null;
  return {
    argv,
    cwd: '',
    envHash: '',
    envSubset: {},
    ttyId: null,
    user: '',
    hostname: '',
    parentProcessTree: [],
    fileArgs: [],
    source: 'claude-pretooluse',
    captureSchemaVersion: 2,
    // Synthesized in-memory to run ruleset matching against an intent.
    // It never reaches a bundle, so there is no capture time to record.
    capturedAt: '',
    capturedAtSource: 'reconstructed',
    sessionId: null,
  };
}

/**
 * Whitespace-and-quote tokenizer for shell command strings.
 *
 * Goal is to faithfully reproduce the argv a POSIX shell would have
 * built for the patterns destructive rules look for. Single quotes
 * preserve content literally; double quotes preserve content but
 * still respect a trailing close quote; everything else is grouped
 * on whitespace boundaries. Quotes are stripped from the emitted
 * token (so `psql -c "DROP TABLE x"` yields argv[2] = "DROP TABLE x").
 */
export function tokenizeShellCommand(cmd: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < cmd.length) {
    // Skip leading whitespace.
    while (i < cmd.length && /\s/.test(cmd[i]!)) i++;
    if (i >= cmd.length) break;

    let token = '';
    let inSingle = false;
    let inDouble = false;
    while (i < cmd.length) {
      const c = cmd[i]!;
      if (!inSingle && !inDouble && /\s/.test(c)) break;
      if (c === "'" && !inDouble) {
        inSingle = !inSingle;
        i++;
        continue;
      }
      if (c === '"' && !inSingle) {
        inDouble = !inDouble;
        i++;
        continue;
      }
      // Backslash inside double quotes escapes the next character;
      // outside quotes also escapes (joins next char into token).
      if (c === '\\' && !inSingle && i + 1 < cmd.length) {
        token += cmd[i + 1];
        i += 2;
        continue;
      }
      token += c;
      i++;
    }
    out.push(token);
  }
  return out;
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

  // Check argvHead (prefix match), if defined, must match
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

  // Check argvContainsAny (any token contains any of the strings), if defined, must match
  if (argvContainsAny && argvContainsAny.length > 0) {
    const found = argv.some((arg) =>
      argvContainsAny.some((term) => arg.includes(term))
    );
    if (!found) {
      return null;
    }
    matchedField = matchedField ? `${matchedField}+argvContainsAny` : 'argvContainsAny';
  }

  // Check anyArgvRegex (regex matches any argv token), if defined, must match
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

  // Check stdinRegex (for gh api graphql cases), if defined, must match
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
