// packages/core/src/reconstruct/destructive-match.ts
//
// Match events against a destructive ruleset.
//
// Two kinds of event describe "the agent tried to run a shell command":
//   1. shell_command_pre, produced by active capture (the Claude
//      PreToolUse hook or the shell shim). The hook records Bash tool
//      calls as ['bash', '-c', <command>].
//   2. tool_call_intent, produced when reconstructing from the Claude
//      Code JSONL alone. The command is a free-form string.
//
// Both are expanded into simple commands (shell-expand.ts) and every
// simple command is matched independently. A rule fires if any simple
// command matches; the match records which one and where it sat.

import { pcreToJsRegex } from './pcre-regex.js';
import type {
  Event,
  ShellCommandPrePayload,
  ToolCallIntentPayload,
} from '../events/schema.js';
import type { DestructiveRule, RuleMatch } from './destructive-rules.js';
import { expandArgv, expandCommandString, type SimpleCommand } from './shell-expand.js';

// ── PCRE-to-JS regex conversion ──────────────────────────────────────

/**
 * Whether argv starts with the given tokens, case-insensitively.
 *
 * @param argv - The simple command's tokens.
 * @param head - The rule's argvHead.
 * @returns True when every head token matches the token at its position.
 */
function matchesHead(argv: string[], head: string[]): boolean {
  if (argv.length < head.length) return false;
  return head.every((term, i) => argv[i]?.toLowerCase() === term.toLowerCase());
}

/**
 * argv with the program's global options removed.
 *
 * Many tools take options before the subcommand: `terraform -chdir=X
 * destroy`, `git -C /repo push --force`, `docker --context prod system
 * prune`. A rule written as ["terraform", "destroy"] means the destroy
 * subcommand, not that exact token sequence, so the options between the
 * program and its first non-option argument are dropped before the
 * second matching attempt.
 *
 * Only the leading run is removed, and only up to the first non-option
 * token: everything after the subcommand is the subcommand's own
 * arguments and a rule that names them means them.
 *
 * @param argv - The simple command's tokens.
 * @returns argv with the leading option run removed, or argv unchanged.
 */
export function withoutGlobalOptions(argv: string[]): string[] {
  if (argv.length < 2) return argv;
  let i = 1;
  while (i < argv.length && argv[i]!.startsWith('-')) {
    const option = argv[i]!;
    i++;
    // A separated value (`-C /repo`) belongs to the option before it.
    // An attached one (`-chdir=X`, `--context=prod`) does not.
    if (!option.includes('=') && i < argv.length && !argv[i]!.startsWith('-') && SEPARATED_VALUE_OPTIONS.has(option)) {
      i++;
    }
  }
  return i === 1 ? argv : [argv[0]!, ...argv.slice(i)];
}

/**
 * Global options that take their value as the next token. Kept as a list
 * rather than guessed, because guessing wrong eats the subcommand: with
 * `git -c push` treated as an option and a value, the `push` rule would
 * stop firing.
 */
const SEPARATED_VALUE_OPTIONS = new Set([
  '-C',
  '-c',
  // Go-style single-dash long options. terraform documents -chdir=DIR,
  // but Go's flag parsing accepts the separated form too, and a detector
  // that misses the form a tool tolerates is a detector with a hole.
  '-chdir',
  '-namespace',
  '-profile',
  '--config',
  '--context',
  '--chdir',
  '--cwd',
  '--directory',
  '--namespace',
  '-n',
  '--profile',
  '--region',
  '--kubeconfig',
  '--host',
  '-H',
]);

// ── Rule matching ────────────────────────────────────────────────────

/**
 * Expand the shell command an event records into simple commands.
 *
 * @param event - A shell_command_pre or tool_call_intent event.
 * @returns The simple commands, or [] when the event records no shell command.
 */
export function simpleCommandsForEvent(event: Event): SimpleCommand[] {
  if (event.type === 'shell_command_pre') {
    return expandArgv((event.payload as ShellCommandPrePayload).argv);
  }
  if (event.type === 'tool_call_intent') {
    const intent = event.payload as ToolCallIntentPayload;
    if (!intent || typeof intent.toolName !== 'string') return [];
    if (intent.toolName.toLowerCase() !== 'bash') return [];
    const input = intent.toolInput as { command?: unknown } | null | undefined;
    if (!input || typeof input.command !== 'string' || input.command.length === 0) return [];
    return expandCommandString(input.command);
  }
  return [];
}

/**
 * Match an event against a ruleset.
 *
 * Returns one RuleMatch per rule that fired. A rule fires when any simple
 * command in the event's compound command satisfies every criterion the
 * rule defines; the match names the first such command.
 *
 * @param event - The event to test.
 * @param rules - The ruleset.
 * @returns Matches in ruleset order; [] when nothing fired.
 */
export function matchDestructiveRules(
  event: Event,
  rules: DestructiveRule[]
): RuleMatch[] {
  const commands = simpleCommandsForEvent(event);
  if (commands.length === 0) return [];

  const matches: RuleMatch[] = [];
  for (const rule of rules) {
    for (const command of commands) {
      const match = matchRuleAgainstCommand(rule, command, commands.length);
      if (match) {
        matches.push(match);
        break;
      }
    }
  }
  return matches;
}

/**
 * Check if a single rule matches one simple command.
 *
 * When a rule defines multiple matcher criteria, ALL defined criteria
 * must match (AND logic).
 */
function matchRuleAgainstCommand(
  rule: DestructiveRule,
  command: SimpleCommand,
  commandCount: number
): RuleMatch | null {
  const { argv } = command;
  const { argvHead, argvContainsAny, anyArgvRegex, stdinRegex } = rule.matcher;

  const fields: string[] = [];
  let matchedArgv = argv;

  if (argvHead && argvHead.length > 0) {
    // Matched against argv as written and against argv with the global
    // options that sit between the program and its subcommand removed.
    // `terraform -chdir=infra/prod destroy` is the same act as
    // `terraform destroy` and used to slip past a ["terraform",
    // "destroy"] head; `rm -rf /x` still matches on the as-written form,
    // which is why both are tried rather than only the stripped one.
    if (!matchesHead(argv, argvHead) && !matchesHead(withoutGlobalOptions(argv), argvHead)) {
      return null;
    }
    fields.push('argvHead');
  }

  if (argvContainsAny && argvContainsAny.length > 0) {
    const found = argv.some((arg) => argvContainsAny.some((term) => arg.includes(term)));
    if (!found) return null;
    fields.push('argvContainsAny');
  }

  if (anyArgvRegex && anyArgvRegex.length > 0) {
    const regex = rule.matcher.compiled?.anyArgv ?? pcreToJsRegex(anyArgvRegex);
    if (!regex) return null;
    const found = argv.some((arg) => regex.test(arg));
    if (!found) return null;
    matchedArgv = argv.filter((arg) => regex.test(arg));
    fields.push('anyArgvRegex');
  }

  if (stdinRegex && stdinRegex.length > 0) {
    // stdin content is not captured in shell_command_pre payloads, so the
    // best available proxy is the simple command's full text.
    const regex = rule.matcher.compiled?.stdin ?? pcreToJsRegex(stdinRegex);
    if (!regex) return null;
    if (!regex.test(argv.join(' '))) return null;
    fields.push('stdinRegex');
  }

  if (fields.length === 0) return null;

  return {
    ruleId: rule.id,
    severity: rule.severity,
    matchedArgv,
    matchedField: fields.join('+'),
    simpleCommandIndex: command.index,
    simpleCommand: argv,
    simpleCommandCount: commandCount,
    strippedWrappers: command.wrappers,
  };
}

// ── Destructive operations index ─────────────────────────────────────

/**
 * Build an index of destructive operations from a list of events.
 *
 * @param events - Events to scan.
 * @param rules - The ruleset.
 * @returns One entry per event that matched at least one rule.
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
