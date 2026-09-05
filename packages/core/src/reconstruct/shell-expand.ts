// packages/core/src/reconstruct/shell-expand.ts
//
// Turn a recorded argv (or a raw command string) into the simple commands
// destructive rules should see. Two transformations on top of the
// splitter in shell-split.ts:
//
//   1. `<shell> -c <string>` is expanded into the commands inside the
//      string. The Claude PreToolUse hook records every Bash tool call
//      as ['bash', '-c', <command>], so without this step no argvHead
//      rule could ever fire on active capture.
//   2. Privilege and environment wrappers (sudo, env, nice, time, nohup,
//      command, exec, timeout, doas, xargs) and leading VAR=value
//      assignments are stripped so the verb lands at argv[0].
//
// Both are applied recursively: `sudo bash -c "env X=1 terraform destroy"`
// resolves to ['terraform', 'destroy'].

import { splitShellCommand, type RawSimpleCommand, type SimpleCommandOrigin } from './shell-split.js';

// ── Types ─────────────────────────────────────────────────────────────

/** A simple command ready for rule matching. */
export interface SimpleCommand {
  /** Zero-based position in source order across the whole compound command. */
  index: number;
  /** argv after wrapper stripping; argv[0] is the verb rules match on. */
  argv: string[];
  /** argv as the shell would have built it, before wrapper stripping. */
  rawArgv: string[];
  /** Wrappers removed to reach `argv`, in the order they were removed. */
  wrappers: string[];
  /** Where the command sat in the compound command. */
  origin: SimpleCommandOrigin;
}

const SHELL_NAMES = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash']);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Flags that consume the following word, per wrapper. A wrapper not in
 * this table is stripped by name alone.
 */
const WRAPPER_FLAGS_WITH_VALUE: Record<string, Set<string>> = {
  sudo: new Set(['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U', '-T', '--user', '--group', '--prompt', '--host', '--chdir', '--role', '--type']),
  doas: new Set(['-u', '-C']),
  env: new Set(['-u', '-C', '-S', '--unset', '--chdir', '--split-string']),
  nice: new Set(['-n', '--adjustment']),
  time: new Set(['-f', '-o', '--format', '--output']),
  timeout: new Set(['-s', '-k', '--signal', '--kill-after']),
  xargs: new Set(['-n', '-I', '-P', '-d', '-a', '-L', '-s', '-E', '-i', '-l', '--max-args', '--replace', '--max-procs', '--delimiter', '--arg-file', '--max-lines', '--max-chars', '--eof']),
  command: new Set(),
  nohup: new Set(),
  exec: new Set(['-a']),
  builtin: new Set(),
};

/** Wrappers whose first positional argument is not the wrapped command. */
const WRAPPER_POSITIONALS: Record<string, number> = { timeout: 1 };

// ── Public API ────────────────────────────────────────────────────────

/**
 * Expand a raw command string into the simple commands rules match on.
 *
 * @param command - The command as a shell would receive it.
 * @returns Simple commands in source order with wrappers stripped.
 */
export function expandCommandString(command: string): SimpleCommand[] {
  return finalize(splitShellCommand(command, 'top').flatMap(stripWrappers));
}

/**
 * Expand a recorded argv into the simple commands rules match on.
 *
 * ['bash', '-c', 'a && b'] yields the commands inside the string; any
 * other argv is treated as one simple command and only wrapper-stripped.
 *
 * @param argv - argv as recorded by the hook, the shim, or shell history.
 * @returns Simple commands in source order with wrappers stripped.
 */
export function expandArgv(argv: string[]): SimpleCommand[] {
  if (argv.length === 0) return [];
  return finalize(stripWrappers({ argv, origin: 'top' }));
}

// ── Wrapper stripping ─────────────────────────────────────────────────

function finalize(commands: SimpleCommand[]): SimpleCommand[] {
  return commands.map((c, index) => ({ ...c, index }));
}

/**
 * Strip wrappers from one raw command. Returns more than one command
 * when the wrapped command turns out to be `<shell> -c <string>`.
 */
function stripWrappers(raw: RawSimpleCommand): SimpleCommand[] {
  let argv = raw.argv;
  const wrappers: string[] = [];

  for (let guard = 0; guard < 16; guard++) {
    argv = dropAssignments(argv, wrappers);
    if (argv.length === 0) break;
    const verb = basename(argv[0]!);

    if (SHELL_NAMES.has(verb)) {
      const inner = shellCommandString(argv);
      if (inner !== null) {
        return splitShellCommand(inner, 'shell-c').flatMap((nested) => {
          const expanded = stripWrappers(nested);
          return expanded.map((c) => ({ ...c, wrappers: [...wrappers, verb, ...c.wrappers] }));
        });
      }
      break;
    }

    const flagsWithValue = WRAPPER_FLAGS_WITH_VALUE[verb];
    if (flagsWithValue === undefined) break;
    if (verb === 'command' && argv.slice(1).some((a) => a === '-v' || a === '-V')) break;

    wrappers.push(verb);
    argv = dropWrapperFlags(argv.slice(1), flagsWithValue, WRAPPER_POSITIONALS[verb] ?? 0);
  }

  return [{ index: 0, argv, rawArgv: raw.argv, wrappers, origin: raw.origin }];
}

function dropAssignments(argv: string[], wrappers: string[]): string[] {
  let i = 0;
  while (i < argv.length && ASSIGNMENT.test(argv[i]!)) {
    wrappers.push(argv[i]!.slice(0, argv[i]!.indexOf('=')) + '=');
    i++;
  }
  return i === 0 ? argv : argv.slice(i);
}

function dropWrapperFlags(rest: string[], flagsWithValue: Set<string>, positionals: number): string[] {
  let i = 0;
  while (i < rest.length) {
    const token = rest[i]!;
    if (token === '--') {
      i++;
      break;
    }
    if (token.startsWith('-') && token.length > 1) {
      const eq = token.indexOf('=');
      const name = eq === -1 ? token : token.slice(0, eq);
      // Short flags with an attached value (-n5, -umike) carry it inline.
      const attached = !token.startsWith('--') && token.length > 2 && flagsWithValue.has(token.slice(0, 2));
      if (flagsWithValue.has(name) && eq === -1 && !attached) {
        i += 2;
      } else {
        i += 1;
      }
      continue;
    }
    break;
  }
  return rest.slice(i + positionals);
}

/**
 * If argv is `<shell> [flags] -c <string> [args]`, return the string.
 * Combined short flags such as `-lc` or `-ec` count as `-c`.
 */
function shellCommandString(argv: string[]): string | null {
  for (let i = 1; i < argv.length; i++) {
    const token = argv[i]!;
    if (token === '--') return null;
    if (!token.startsWith('-') || token.startsWith('--')) return null;
    if (token.includes('c')) {
      const next = argv[i + 1];
      return next === undefined ? null : next;
    }
  }
  return null;
}

function basename(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash === -1 ? path : path.slice(slash + 1);
}
