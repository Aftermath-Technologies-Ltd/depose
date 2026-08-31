// packages/cli/src/commands/cli-args.ts
//
// The kebab-cased argument shape the command handlers consume, and the
// conversion from commander's camelCase options.
//
// Commander derives option names from the long flag, so `--from-claude`
// arrives as `opts.fromClaude`. Handlers were written against
// `args['from-claude']`, so the keys are rebuilt rather than rewriting
// every handler.

export interface CliArgs {
  [key: string]: string | boolean | string[] | undefined;
}

function camelToKebab(name: string): string {
  return name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
}

/**
 * Convert commander's camelCase options into the kebab-case shape the
 * handlers consume.
 *
 * @param opts - Raw options object from a commander action.
 * @returns The same values keyed in kebab-case.
 */
export function optsToArgs(opts: Record<string, unknown>): CliArgs {
  const out: CliArgs = {};
  for (const [k, v] of Object.entries(opts)) {
    out[camelToKebab(k)] = v as string | boolean | string[] | undefined;
  }
  return out;
}
