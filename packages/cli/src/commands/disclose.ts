// packages/cli/src/commands/disclose.ts
//
// `depose disclose <bundle> --events <ids or ranges> --fields <paths> --out <dir>`
//
// Produces a disclosure bundle: the selected events byte-identical to
// the sealed ones, audit paths for every position against the signed
// Merkle root, and commitment openings for the selected fields only.
// The original manifest, signature, and timestamp travel unchanged.

import { resolve, join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { buildDisclosure } from '@depose/bundle';
import { parseEventLine } from '@depose/core';
import { CLI_VERSION } from '../version.js';

export interface DiscloseCommandArgs {
  events?: string;
  fields?: string;
  out?: string;
  include?: string | string[];
  'consistent-with'?: string;
  [key: string]: string | boolean | string[] | undefined;
}

/**
 * Resolve an `--events` spec to zero-based indices.
 *
 * Accepts `all`, comma-separated event ids, zero-based indices, and
 * inclusive index ranges (`3-7`), in any mix.
 *
 * @param spec - The flag value.
 * @param ids - Event ids in file order.
 * @returns Sorted unique indices.
 * @throws Error on an unknown id, a malformed range, or an index out of range.
 */
export function parseEventSelection(spec: string, ids: string[]): number[] {
  if (spec.trim() === 'all') return ids.map((_, i) => i);
  const out = new Set<number>();
  const byId = new Map(ids.map((id, i) => [id, i] as const));
  for (const raw of spec.split(',')) {
    const token = raw.trim();
    if (token === '') continue;
    const range = token.match(/^(\d+)-(\d+)$/);
    if (range) {
      const from = Number(range[1]);
      const to = Number(range[2]);
      if (from > to) throw new Error(`range "${token}" runs backwards; write it as ${to}-${from}`);
      for (let i = from; i <= to; i++) out.add(i);
      continue;
    }
    if (/^\d+$/.test(token)) {
      out.add(Number(token));
      continue;
    }
    const index = byId.get(token);
    if (index === undefined) {
      throw new Error(`event id "${token}" is not in this bundle; pass an id from events.jsonl, a zero-based index, or a range like 3-7`);
    }
    out.add(index);
  }
  for (const i of out) {
    if (i >= ids.length) throw new Error(`event index ${i} is out of range; the bundle has ${ids.length} events`);
  }
  return [...out].sort((a, b) => a - b);
}

/**
 * Resolve a `--fields` spec to JSON pointers or 'all'.
 *
 * @param spec - `all`, `none`, or comma-separated pointers (`/toolInput,/output`).
 * @returns The pointers, or 'all'.
 * @throws Error when a pointer is not a single top-level field.
 */
export function parseFieldSelection(spec: string): string[] | 'all' {
  const trimmed = spec.trim();
  if (trimmed === 'all') return 'all';
  if (trimmed === 'none' || trimmed === '') return [];
  const paths = trimmed.split(',').map((p) => p.trim()).filter((p) => p.length > 0);
  for (const p of paths) {
    if (!/^\/[^/]+$/.test(p)) {
      throw new Error(`field "${p}" must be a JSON pointer to one top-level payload field, like /toolInput`);
    }
  }
  return paths;
}

/**
 * Handle `depose disclose`.
 *
 * @param bundlePath - The sealed bundle directory.
 * @param args - Parsed flags.
 */
export async function handleDisclose(bundlePath: string, args: DiscloseCommandArgs): Promise<void> {
  const bundleDir = resolve(bundlePath);
  if (!existsSync(join(bundleDir, 'manifest.json'))) {
    console.error(`ERROR: ${bundleDir} has no manifest.json; pass a sealed bundle directory`);
    process.exit(1);
    return;
  }
  const eventsSpec = typeof args.events === 'string' ? args.events : 'all';
  const fieldsSpec = typeof args.fields === 'string' ? args.fields : 'none';
  const outDir = typeof args.out === 'string' ? resolve(args.out) : `${bundleDir}-disclosure`;
  const include = args.include === undefined ? undefined : ([] as string[]).concat(args.include as string | string[]);

  const ids = readFileSync(join(bundleDir, 'events.jsonl'), 'utf-8')
    .split('\n')
    .filter((l) => l.length > 0)
    .map((line) => parseEventLine(line).id);

  try {
    const result = buildDisclosure({
      bundleDir,
      outDir,
      indices: parseEventSelection(eventsSpec, ids),
      fields: parseFieldSelection(fieldsSpec),
      includeFiles: include,
      version: CLI_VERSION,
      producedAt: new Date().toISOString(),
      consistentWith: typeof args['consistent-with'] === 'string' ? resolve(args['consistent-with']) : undefined,
    });
    console.log(`Disclosure written to: ${result.outDir}`);
    console.log(
      `  ${result.disclosedCount} of ${result.document.leafCount} events disclosed, ` +
        `${result.withheldCount} withheld (positions and count remain visible by design)`
    );
    console.log(`  ${result.openingsDisclosed} field opening(s) disclosed; withheld fields: ${result.document.fields.withheld.join(', ') || 'none'}`);
    console.log(`Verify with: depose-verify verify ${result.outDir}`);
  } catch (err) {
    console.error(`FATAL: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
