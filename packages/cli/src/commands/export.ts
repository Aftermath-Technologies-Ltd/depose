// packages/cli/src/commands/export.ts
//
// `depose export <bundle> --format aat|asqav-receipt|scitt-statement [--out <file>]`
//
// Three IETF-shaped views of the same sealed bundle. Each exporter is a
// pure function from the loaded bundle (and, for the two signed formats,
// a key) to bytes; this file is the argument handling and the key checks
// around them. What each format can and cannot carry is in
// docs/export-mapping.md.

import { resolve, join } from 'node:path';
import { existsSync, writeFileSync } from 'node:fs';
import {
  loadBundle,
  exportAat,
  exportAsqavReceipts,
  exportScittStatement,
  type LoadedBundle,
} from '@depose/bundle';
import { loadOrGenerateKeyPair, fingerprintPublicKeyPem, type Ed25519KeyPair } from '@depose/chain';

/** Formats `--format` accepts. */
export const EXPORT_FORMATS = ['aat', 'asqav-receipt', 'scitt-statement'] as const;

/** One of the supported export formats. */
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

export interface ExportCommandArgs {
  format?: string;
  out?: string;
  'key-dir'?: string;
  'allow-key-mismatch'?: boolean;
  [key: string]: string | boolean | string[] | undefined;
}

/** Default filename for each format, relative to the bundle's parent. */
const DEFAULT_SUFFIX: Record<ExportFormat, string> = {
  aat: '-aat.jsonl',
  'asqav-receipt': '-asqav-receipts.jsonl',
  'scitt-statement': '-scitt-statement.cose',
};

/**
 * Narrow a `--format` value.
 *
 * @param value - The flag value.
 * @returns The format.
 * @throws Error naming the supported formats.
 */
export function parseFormat(value: string | undefined): ExportFormat {
  if (value && (EXPORT_FORMATS as readonly string[]).includes(value)) {
    return value as ExportFormat;
  }
  throw new Error(
    `--format is required and must be one of ${EXPORT_FORMATS.join(', ')}; got ${value ? `"${value}"` : 'nothing'}`
  );
}

/**
 * Produce the export bytes for a loaded bundle.
 *
 * Pure: the same bundle and key always produce the same bytes.
 *
 * @param bundle - The loaded bundle.
 * @param format - The target format.
 * @param keyPair - The signing key, required for the two signed formats.
 * @returns The bytes to write.
 * @throws Error when a signed format is asked for without a key.
 */
export function renderExport(
  bundle: LoadedBundle,
  format: ExportFormat,
  keyPair: Ed25519KeyPair | null
): Buffer {
  if (format === 'aat') {
    return Buffer.from(exportAat(bundle), 'utf-8');
  }
  if (!keyPair) {
    throw new Error(`--format ${format} signs its output and needs a key; pass --key-dir or run where the default key store is readable`);
  }
  if (format === 'asqav-receipt') {
    return Buffer.from(exportAsqavReceipts(bundle, keyPair), 'utf-8');
  }
  return Buffer.from(exportScittStatement(bundle, keyPair));
}

/**
 * Run `depose export`.
 *
 * @param bundlePath - The bundle directory.
 * @param args - Parsed flags.
 */
export async function handleExport(bundlePath: string, args: ExportCommandArgs): Promise<void> {
  const format = parseFormat(args.format as string | undefined);
  const dir = resolve(bundlePath);
  if (!existsSync(dir)) {
    console.error(`ERROR: bundle not found: ${dir}`);
    process.exit(1);
  }

  const bundle = loadBundle(dir);
  const keyPair = format === 'aat' ? null : resolveKey(bundle, args);

  const outPath = args.out
    ? resolve(args.out as string)
    : join(resolve(dir, '..'), `${bundle.manifest.bundleId}${DEFAULT_SUFFIX[format]}`);

  writeFileSync(outPath, renderExport(bundle, format, keyPair));
  console.log(`Wrote ${format} export: ${outPath}`);
  if (format !== 'aat') {
    console.log('Signed with the local Ed25519 key. Field mappings and their limits: docs/export-mapping.md');
  }
}

/**
 * Load the signing key and refuse to sign an export with a key that did
 * not seal the bundle.
 *
 * An export signed by a different key is a new claim by a new party. That
 * may be what someone wants, but it must be asked for, not defaulted into.
 */
function resolveKey(bundle: LoadedBundle, args: ExportCommandArgs): Ed25519KeyPair {
  const keyPair = loadOrGenerateKeyPair(args['key-dir'] as string | undefined);
  const sealed = bundle.manifest.producer.keyFingerprint;
  if (!sealed || args['allow-key-mismatch'] === true) {
    return keyPair;
  }
  const local = fingerprintPublicKeyPem(keyPair.publicKeyPem);
  if (local !== sealed) {
    console.error(
      `ERROR: this bundle was sealed by key ${sealed.slice(0, 16)}... and the local key is ${local.slice(0, 16)}...\n` +
        `A signed export asserts the sealing producer's identity. Point --key-dir at the sealing key, ` +
        `or pass --allow-key-mismatch to sign as a different party on purpose.`
    );
    process.exit(1);
  }
  return keyPair;
}
