// packages/cli/src/commands/anchor.ts
//
// `depose anchor <bundle>`: get the RFC 3161 token for a bundle that was
// sealed while no timestamp authority could be reached.
//
// The manifest is not touched, so the original signature verifies exactly
// as it did before. The anchor goes into attestations/anchor.json with a
// countersignature by the same key, and the verifier reports the seal
// time and the anchor time separately.

import { resolve, join } from 'node:path';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { anchorBundle, serializeManifest, type Manifest } from '@depose/bundle';
import { loadOrGenerateKeyPair, type TsaEndpoint } from '@depose/chain';
import { loadRuleset, type RulesetTsa } from '@depose/core';

export interface AnchorCommandArgs {
  'key-dir'?: string;
  rules?: string;
  force?: boolean;
  [key: string]: string | boolean | string[] | undefined;
}

/**
 * Turn ruleset TSA entries into endpoints the chain package can use.
 *
 * @param configured - Entries from the ruleset's `tsa` list.
 * @returns Endpoints in the same order, or undefined when none are configured.
 */
export function tsaEndpointsFromRuleset(configured: RulesetTsa[]): TsaEndpoint[] | undefined {
  if (configured.length === 0) return undefined;
  return configured.map((tsa) => ({
    name: tsa.name,
    url: tsa.url,
    contentType: 'application/timestamp-query',
    ...(tsa.signerFingerprint ? { signerFingerprint: tsa.signerFingerprint } : {}),
  }));
}

/**
 * Run `depose anchor`.
 *
 * @param bundlePath - The sealed bundle directory.
 * @param args - Parsed flags.
 */
export async function handleAnchor(bundlePath: string, args: AnchorCommandArgs): Promise<void> {
  const dir = resolve(bundlePath);
  if (!existsSync(join(dir, 'manifest.json'))) {
    console.error(`ERROR: ${dir} has no manifest.json; point anchor at a sealed bundle directory`);
    process.exit(1);
  }

  const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf-8')) as Manifest;
  const keyPair = loadOrGenerateKeyPair(args['key-dir'] as string | undefined);
  const rulesPath = args.rules as string | undefined;
  const tsaEndpoints = rulesPath ? tsaEndpointsFromRuleset(loadRuleset(resolve(rulesPath)).tsa) : undefined;

  try {
    const result = await anchorBundle(dir, {
      keyPair,
      tsaEndpoints,
      force: args.force === true,
    });

    if (!result.obtained) {
      console.log(`Already anchored at ${result.document.anchoredAt}. Pass --force to add another anchor.`);
      return;
    }

    // The label in the manifest catches up with reality. It is outside
    // the signed form, so the original signature is unaffected.
    if (manifest.anchorStatus !== 'anchored') {
      manifest.anchorStatus = 'anchored';
      writeFileSync(join(dir, 'manifest.json'), serializeManifest(manifest), 'utf-8');
    }

    console.log(`Anchored ${manifest.bundleId} at ${result.document.anchoredAt}`);
    for (const token of result.document.timestamps) {
      console.log(`  ${token.tsa}: ${token.timestamp} (${token.file})`);
    }
    for (const error of result.errors) {
      console.error(`  warning: ${error}`);
    }
    console.log('The manifest signature is unchanged. Re-verify with: depose-verify verify ' + dir);
  } catch (err) {
    console.error(`ERROR: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
