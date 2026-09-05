// packages/bundle/src/export/read-bundle.ts
//
// Loads a sealed bundle into the shape every exporter works from.
//
// Exporters are pure: this reads the directory once, and everything after
// it is a function from the loaded bundle to bytes. Nothing here verifies
// the bundle; `depose-verify` does that, and an exporter that quietly
// re-verified would give a second, weaker opinion on the same question.

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseEventLine, type Event } from '@depose/core';
import type { Manifest } from '../manifest.js';

/** A sealed bundle, read into memory. */
export interface LoadedBundle {
  /** The directory it was read from. */
  path: string;
  manifest: Manifest;
  /** The literal manifest.json bytes, which the signature covers. */
  manifestBytes: Buffer;
  /** Events in file order, which is ascending id order. */
  events: Event[];
  /** The destructive ruleset the bundle was built with, or null. */
  rulesetBytes: Buffer | null;
}

/**
 * Read a sealed bundle directory.
 *
 * @param bundleDir - Path to the bundle.
 * @returns The manifest, its literal bytes, the events, and the ruleset.
 * @throws Error naming the missing file when the directory is not a bundle.
 */
export function loadBundle(bundleDir: string): LoadedBundle {
  const manifestPath = join(bundleDir, 'manifest.json');
  if (!existsSync(manifestPath)) {
    throw new Error(
      `${bundleDir} has no manifest.json, so it is not a DEPOSE bundle; ` +
        `point export at the incident-<bundleId> directory that depose record wrote`
    );
  }
  const manifestBytes = readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes.toString('utf-8')) as Manifest;

  const eventsPath = join(bundleDir, 'events.jsonl');
  if (!existsSync(eventsPath)) {
    throw new Error(`${bundleDir} has a manifest but no events.jsonl; the bundle is incomplete`);
  }
  const events = readFileSync(eventsPath, 'utf-8')
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => parseEventLine(line));

  const rulesPath = join(bundleDir, 'rules', 'destructive.yaml');
  const rulesetBytes = existsSync(rulesPath) ? readFileSync(rulesPath) : null;

  return { path: bundleDir, manifest, manifestBytes, events, rulesetBytes };
}

/**
 * The base64 RFC 3161 tokens the bundle carries, in manifest order.
 *
 * @param bundle - The loaded bundle.
 * @returns One entry per token, with the TSA that issued it.
 */
export function timestampTokens(bundle: LoadedBundle): Array<{ tsa: string; timestamp: string; tokenBase64: string }> {
  return (bundle.manifest.timestamps ?? []).map((token) => ({
    tsa: token.tsa,
    timestamp: token.timestamp,
    tokenBase64: token.tokenBase64,
  }));
}
