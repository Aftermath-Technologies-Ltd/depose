// packages/bundle/test/export-fixture.ts
//
// Seals the two example incidents with a fixed key, a fixed clock, and a
// fixed ULID seed so the export goldens are reproducible. Ed25519
// signatures are deterministic (RFC 8032 §5.1.6), so a byte-for-byte
// comparison against a checked-in file is a real assertion, not a flaky
// one. Without the seed the event ids differ per run and every golden
// would have to be regenerated on every commit.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  normalizeClaudeCodeJsonl,
  mergeEvents,
  loadRuleset,
  setFixedUlidSeed,
  clearFixedUlidSeed,
  type Event,
} from '@depose/core';
import type { Ed25519KeyPair } from '@depose/chain';
import { writeBundle, loadBundle, type LoadedBundle } from '../src/index.js';

/**
 * A fixed Ed25519 key, generated once for these tests and committed on
 * purpose. It signs nothing outside the test tree.
 */
export const EXPORT_TEST_KEY: Ed25519KeyPair = {
  privateKeyPem:
    '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKSuAOltd5oo8B7ws/l/n6QiCX+prAH0aWthOp/OlqCb\n-----END PRIVATE KEY-----\n',
  publicKeyPem:
    '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAzUORbHgTVQ4puLb/2ZqWSWcGLKUryxoRustfML5+HUQ=\n-----END PUBLIC KEY-----\n',
};

/** The two example incidents the goldens cover. */
export const EXPORT_EXAMPLES = ['datatalks-reconstruction', 'pocketos-reconstruction'] as const;

const rulesPath = join(__dirname, '../../cli/rules/destructive.default.yaml');
const examplesDir = join(__dirname, '../../../examples');

/** Where the checked-in golden exports live. */
export const GOLDEN_EXPORT_DIR = join(__dirname, 'golden-exports');

/** Fixed ULID seed for the export fixtures. */
const ULID_SEED = Date.UTC(2025, 4, 18, 15, 30, 0);

/**
 * Seal one example incident into a bundle and load it back.
 *
 * @param example - The example directory name.
 * @param outputRoot - Where to write the bundle.
 * @returns The loaded bundle, ready for an exporter.
 */
export async function sealExample(example: string, outputRoot: string): Promise<LoadedBundle> {
  setFixedUlidSeed(ULID_SEED);
  try {
    return await seal(example, outputRoot);
  } finally {
    clearFixedUlidSeed();
  }
}

async function seal(example: string, outputRoot: string): Promise<LoadedBundle> {
  const ruleset = loadRuleset(rulesPath);
  const { depopPath } = await writeBundle(eventsFromExample(example), ruleset.rules, {
    sessionId: `export-${example}`,
    agentId: 'claude-code',
    version: '0.1.0',
    producedAt: '2025-05-18T16:00:00.000Z',
    sessionStartedAt: '2025-05-18T15:30:00.000Z',
    sessionEndedAt: '2025-05-18T15:31:00.000Z',
    rules: ruleset.rules,
    rulesetBytes: readFileSync(rulesPath),
    outputDir: outputRoot,
    keyPair: EXPORT_TEST_KEY,
    mode: 'signed',
    disclosable: ruleset.disclosable,
    // A fixed token stands in for a live TSA call so the bundle is
    // reproducible. The exports carry it across verbatim; nothing here
    // claims it verifies.
    injectedTimestamps: [
      {
        tsa: 'test-tsa',
        timestamp: '2025-05-18T16:00:30.000Z',
        tokenBase64: Buffer.from('depose-export-golden-token').toString('base64'),
      },
    ],
  });
  return loadBundle(depopPath);
}

function eventsFromExample(example: string): Event[] {
  const jsonl = readFileSync(join(examplesDir, example, 'session.synthetic.jsonl'), 'utf-8');
  const { events, sessionId } = normalizeClaudeCodeJsonl(jsonl);
  return mergeEvents({ claudeCodeEvents: events }, { sessionId }).events;
}
