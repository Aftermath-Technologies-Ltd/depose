// packages/bundle/test/anchor.test.ts
//
// Sealing when no timestamp authority answers, and anchoring afterwards.
//
// The property that matters: `depose anchor` must not disturb the seal.
// manifest.json is compared byte for byte before and after, and the
// bundle is run through the real Go verifier at both points.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { loadRuleset, normalizeClaudeCodeJsonl, mergeEvents, sha256String, type Event } from '@depose/core';
import { generateEd25519KeyPair, type TsaEndpoint, type Ed25519KeyPair } from '@depose/chain';
import { writeBundle } from '../src/writer.js';
import { serializeManifestForSigning } from '../src/manifest-io.js';
import { anchorBundle, verifyAnchorCountersignature, countersign, ANCHOR_PATH } from '../src/anchor.js';
import type { Manifest } from '../src/manifest.js';
import { EXPORT_EXAMPLES } from './export-fixture.js';

const outputRoot = join(__dirname, 'test-output-anchor');
const rulesPath = join(__dirname, '../../cli/rules/destructive.default.yaml');
const examplesDir = join(__dirname, '../../../examples');
const verifyBinary = process.env.DEPOSE_VERIFY_PATH || join(__dirname, '../../../apps/verify/build/depose-verify');

/** An endpoint that cannot resolve, so every attempt fails fast. */
const DEAD_TSA: TsaEndpoint[] = [
  { name: 'unreachable', url: 'http://127.0.0.1:1/tsr', contentType: 'application/timestamp-query' },
];

const FAKE_TOKEN = {
  tsa: 'test-tsa',
  timestamp: '2025-05-18T18:00:00.000Z',
  tokenBase64: Buffer.from('anchor-token-bytes').toString('base64'),
};

let keyPair: Ed25519KeyPair;

beforeEach(() => {
  rmSync(outputRoot, { recursive: true, force: true });
  mkdirSync(outputRoot, { recursive: true });
  keyPair = generateEd25519KeyPair();
});

afterEach(() => {
  rmSync(outputRoot, { recursive: true, force: true });
});

async function sealPending(): Promise<string> {
  const ruleset = loadRuleset(rulesPath);
  const jsonl = readFileSync(join(examplesDir, EXPORT_EXAMPLES[1], 'session.synthetic.jsonl'), 'utf-8');
  const { events, sessionId } = normalizeClaudeCodeJsonl(jsonl);
  const merged: Event[] = mergeEvents({ claudeCodeEvents: events }, { sessionId }).events;

  const { depopPath } = await writeBundle(merged, ruleset.rules, {
    sessionId: 'pending-anchor',
    agentId: 'claude-code',
    version: '0.1.0',
    producedAt: '2025-05-18T16:00:00.000Z',
    sessionStartedAt: '2025-05-18T15:30:00.000Z',
    sessionEndedAt: '2025-05-18T15:31:00.000Z',
    rules: ruleset.rules,
    rulesetBytes: readFileSync(rulesPath),
    outputDir: outputRoot,
    keyPair,
    mode: 'signed',
    disclosable: ruleset.disclosable,
    tsaEndpoints: DEAD_TSA,
  });
  return depopPath;
}

function readManifest(dir: string): Manifest {
  return JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf-8')) as Manifest;
}

function verify(dir: string): { exitCode: number; stdout: string } {
  try {
    return { exitCode: 0, stdout: execFileSync(verifyBinary, ['verify', dir], { encoding: 'utf-8' }) };
  } catch (err) {
    const e = err as { status?: number; stdout?: string };
    return { exitCode: e.status ?? 1, stdout: e.stdout ?? '' };
  }
}

function statusOf(stdout: string, check: string): string | null {
  const m = stdout.match(new RegExp(`\\] ${check}: (\\w+)`));
  return m ? m[1]! : null;
}

describe('sealing when no timestamp authority answers', () => {
  it('produces a signed bundle rather than nothing, and says it is unanchored', async () => {
    const dir = await sealPending();
    const manifest = readManifest(dir);

    expect(manifest.producer.mode).toBe('signed');
    expect(manifest.signatures).toHaveLength(1);
    expect(manifest.timestamps).toHaveLength(0);
    expect(manifest.anchorStatus).toBe('pending');
  });

  it('fails closed instead when the producer asked for an anchor', async () => {
    const ruleset = loadRuleset(rulesPath);
    await expect(
      writeBundle([], ruleset.rules, {
        sessionId: 'require-anchor',
        agentId: 'claude-code',
        version: '0.1.0',
        producedAt: '2025-05-18T16:00:00.000Z',
        sessionStartedAt: '2025-05-18T15:30:00.000Z',
        sessionEndedAt: '2025-05-18T15:31:00.000Z',
        rules: ruleset.rules,
        rulesetBytes: readFileSync(rulesPath),
        outputDir: outputRoot,
        keyPair,
        mode: 'signed',
        tsaEndpoints: DEAD_TSA,
        requireAnchor: true,
      })
    ).rejects.toThrow(/--require-anchor/);
  });

  it('verifies, with the missing anchor reported as a downgrade and not a failure', async () => {
    if (!existsSync(verifyBinary)) return;
    const { exitCode, stdout } = verify(await sealPending());

    expect(exitCode).toBe(0);
    expect(statusOf(stdout, 'mode-contract')).toBe('PASS');
    expect(statusOf(stdout, 'signature-verify')).toBe('PASS');
    expect(statusOf(stdout, 'anchor-status')).toBe('WARN');
    expect(stdout).toContain('never anchored');
    expect(statusOf(stdout, 'timestamp-verify')).toBe('SKIPPED');
  });
});

describe('anchoring afterwards', () => {
  it('leaves manifest.json byte-identical, so the original seal still verifies', async () => {
    const dir = await sealPending();
    const before = readFileSync(join(dir, 'manifest.json'));

    await anchorBundle(dir, {
      keyPair,
      injectedTimestamps: [FAKE_TOKEN],
      now: () => new Date('2025-05-18T18:00:05.000Z'),
    });

    expect(readFileSync(join(dir, 'manifest.json')).equals(before)).toBe(true);
    expect(existsSync(join(dir, ANCHOR_PATH))).toBe(true);
  });

  it('countersigns the anchor with the sealing key', async () => {
    const dir = await sealPending();
    const { document } = await anchorBundle(dir, { keyPair, injectedTimestamps: [FAKE_TOKEN] });

    expect(document.countersignature.scheme).toBe('ed25519');
    expect(document.countersignature.publicKey).toBe(keyPair.publicKeyPem);
    expect(verifyAnchorCountersignature(document)).toBe(true);
  });

  it('binds the anchor to this manifest, not to any other', async () => {
    const dir = await sealPending();
    const { document } = await anchorBundle(dir, { keyPair, injectedTimestamps: [FAKE_TOKEN] });

    expect(document.manifestSha256).toBe(sha256String(serializeManifestForSigning(readManifest(dir))));
    expect(document.bundleId).toBe(readManifest(dir).bundleId);
  });

  it('writes the token bytes where the document says they are', async () => {
    const dir = await sealPending();
    const { document } = await anchorBundle(dir, { keyPair, injectedTimestamps: [FAKE_TOKEN] });
    const token = document.timestamps[0]!;

    expect(readFileSync(join(dir, token.file)).toString('base64')).toBe(FAKE_TOKEN.tokenBase64);
  });

  it('refuses a key that did not seal the bundle', async () => {
    const dir = await sealPending();
    await expect(
      anchorBundle(dir, { keyPair: generateEd25519KeyPair(), injectedTimestamps: [FAKE_TOKEN] })
    ).rejects.toThrow(/sealing key/);
  });

  it('refuses a dev-unsigned bundle, which has no signature to date', async () => {
    const ruleset = loadRuleset(rulesPath);
    const { depopPath } = await writeBundle([], ruleset.rules, {
      sessionId: 'dev',
      agentId: 'claude-code',
      version: '0.1.0',
      producedAt: '2025-05-18T16:00:00.000Z',
      sessionStartedAt: '2025-05-18T15:30:00.000Z',
      sessionEndedAt: '2025-05-18T15:31:00.000Z',
      rules: ruleset.rules,
      rulesetBytes: readFileSync(rulesPath),
      outputDir: outputRoot,
      mode: 'dev-unsigned',
    });
    await expect(anchorBundle(depopPath, { keyPair, injectedTimestamps: [FAKE_TOKEN] })).rejects.toThrow(
      /has none/
    );
  });

  it('does nothing on a second run unless forced', async () => {
    const dir = await sealPending();
    await anchorBundle(dir, { keyPair, injectedTimestamps: [FAKE_TOKEN] });
    const again = await anchorBundle(dir, { keyPair, injectedTimestamps: [FAKE_TOKEN] });

    expect(again.obtained).toBe(false);
  });

  it('reports the failure and leaves the bundle alone when no authority answers', async () => {
    const dir = await sealPending();
    await expect(anchorBundle(dir, { keyPair, tsaEndpoints: DEAD_TSA })).rejects.toThrow(/still unanchored/);
    expect(existsSync(join(dir, ANCHOR_PATH))).toBe(false);
  });
});

describe('the verifier on an anchored bundle', () => {
  it('reports the seal time and the anchor time separately', async () => {
    if (!existsSync(verifyBinary)) return;
    const dir = await sealPending();
    await anchorBundle(dir, {
      keyPair,
      injectedTimestamps: [FAKE_TOKEN],
      now: () => new Date('2025-05-18T18:00:05.000Z'),
    });

    const { stdout } = verify(dir);
    expect(statusOf(stdout, 'signature-verify')).toBe('PASS');
    expect(statusOf(stdout, 'anchor-status')).toBe('PASS');
    expect(stdout).toContain('sealed 2025-05-18T16:00:00.000Z pending an anchor');
    expect(stdout).toContain('anchored 2025-05-18T18:00:00.000Z');
    // The injected token is not a real TSR, so only the token check fails.
    expect(statusOf(stdout, 'timestamp-verify')).toBe('FAIL');
  });

  it('fails when the countersignature was made by someone else', async () => {
    if (!existsSync(verifyBinary)) return;
    const dir = await sealPending();
    const { document } = await anchorBundle(dir, { keyPair, injectedTimestamps: [FAKE_TOKEN] });
    const impostor = generateEd25519KeyPair();
    const { countersignature: _replaced, ...claim } = document;
    writeFileSync(
      join(dir, ANCHOR_PATH),
      JSON.stringify({ ...claim, countersignature: countersign(claim, impostor) }, null, 2) + '\n'
    );

    const { stdout } = verify(dir);
    expect(statusOf(stdout, 'anchor-status')).toBe('FAIL');
    expect(stdout).toContain('different key');
  });

  it('fails when the anchor claim was edited after countersigning', async () => {
    if (!existsSync(verifyBinary)) return;
    const dir = await sealPending();
    const { document } = await anchorBundle(dir, { keyPair, injectedTimestamps: [FAKE_TOKEN] });
    writeFileSync(
      join(dir, ANCHOR_PATH),
      JSON.stringify({ ...document, anchoredAt: '2019-01-01T00:00:00.000Z' }, null, 2) + '\n'
    );

    const { stdout } = verify(dir);
    expect(statusOf(stdout, 'anchor-status')).toBe('FAIL');
    expect(stdout).toContain('countersignature INVALID');
  });

  it('fails when the anchor belongs to a different seal', async () => {
    if (!existsSync(verifyBinary)) return;
    const dir = await sealPending();
    const { document } = await anchorBundle(dir, { keyPair, injectedTimestamps: [FAKE_TOKEN] });
    const { countersignature: _replaced, ...claim } = document;
    const moved = { ...claim, manifestSha256: 'f'.repeat(64) };
    writeFileSync(
      join(dir, ANCHOR_PATH),
      JSON.stringify({ ...moved, countersignature: countersign(moved, keyPair) }, null, 2) + '\n'
    );

    const { stdout } = verify(dir);
    expect(statusOf(stdout, 'anchor-status')).toBe('FAIL');
    expect(stdout).toContain('belongs to a different seal');
  });

  it('fails when a token file the anchor names was swapped', async () => {
    if (!existsSync(verifyBinary)) return;
    const dir = await sealPending();
    const { document } = await anchorBundle(dir, { keyPair, injectedTimestamps: [FAKE_TOKEN] });
    writeFileSync(join(dir, document.timestamps[0]!.file), Buffer.from('not the token'));

    const { stdout } = verify(dir);
    expect(statusOf(stdout, 'attestation-files')).toBe('FAIL');
    expect(stdout).toContain('does not match anchor.timestamps[0]');
  });
});
