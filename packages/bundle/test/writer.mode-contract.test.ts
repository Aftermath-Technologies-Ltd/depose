// Mode-contract acceptance tests for the producer + verifier.
//
// A3 introduced producer.mode ∈ {signed, dev-unsigned}. The verifier
// is the enforcement point. These tests build bundles in both modes
// and run depose-verify against them, asserting:
//   - signed → expect to see "PASS" (no parenthetical disclaimer).
//   - dev-unsigned → expect "PASS (dev-unsigned — not evidence)".
//   - dev-unsigned mutated to carry a signature → mode-contract fails.
//   - signed declared but signature stripped → mode-contract fails.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { join as pathJoin } from 'node:path';
import { normalizeClaudeCodeJsonl, loadDestructiveRules } from '@depose/core';
import { writeBundle } from '../src/index.js';
import { generateEd25519KeyPair } from '@depose/chain';

const rulesPath = pathJoin(__dirname, '../../cli/rules/destructive.default.yaml');
const testOutputDir = pathJoin(__dirname, 'test-output-mode-contract');
const verifyBinary = process.env.DEPOSE_VERIFY_PATH ||
  pathJoin(__dirname, '../../../apps/verify/build/depose-verify');

const FAKE_TIMESTAMP = [
  {
    tsa: 'test-tsa',
    timestamp: '2025-05-18T15:31:30.000Z',
    tokenBase64: Buffer.from('fake-token').toString('base64'),
  },
];

function cleanup(): void {
  try {
    rmSync(testOutputDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
  mkdirSync(testOutputDir, { recursive: true });
}

function hasVerifyBinary(): boolean {
  return existsSync(verifyBinary);
}

function runVerify(bundlePath: string): { exitCode: number; stdout: string } {
  try {
    const stdout = execSync(`${verifyBinary} verify ${bundlePath}`, {
      encoding: 'utf-8',
      timeout: 30000,
    });
    return { exitCode: 0, stdout };
  } catch (err: unknown) {
    const e = err as { status?: number; stdout?: string };
    return { exitCode: e.status ?? 1, stdout: e.stdout ?? '' };
  }
}

async function buildBundle(opts: {
  mode: 'signed' | 'dev-unsigned';
  sessionId: string;
  includeKey: boolean;
}): Promise<string> {
  const jsonl = JSON.stringify({
    type: 'user',
    content: `mode contract ${opts.sessionId}`,
    timestamp: '2025-05-18T15:30:00.000Z',
  });
  const { events } = normalizeClaudeCodeJsonl(jsonl);
  const rules = loadDestructiveRules(rulesPath);
  const rulesetBytes = readFileSync(rulesPath);
  const keyPair = opts.includeKey ? generateEd25519KeyPair() : undefined;

  const { depopPath } = await writeBundle(events, rules, {
    sessionId: opts.sessionId,
    agentId: 'claude-code',
    version: '0.1.0',
    producedAt: '2025-05-18T16:00:00.000Z',
    sessionStartedAt: '2025-05-18T15:30:00.000Z',
    sessionEndedAt: '2025-05-18T15:31:00.000Z',
    rules,
    rulesetBytes,
    outputDir: testOutputDir,
    mode: opts.mode,
    keyPair,
    injectedTimestamps: opts.mode === 'signed' ? FAKE_TIMESTAMP : undefined,
  });
  return depopPath;
}

describe('mode contract', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it('dev-unsigned bundle lands in incident-unsigned-<id> with banner', async () => {
    const depopPath = await buildBundle({
      mode: 'dev-unsigned',
      sessionId: 'sess-dm-banner',
      includeKey: false,
    });

    expect(depopPath).toContain('incident-unsigned-sess-dm-banner');

    const manifest = JSON.parse(readFileSync(pathJoin(depopPath, 'manifest.json'), 'utf-8'));
    expect(manifest.producer.mode).toBe('dev-unsigned');
    expect(manifest.signatures).toEqual([]);
    expect(manifest.timestamps).toEqual([]);

    const verifyTxt = readFileSync(pathJoin(depopPath, 'verify.txt'), 'utf-8');
    expect(verifyTxt).toMatch(/THIS IS A DEVELOPMENT BUNDLE — NOT EVIDENCE/);

    const narrativeMd = readFileSync(pathJoin(depopPath, 'narrative.md'), 'utf-8');
    expect(narrativeMd).toMatch(/THIS IS A DEVELOPMENT BUNDLE — NOT EVIDENCE/);
  });

  it('signed bundle lands in incident-<id> without banner', async () => {
    const depopPath = await buildBundle({
      mode: 'signed',
      sessionId: 'sess-mc-signed',
      includeKey: true,
    });

    expect(depopPath).toContain('incident-sess-mc-signed');
    expect(depopPath).not.toContain('incident-unsigned-');

    const manifest = JSON.parse(readFileSync(pathJoin(depopPath, 'manifest.json'), 'utf-8'));
    expect(manifest.producer.mode).toBe('signed');
    expect(manifest.signatures.length).toBeGreaterThan(0);
    expect(manifest.timestamps.length).toBeGreaterThan(0);

    const verifyTxt = readFileSync(pathJoin(depopPath, 'verify.txt'), 'utf-8');
    expect(verifyTxt).not.toMatch(/NOT EVIDENCE/);
  });

  it('signed mode without keyPair throws', async () => {
    await expect(
      buildBundle({ mode: 'signed', sessionId: 'sess-no-key', includeKey: false })
    ).rejects.toThrow(/mode="signed" requires a keyPair/);
  });

  it('verifier prints "PASS (dev-unsigned — not evidence)" for clean dev-unsigned', async () => {
    if (!hasVerifyBinary()) return;
    const depopPath = await buildBundle({
      mode: 'dev-unsigned',
      sessionId: 'sess-mc-dev-pass',
      includeKey: false,
    });
    const result = runVerify(depopPath);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('PASS (dev-unsigned — not evidence)');
    expect(result.stdout).not.toMatch(/RESULT: PASS\b\s*$/m);
  });

  it('verifier fails when a dev-unsigned bundle smuggles a signature', async () => {
    if (!hasVerifyBinary()) return;
    const depopPath = await buildBundle({
      mode: 'dev-unsigned',
      sessionId: 'sess-mc-smuggle',
      includeKey: false,
    });

    // Mutate manifest to inject a bogus signature block. The mode is
    // still "dev-unsigned" — that's the lie we want the verifier to
    // catch.
    const manifestPath = pathJoin(depopPath, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    manifest.signatures = [{
      scheme: 'ed25519',
      signature: Buffer.from('fake').toString('base64'),
      publicKey: '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n',
      signedFields: 'manifest.json',
    }];
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf-8');

    const result = runVerify(depopPath);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toContain('mode-contract');
    expect(result.stdout).toContain('FAIL');
  });

  it('verifier fails when a signed bundle has its timestamp stripped', async () => {
    if (!hasVerifyBinary()) return;
    const depopPath = await buildBundle({
      mode: 'signed',
      sessionId: 'sess-mc-strip-ts',
      includeKey: true,
    });

    const manifestPath = pathJoin(depopPath, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    manifest.timestamps = [];
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf-8');

    const result = runVerify(depopPath);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toContain('mode-contract');
    expect(result.stdout).toContain('FAIL');
  });

  it('verifier fails when producer.mode is missing', async () => {
    if (!hasVerifyBinary()) return;
    const depopPath = await buildBundle({
      mode: 'signed',
      sessionId: 'sess-mc-no-mode',
      includeKey: true,
    });

    const manifestPath = pathJoin(depopPath, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    delete manifest.producer.mode;
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf-8');

    const result = runVerify(depopPath);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toContain('mode-declaration');
  });

  it('verifier accepts the correct --expected-key-fingerprint (C4)', async () => {
    if (!hasVerifyBinary()) return;
    const depopPath = await buildBundle({
      mode: 'signed',
      sessionId: 'sess-mc-keypin-ok',
      includeKey: true,
    });

    const manifest = JSON.parse(readFileSync(pathJoin(depopPath, 'manifest.json'), 'utf-8'));
    const fp = manifest.producer.keyFingerprint;
    expect(fp).toMatch(/^[0-9a-f]{64}$/);

    const result = (() => {
      try {
        const stdout = execSync(`${verifyBinary} verify --expected-key-fingerprint ${fp} ${depopPath}`, {
          encoding: 'utf-8',
          timeout: 30000,
        });
        return { exitCode: 0, stdout };
      } catch (err: unknown) {
        const e = err as { status?: number; stdout?: string };
        return { exitCode: e.status ?? 1, stdout: e.stdout ?? '' };
      }
    })();
    expect(result.stdout).toContain('key-fingerprint-pin');
    expect(result.stdout).toContain('matches expectation');
  });

  it('verifier rejects a mismatched --expected-key-fingerprint (C4)', async () => {
    if (!hasVerifyBinary()) return;
    const depopPath = await buildBundle({
      mode: 'signed',
      sessionId: 'sess-mc-keypin-bad',
      includeKey: true,
    });

    const wrong = '0'.repeat(64);
    const result = (() => {
      try {
        const stdout = execSync(`${verifyBinary} verify --expected-key-fingerprint=${wrong} ${depopPath}`, {
          encoding: 'utf-8',
          timeout: 30000,
        });
        return { exitCode: 0, stdout };
      } catch (err: unknown) {
        const e = err as { status?: number; stdout?: string };
        return { exitCode: e.status ?? 1, stdout: e.stdout ?? '' };
      }
    })();
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toContain('key fingerprint mismatch');
  });

  it('verifier rejects an unsupported schemaVersion', async () => {
    if (!hasVerifyBinary()) return;
    const depopPath = await buildBundle({
      mode: 'dev-unsigned',
      sessionId: 'sess-mc-future-schema',
      includeKey: false,
    });

    const manifestPath = pathJoin(depopPath, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    manifest.schemaVersion = 999;
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf-8');

    const result = runVerify(depopPath);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toMatch(/unsupported schemaVersion 999/);
  });
});
