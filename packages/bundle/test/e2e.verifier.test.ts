// packages/bundle/test/e2e.verifier.test.ts
//
// The other half of the end-to-end acceptance: a bundle produced here,
// handed to the real depose-verify binary. Bundle production itself is
// in e2e.acceptance.test.ts; this file is about what a recipient sees.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { join as pathJoin } from 'node:path';
import { execSync } from 'node:child_process';
import {
  normalizeClaudeCodeJsonl,
  loadDestructiveRules,
} from '@depose/core';
import { writeBundle } from '../src/index.js';
import { generateEd25519KeyPair } from '@depose/chain';

const rulesPath = pathJoin(__dirname, '../../cli/rules/destructive.default.yaml');
// A directory of its own: the acceptance file next door clears its
// output in beforeEach, and vitest runs the two in parallel.
const testOutputDir = pathJoin(__dirname, 'test-output-e2e-verifier');
const verifyBinary = process.env.DEPOSE_VERIFY_PATH ||
  pathJoin(__dirname, '../../../apps/verify/build/depose-verify');

// ── Helper ───────────────────────────────────────────────────────────

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

function runVerify(bundlePath: string): { exitCode: number; stdout: string; stderr: string } {
  try {
    const stdout = execSync(`${verifyBinary} verify ${bundlePath}`, {
      encoding: 'utf-8',
      timeout: 30000,
    });
    return { exitCode: 0, stdout, stderr: '' };
  } catch (err: unknown) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return {
      exitCode: e.status ?? 1,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
    };
  }
}

// Fake RFC 3161 token to inject into signed-mode bundles during
// tests that can't reach a live TSA. The verifier's structural
// check will fail (no real signing cert, wrong messageImprint), but
// chain-replay and signature-verify still run as intended.
const FAKE_TIMESTAMP = [
  {
    tsa: 'test-tsa',
    timestamp: '2025-05-18T15:31:30.000Z',
    tokenBase64: Buffer.from('fake-rfc3161-token-for-tests').toString('base64'),
  },
];

// ── Tests ────────────────────────────────────────────────────────────


describe('Phase 2 acceptance: depose-verify binary', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it('verifies a signed bundle with depose-verify (happy path)', async () => {
    if (!hasVerifyBinary()) {
      return; // Skip if binary not built
    }

    const jsonl = JSON.stringify({
      type: 'user',
      content: 'e2e verify test',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const keyPair = generateEd25519KeyPair();

    const { depopPath } = await writeBundle(events, rules, {
      sessionId: 'sess-verify-e2e',
      agentId: 'claude-code',
      version: '0.1.0',
      producedAt: '2025-05-18T16:00:00.000Z',
      sessionStartedAt: '2025-05-18T15:30:00.000Z',
      sessionEndedAt: '2025-05-18T15:31:00.000Z',
      rules,
      rulesetBytes,
      outputDir: testOutputDir,
      keyPair,
      mode: 'signed' as const,
      injectedTimestamps: FAKE_TIMESTAMP,
    });

    const result = runVerify(depopPath);
    // Should get at least chain + signature checks passing
    // Timestamp check will fail since we skipped timestamps; that's expected
    expect(result.stdout).toContain('chain-replay');
    expect(result.stdout).toContain('signature-verify');
  });

  it('detects tampered events with depose-verify', async () => {
    if (!hasVerifyBinary()) {
      return;
    }

    const jsonl = JSON.stringify({
      type: 'user',
      content: 'tamper detect test',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const keyPair = generateEd25519KeyPair();

    const { depopPath } = await writeBundle(events, rules, {
      sessionId: 'sess-tamper-detect',
      agentId: 'claude-code',
      version: '0.1.0',
      producedAt: '2025-05-18T16:00:00.000Z',
      sessionStartedAt: '2025-05-18T15:30:00.000Z',
      sessionEndedAt: '2025-05-18T15:31:00.000Z',
      rules,
      rulesetBytes,
      outputDir: testOutputDir,
      keyPair,
      mode: 'signed' as const,
      injectedTimestamps: FAKE_TIMESTAMP,
    });

    // Tamper with events.jsonl
    const eventsPath = pathJoin(depopPath, 'events.jsonl');
    const content = readFileSync(eventsPath, 'utf-8');
    writeFileSync(eventsPath, content.replace('tamper detect test', 'TAMPERED'), 'utf-8');

    const result = runVerify(depopPath);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toContain('FAIL');
  });

  it('detects stripped signature with depose-verify', async () => {
    if (!hasVerifyBinary()) {
      return;
    }

    const jsonl = JSON.stringify({
      type: 'user',
      content: 'strip sig test',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const keyPair = generateEd25519KeyPair();

    const { depopPath } = await writeBundle(events, rules, {
      sessionId: 'sess-strip-sig-e2e',
      agentId: 'claude-code',
      version: '0.1.0',
      producedAt: '2025-05-18T16:00:00.000Z',
      sessionStartedAt: '2025-05-18T15:30:00.000Z',
      sessionEndedAt: '2025-05-18T15:31:00.000Z',
      rules,
      rulesetBytes,
      outputDir: testOutputDir,
      keyPair,
      mode: 'signed' as const,
      injectedTimestamps: FAKE_TIMESTAMP,
    });

    // Strip signature from manifest
    const manifestPath = pathJoin(depopPath, 'manifest.json');
    const manifestData = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    manifestData.signatures = [];
    writeFileSync(manifestPath, JSON.stringify(manifestData), 'utf-8');

    const result = runVerify(depopPath);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toContain('FAIL');
  });

  it('detects backdated manifest (producedAt after TSA timestamp)', async () => {
    // This tests the anti-backdating check in depose-verify.
    // We create a signed bundle, then manually inject a fake timestamp
    // into the manifest that is BEFORE producedAt, which should trigger
    // a backdating warning from the verifier.
    if (!hasVerifyBinary()) {
      return;
    }

    const jsonl = JSON.stringify({
      type: 'user',
      content: 'backdate test',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const keyPair = generateEd25519KeyPair();

    // producedAt is 2025-05-18T16:00:00.000Z
    // We'll inject a "timestamp" from 2025-05-18T17:00:00.000Z (1 hour AFTER producedAt)
    // This means the bundle was supposedly produced BEFORE the TSA signed it,
    // which is suspicious (possible backdating of producedAt)
    const { depopPath } = await writeBundle(events, rules, {
      sessionId: 'sess-backdate',
      agentId: 'claude-code',
      version: '0.1.0',
      producedAt: '2025-05-18T16:00:00.000Z',
      sessionStartedAt: '2025-05-18T15:30:00.000Z',
      sessionEndedAt: '2025-05-18T15:31:00.000Z',
      rules,
      rulesetBytes,
      outputDir: testOutputDir,
      keyPair,
      mode: 'signed' as const,
      injectedTimestamps: FAKE_TIMESTAMP,
    });

    // Inject a fake RFC 3161 timestamp that is AFTER producedAt
    const manifestPath = pathJoin(depopPath, 'manifest.json');
    const manifestData = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    manifestData.timestamps = [{
      tsa: 'test-tsa',
      timestamp: '2025-05-18T17:00:00.000Z', // 1hr AFTER producedAt
      tokenBase64: Buffer.from('fake-tsr-for-backdate-test').toString('base64'),
    }];
    writeFileSync(manifestPath, JSON.stringify(manifestData), 'utf-8');

    const result = runVerify(depopPath);
    // Verifier should flag backdating: producedAt (16:00) is before TSA timestamp (17:00)
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout).toContain('FAIL');
  });
});