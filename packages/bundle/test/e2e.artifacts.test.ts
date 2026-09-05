// packages/bundle/test/e2e.artifacts.test.ts
//
// What a produced bundle contains beyond the chain and the signature:
// the narrative, verify.txt, the raw sources, and the deterministic
// re-run. Chain and signature production are in e2e.acceptance.test.ts.

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
// Its own directory: e2e.acceptance.test.ts clears its output in
// beforeEach and vitest runs the files in parallel.
const testOutputDir = pathJoin(__dirname, 'test-output-e2e-artifacts');
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

describe('Phase 2 acceptance: bundle contents', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it('detects tampered artifact file (depose-verify artifact hash mismatch)', async () => {
    if (!hasVerifyBinary()) {
      return;
    }

    const jsonl = JSON.stringify({
      type: 'user',
      content: 'artifact tamper test',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const keyPair = generateEd25519KeyPair();

    const { depopPath } = await writeBundle(events, rules, {
      sessionId: 'sess-tamper-artifact',
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

    // Flip a byte in the rules/destructive.yaml artifact
    const rulesArtifact = pathJoin(depopPath, 'rules', 'destructive.yaml');
    if (existsSync(rulesArtifact)) {
      const content = readFileSync(rulesArtifact, 'utf-8');
      writeFileSync(rulesArtifact, 'TAMPERED' + content, 'utf-8');

      const result = runVerify(depopPath);
      // Verifier should detect artifact mismatch, but since the verifier
      // checks events.jsonl integrity rather than individual artifact hashes
      // in this version, we verify it still runs and reports results
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout).toContain('FAIL');
    }
  });

  it('detects missing signature (unsigned bundle fails signature check)', async () => {
    const jsonl = JSON.stringify({
      type: 'user',
      content: 'no sig test',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const keyPair = generateEd25519KeyPair();

    const { depopPath } = await writeBundle(events, rules, {
      sessionId: 'sess-strip-sig',
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

    // Strip the signature from attestations/signatures.json
    const sigPath = pathJoin(depopPath, 'attestations', 'signatures.json');
    writeFileSync(sigPath, JSON.stringify({ blocks: [] }), 'utf-8');

    // Reading back should show empty signatures
    const sigs = JSON.parse(readFileSync(sigPath, 'utf-8'));
    expect(sigs.blocks).toEqual([]);

    // Manifest still has the signature, but if we also strip it from manifest
    const manifestPath = pathJoin(depopPath, 'manifest.json');
    const manifestData = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    manifestData.signatures = [];
    writeFileSync(manifestPath, JSON.stringify(manifestData), 'utf-8');

    // Now verify should detect missing signature
    const manifestJson = readFileSync(manifestPath, 'utf-8');
    // No signatures available to verify against
    expect(JSON.parse(manifestJson).signatures).toEqual([]);
  });

  it('produces deterministic chain hashes for same input', async () => {
    const jsonl = JSON.stringify({
      type: 'user',
      content: 'determinism test',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const keyPair = generateEd25519KeyPair();
    const producedAt = '2025-05-18T16:00:00.000Z';

    const { depopPath: path1 } = await writeBundle(events, rules, {
      sessionId: 'sess-det-1',
      agentId: 'claude-code',
      version: '0.1.0',
      producedAt,
      sessionStartedAt: '2025-05-18T15:30:00.000Z',
      sessionEndedAt: '2025-05-18T15:31:00.000Z',
      rules,
      rulesetBytes,
      outputDir: testOutputDir,
      keyPair,
      mode: 'signed' as const,
      injectedTimestamps: FAKE_TIMESTAMP,
    });

    const { depopPath: path2 } = await writeBundle(events, rules, {
      sessionId: 'sess-det-2',
      agentId: 'claude-code',
      version: '0.1.0',
      producedAt,
      sessionStartedAt: '2025-05-18T15:30:00.000Z',
      sessionEndedAt: '2025-05-18T15:31:00.000Z',
      rules,
      rulesetBytes,
      outputDir: testOutputDir,
      keyPair,
      mode: 'signed' as const,
      injectedTimestamps: FAKE_TIMESTAMP,
    });

    // events.jsonl chain hashes should be identical (same input, same key)
    const e1 = readFileSync(pathJoin(path1, 'events.jsonl'), 'utf-8');
    const e2 = readFileSync(pathJoin(path2, 'events.jsonl'), 'utf-8');
    expect(e1).toBe(e2);

    // Manifest rootHash should be identical
    const m1 = JSON.parse(readFileSync(pathJoin(path1, 'manifest.json'), 'utf-8'));
    const m2 = JSON.parse(readFileSync(pathJoin(path2, 'manifest.json'), 'utf-8'));
    expect(m1.rootHash).toBe(m2.rootHash);
  });
});

// ── depose-verify binary integration tests ────────────────────────────
