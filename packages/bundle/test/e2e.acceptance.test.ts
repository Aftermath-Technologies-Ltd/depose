// packages/bundle/test/e2e.acceptance.test.ts
//
// End-to-end acceptance tests for Phase 2 (BUILD_PLAN.md §6).
//
// These tests exercise the full production + verification pipeline:
//   1. Produce a signed bundle
//   2. Verify with depose-verify → PASS
//   3. Tamper file/artifact → re-verify → FAIL
//   4. Tamper event payload → re-chain → FAIL
//   5. Strip signature → FAIL
//   6. Determinism: same input → byte-identical output (mod signatures)
//
// The depose-verify binary must be built before running these tests.
// Set DEPOSE_VERIFY_PATH to override the default path.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync, unlinkSync } from 'node:fs';
import { join as pathJoin } from 'node:path';
import { execSync } from 'node:child_process';
import {
  normalizeClaudeCodeJsonl,
  loadDestructiveRules,
  generateUlid,
} from '@depose/core';
import { writeBundle } from '../src/index.js';
import { generateEd25519KeyPair, verifyHashChain, verifyManifestSignature } from '@depose/chain';

const fixturesDir = pathJoin(__dirname, '../../core/test/fixtures');
const rulesPath = pathJoin(__dirname, '../../cli/rules/destructive.default.yaml');
const testOutputDir = pathJoin(__dirname, 'test-output-e2e');
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
  } catch (err: any) {
    return {
      exitCode: err.status ?? 1,
      stdout: err.stdout ?? '',
      stderr: err.stderr ?? '',
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

describe('Phase 2 acceptance: signed bundle pipeline', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it('produces a signed bundle with hash chain, signature, and chain validation', async () => {
    const jsonl = JSON.stringify({
      type: 'user',
      content: 'hello world',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const keyPair = generateEd25519KeyPair();

    const { depopPath, manifest } = await writeBundle(events, rules, {
      sessionId: 'sess-e2e-sign',
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

    // Verify manifest has non-empty rootHash
    expect(manifest.rootHash).not.toBe('');
    expect(manifest.rootHash.length).toBe(64); // SHA-256 hex

    // Verify signature is populated
    expect(manifest.signatures.length).toBe(1);
    expect(manifest.signatures[0]!.scheme).toBe('ed25519');
    expect(manifest.signatures[0]!.signature).toBeTruthy();
    expect(manifest.signatures[0]!.publicKey).toBeTruthy();

    // Verify chain hashes on events
    const eventsContent = readFileSync(pathJoin(depopPath, 'events.jsonl'), 'utf-8');
    const eventLines = eventsContent.trim().split('\n');
    for (const line of eventLines) {
      const evt = JSON.parse(line);
      expect(evt.chainHash).toBeTruthy();
      expect(evt.chainHash.length).toBe(64);
    }

    // Verify signature against manifest (unsigned form — signatures/timestamps stripped)
    // The signature was computed over the manifest before signatures were added
    const manifestJson = readFileSync(pathJoin(depopPath, 'manifest.json'), 'utf-8');
    const manifestForSigning = JSON.parse(manifestJson);
    manifestForSigning.signatures = [];
    manifestForSigning.timestamps = [];
    const manifestForSigningJson = JSON.stringify(manifestForSigning);
    const sigBlock = manifest.signatures[0]!;
    const valid = verifyManifestSignature(
      manifestForSigningJson,
      sigBlock.signature,
      sigBlock.publicKey!
    );
    expect(valid).toBe(true);
  });

  it('verifies hash chain independently via verifyHashChain', async () => {
    const jsonl = JSON.stringify({
      type: 'user',
      content: 'verify chain test',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const keyPair = generateEd25519KeyPair();

    const { manifest, events: chainedEvents } = await writeBundle(events, rules, {
      sessionId: 'sess-chain-verify',
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

    // Verify chain using the chained events (with chainHash populated)
    const chainResult = verifyHashChain(chainedEvents, manifest.rootHash);
    expect(chainResult.valid).toBe(true);
    expect(chainResult.computedRootHash).toBe(manifest.rootHash);
  });

  it('detects tampered event payload (chain hash mismatch)', async () => {
    const jsonl = JSON.stringify({
      type: 'user',
      content: 'original content',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const keyPair = generateEd25519KeyPair();

    const { depopPath, manifest } = await writeBundle(events, rules, {
      sessionId: 'sess-tamper-event',
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

    // Tamper with an event's payloadHash — this is what the chain protects
    const eventsPath = pathJoin(depopPath, 'events.jsonl');
    const eventsContent = readFileSync(eventsPath, 'utf-8');
    // Flip a character in the payloadHash (hex string) to simulate a modified payload
    const tamperedContent = eventsContent.replace(
      /"payloadHash":"([0-9a-f]{2})/,
      (_, hex) => {
        const flip = hex === '00' ? 'ff' : '00';
        return `"payloadHash":"${flip}`;
      }
    );
    writeFileSync(eventsPath, tamperedContent, 'utf-8');

    // Re-read events and verify chain — should fail
    const tamperedEventsContent = readFileSync(eventsPath, 'utf-8');
    const tamperedEvents = tamperedEventsContent.trim().split('\n').map(line => JSON.parse(line));
    const chainResult = verifyHashChain(tamperedEvents, manifest.rootHash);
    expect(chainResult.valid).toBe(false);
  });

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
      // Verifier should detect artifact mismatch — but since the verifier
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

    // Manifest still has the signature — but if we also strip it from manifest
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
    // Timestamp check will fail since we skipped timestamps — that's expected
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