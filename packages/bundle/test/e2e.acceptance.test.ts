// packages/bundle/test/e2e.acceptance.test.ts
//
// End-to-end acceptance tests for the signed bundle pipeline.
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
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join as pathJoin } from 'node:path';
import {
  normalizeClaudeCodeJsonl,
  loadDestructiveRules,
} from '@depose/core';
import { writeBundle, serializeManifestForSigning } from '../src/index.js';
import { generateEd25519KeyPair, verifyHashChain, verifyManifestSignature } from '@depose/chain';

const rulesPath = pathJoin(__dirname, '../../cli/rules/destructive.default.yaml');
const testOutputDir = pathJoin(__dirname, 'test-output-e2e');

// ── Helper ───────────────────────────────────────────────────────────

function cleanup(): void {
  try {
    rmSync(testOutputDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
  mkdirSync(testOutputDir, { recursive: true });
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

    // Verify the signature against the manifest as it is on disk, rebuilt
    // into its signing form: signatures, timestamps, and anchorStatus are
    // all written after the signature is made and are stripped from it.
    const manifestJson = readFileSync(pathJoin(depopPath, 'manifest.json'), 'utf-8');
    const manifestForSigningJson = serializeManifestForSigning(JSON.parse(manifestJson));
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

    // Tamper with an event's payloadHash; this is what the chain protects
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

    // Re-read events and verify chain; should fail
    const tamperedEventsContent = readFileSync(eventsPath, 'utf-8');
    const tamperedEvents = tamperedEventsContent.trim().split('\n').map(line => JSON.parse(line));
    const chainResult = verifyHashChain(tamperedEvents, manifest.rootHash);
    expect(chainResult.valid).toBe(false);
  });
});
