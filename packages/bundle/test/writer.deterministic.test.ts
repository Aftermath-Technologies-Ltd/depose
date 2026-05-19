// packages/bundle/test/writer.deterministic.test.ts
//
// Tests for deterministic bundle writer.
// BUILD_PLAN.md §5: deterministic tar (fixed mtime, sorted entries).
//
// Tests exercise:
//   1. Bundle directory structure matches BUILD_PLAN.md §5
//   2. Manifest is correct (counts, metadata)
//   3. Events are written to events.jsonl (sorted by id)
//   4. Root hash is empty for unsigned mode
//   5. verify.txt is present and attorney-friendly
//   6. Determinism: same input produces same output (byte-identical)

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { join as pathJoin } from 'node:path';
import {
  normalizeClaudeCodeJsonl,
  loadDestructiveRules,
} from '@depose/core';
import { writeBundle, type Manifest } from '../src/index.js';

const rulesPath = pathJoin(__dirname, '../../cli/rules/destructive.default.yaml');
const testOutputDir = pathJoin(__dirname, 'test-output');

// ── Helper ───────────────────────────────────────────────────────────

function cleanup(): void {
  try {
    rmSync(testOutputDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
  mkdirSync(testOutputDir, { recursive: true });
}

// ── Tests ────────────────────────────────────────────────────────────

describe('writeBundle (unsigned mode)', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  describe('directory structure', () => {
    it('creates correct directory layout (BUILD_PLAN.md §5)', async () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const rules = loadDestructiveRules(rulesPath);
      const rulesetBytes = readFileSync(rulesPath);
      const { depopPath } = await writeBundle(events, rules, {
        sessionId: 'sess-test',
        agentId: 'claude-code',
        version: '0.1.0',
        producedAt: '2025-05-18T16:00:00.000Z',
        sessionStartedAt: '2025-05-18T15:30:00.000Z',
        sessionEndedAt: '2025-05-18T15:31:00.000Z',
        rules,
        rulesetBytes,
        outputDir: testOutputDir,
        unsigned: true,
      });

      // Check directory exists
      expect(existsSync(depopPath)).toBe(true);

      // Check required files
      expect(existsSync(pathJoin(depopPath, 'manifest.json'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'events.jsonl'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'raw', 'claude-code'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'raw', 'shell-history'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'raw', 'git-reflog.txt'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'raw', 'capture'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'artifacts', 'files-pre'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'artifacts', 'files-post'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'attestations', 'signatures.json'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'attestations', 'rfc3161-timestamps'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'attestations', 'rekor-entries.json'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'rules', 'destructive.yaml'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'narrative.md'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'narrative.html'))).toBe(true);
      expect(existsSync(pathJoin(depopPath, 'verify.txt'))).toBe(true);
    });
  });

  describe('manifest', () => {
    it('produces correct manifest (counts, metadata)', async () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const rules = loadDestructiveRules(rulesPath);
      const rulesetBytes = readFileSync(rulesPath);
      const { manifest } = await writeBundle(events, rules, {
        sessionId: 'sess-test',
        agentId: 'claude-code',
        version: '0.1.0',
        producedAt: '2025-05-18T16:00:00.000Z',
        sessionStartedAt: '2025-05-18T15:30:00.000Z',
        sessionEndedAt: '2025-05-18T15:31:00.000Z',
        rules,
        rulesetBytes,
        outputDir: testOutputDir,
        unsigned: true,
      });

      expect(manifest.schemaVersion).toBe(1);
      expect(manifest.bundleId).toBe('sess-test');
      expect(manifest.producedAt).toBe('2025-05-18T16:00:00.000Z');
      expect(manifest.producer.tool).toBe('depose');
      expect(manifest.producer.version).toBe('0.1.0');
      expect(manifest.session.agentId).toBe('claude-code');
      expect(manifest.session.sessionId).toBe('sess-test');
      expect(manifest.rootHash).toBe(''); // unsigned mode
      expect(manifest.signatures).toEqual([]);
      expect(manifest.timestamps).toEqual([]);
      expect(manifest.counts.events).toBe(events.length);
      expect(manifest.counts.gaps).toBe(0);
    });
  });

  describe('events.jsonl', () => {
    it('writes events sorted by id (ULID)', async () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const rules = loadDestructiveRules(rulesPath);
      const rulesetBytes = readFileSync(rulesPath);
      const { depopPath } = await writeBundle(events, rules, {
        sessionId: 'sess-test',
        agentId: 'claude-code',
        version: '0.1.0',
        producedAt: '2025-05-18T16:00:00.000Z',
        sessionStartedAt: '2025-05-18T15:30:00.000Z',
        sessionEndedAt: '2025-05-18T15:31:00.000Z',
        rules,
        rulesetBytes,
        outputDir: testOutputDir,
        unsigned: true,
      });

      const eventsContent = readFileSync(pathJoin(depopPath, 'events.jsonl'), 'utf-8');
      const eventLines = eventsContent.trim().split('\n');
      expect(eventLines.length).toBe(events.length);

      // Verify sorted by id
      const ids = eventLines.map((line) => JSON.parse(line).id);
      const sorted = [...ids].sort();
      expect(ids).toEqual(sorted);
    });
  });

  describe('verify.txt', () => {
    it('produces attorney-friendly verify instructions', async () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const rules = loadDestructiveRules(rulesPath);
      const rulesetBytes = readFileSync(rulesPath);
      const { depopPath } = await writeBundle(events, rules, {
        sessionId: 'sess-test',
        agentId: 'claude-code',
        version: '0.1.0',
        producedAt: '2025-05-18T16:00:00.000Z',
        sessionStartedAt: '2025-05-18T15:30:00.000Z',
        sessionEndedAt: '2025-05-18T15:31:00.000Z',
        rules,
        rulesetBytes,
        outputDir: testOutputDir,
        unsigned: true,
      });

      const verifyTxt = readFileSync(pathJoin(depopPath, 'verify.txt'), 'utf-8');
      expect(verifyTxt).toContain('DEPOSE Evidence Bundle Verification Instructions');
      expect(verifyTxt).toContain('depose-verify');
      expect(verifyTxt).toContain('PASS');
      expect(verifyTxt).toContain('FAIL');
    });
  });

  describe('determinism', () => {
    it('produces byte-identical output for same input (unsigned mode)', async () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const rules = loadDestructiveRules(rulesPath);
      const rulesetBytes = readFileSync(rulesPath);
      const producedAt = '2025-05-18T16:00:00.000Z';

      const { depopPath: path1 } = await writeBundle(events, rules, {
        sessionId: 'sess-test',
        agentId: 'claude-code',
        version: '0.1.0',
        producedAt,
        sessionStartedAt: '2025-05-18T15:30:00.000Z',
        sessionEndedAt: '2025-05-18T15:31:00.000Z',
        rules,
        rulesetBytes,
        outputDir: testOutputDir,
        unsigned: true,
      });

      const { depopPath: path2 } = await writeBundle(events, rules, {
        sessionId: 'sess-test',
        agentId: 'claude-code',
        version: '0.1.0',
        producedAt,
        sessionStartedAt: '2025-05-18T15:30:00.000Z',
        sessionEndedAt: '2025-05-18T15:31:00.000Z',
        rules,
        rulesetBytes,
        outputDir: testOutputDir,
        unsigned: true,
      });

      // manifest.json should be identical
      const m1 = readFileSync(pathJoin(path1, 'manifest.json'), 'utf-8');
      const m2 = readFileSync(pathJoin(path2, 'manifest.json'), 'utf-8');
      expect(m1).toBe(m2);

      // events.jsonl should be identical
      const e1 = readFileSync(pathJoin(path1, 'events.jsonl'), 'utf-8');
      const e2 = readFileSync(pathJoin(path2, 'events.jsonl'), 'utf-8');
      expect(e1).toBe(e2);
    });
  });
});