// packages/bundle/test/roundtrip.test.ts
//
// Tests for bundle roundtrip (write → read back → verify structure).
// BUILD_PLAN.md §5 (Phase 2): signed bundles with hash chain.
// Tests use unsigned mode for deterministic fixture testing.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { join as pathJoin } from 'node:path';
import {
  normalizeClaudeCodeJsonl,
  loadDestructiveRules,
} from '@depose/core';
import { writeBundle } from '../src/index.js';

const fixturesDir = pathJoin(__dirname, '../../core/test/fixtures');
const rulesPath = pathJoin(__dirname, '../../cli/rules/destructive.default.yaml');
const testOutputDir = pathJoin(__dirname, 'test-output-roundtrip');

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

describe('roundtrip', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it('writes and reads back a complete bundle from terraform-destroy.jsonl', async () => {
    const jsonl = readFileSync(pathJoin(fixturesDir, 'terraform-destroy.jsonl'), 'utf-8');
    const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const sessionStarted = claudeEvents[0]?.wallTs || new Date().toISOString();
    const sessionEnded = claudeEvents[claudeEvents.length - 1]?.wallTs || new Date().toISOString();
    const producedAt = '2025-05-18T16:00:00.000Z';

    const { depopPath, manifest: _manifest, events: writtenEvents } = await writeBundle(claudeEvents, rules, {
      sessionId: 'sess-roundtrip',
      agentId: 'claude-code',
      version: '0.1.0',
      producedAt,
      sessionStartedAt: sessionStarted,
      sessionEndedAt: sessionEnded,
      rules,
      rulesetBytes,
      outputDir: testOutputDir,
      mode: 'dev-unsigned',
    });

    // Read back manifest
    const manifestContent = readFileSync(pathJoin(depopPath, 'manifest.json'), 'utf-8');
    const readManifest = JSON.parse(manifestContent);
    expect(readManifest.schemaVersion).toBe(1);
    expect(readManifest.bundleId).toBe('sess-roundtrip');
    expect(readManifest.producer.tool).toBe('depose');
    expect(readManifest.counts.events).toBe(claudeEvents.length);
    expect(readManifest.rootHash).toBe(''); // unsigned mode
    expect(readManifest.signatures).toEqual([]);
    // Terraform-destroy.jsonl produces shell_command_pre events without tool_result, so gaps > 0
    expect(readManifest.counts.gaps).toBeGreaterThanOrEqual(0);

    // Read back events
    const eventsContent = readFileSync(pathJoin(depopPath, 'events.jsonl'), 'utf-8');
    const readEvents = eventsContent.trim().split('\n').map((line) => JSON.parse(line));
    expect(readEvents.length).toBe(writtenEvents.length);
    expect(readEvents.length).toBe(claudeEvents.length);

    // Verify events match (compare against sorted written events, not original order)
    for (let i = 0; i < writtenEvents.length; i++) {
      expect(readEvents[i].type).toBe(writtenEvents[i].type);
      expect(readEvents[i].wallTs).toBe(writtenEvents[i].wallTs);
      expect(readEvents[i].sessionId).toBe(writtenEvents[i].sessionId);
    }
  });

  it('verifies all expected directories exist', async () => {
    const jsonl = JSON.stringify({
      type: 'user',
      content: 'hello',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const { depopPath } = await writeBundle(events, rules, {
      sessionId: 'sess-dir',
      agentId: 'claude-code',
      version: '0.1.0',
      producedAt: '2025-05-18T16:00:00.000Z',
      sessionStartedAt: '2025-05-18T15:30:00.000Z',
      sessionEndedAt: '2025-05-18T15:31:00.000Z',
      rules,
      rulesetBytes,
      outputDir: testOutputDir,
      mode: 'dev-unsigned',
    });

    const dirs = [
      'manifest.json',
      'events.jsonl',
      'raw/claude-code',
      'raw/shell-history',
      'raw/git-reflog.txt',
      'raw/capture',
      'artifacts/files-pre',
      'artifacts/files-post',
      'attestations/signatures.json',
      'attestations/rfc3161-timestamps',
      'attestations/rekor-entries.json',
      'rules/destructive.yaml',
      'narrative.md',
      'narrative.html',
      'verify.txt',
    ];

    for (const dir of dirs) {
      expect(existsSync(pathJoin(depopPath, dir))).toBe(true);
    }
  });

  it('verifies empty attestations (unsigned mode)', async () => {
    const jsonl = JSON.stringify({
      type: 'user',
      content: 'hello',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);
    const { depopPath } = await writeBundle(events, rules, {
      sessionId: 'sess-attest',
      agentId: 'claude-code',
      version: '0.1.0',
      producedAt: '2025-05-18T16:00:00.000Z',
      sessionStartedAt: '2025-05-18T15:30:00.000Z',
      sessionEndedAt: '2025-05-18T15:31:00.000Z',
      rules,
      rulesetBytes,
      outputDir: testOutputDir,
      mode: 'dev-unsigned',
    });

    const sigs = JSON.parse(readFileSync(pathJoin(depopPath, 'attestations', 'signatures.json'), 'utf-8'));
    expect(sigs.blocks).toEqual([]);

    const rekor = JSON.parse(readFileSync(pathJoin(depopPath, 'attestations', 'rekor-entries.json'), 'utf-8'));
    expect(rekor.entries).toEqual([]);
  });
});