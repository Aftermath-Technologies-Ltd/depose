// Verifies that the bundle contains the ruleset *bytes* and that
// manifest.rulesetHash matches sha256 of the embedded file. A third
// party reading just the bundle must be able to reconstruct which
// rules produced the destructive-op counts.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, mkdirSync, rmSync } from 'node:fs';
import { join as pathJoin } from 'node:path';
import { createHash } from 'node:crypto';
import { normalizeClaudeCodeJsonl, loadDestructiveRules } from '@depose/core';
import { writeBundle } from '../src/index.js';

const rulesPath = pathJoin(__dirname, '../../cli/rules/destructive.default.yaml');
const testOutputDir = pathJoin(__dirname, 'test-output-ruleset-integrity');

function cleanup(): void {
  try {
    rmSync(testOutputDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
  mkdirSync(testOutputDir, { recursive: true });
}

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

describe('bundle ruleset integrity', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it('writes the ruleset bytes verbatim and the manifest hash matches', async () => {
    const jsonl = JSON.stringify({
      type: 'user',
      content: 'ruleset integrity',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);

    const { depopPath, manifest } = await writeBundle(events, rules, {
      sessionId: 'sess-ruleset-integrity',
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

    const embedded = readFileSync(pathJoin(depopPath, 'rules', 'destructive.yaml'));
    expect(embedded.equals(rulesetBytes)).toBe(true);
    expect(sha256Hex(embedded)).toBe(manifest.rulesetHash);
  });

  it('flipping a byte in the embedded ruleset breaks the rulesetHash match', async () => {
    const jsonl = JSON.stringify({
      type: 'user',
      content: 'tamper test',
      timestamp: '2025-05-18T15:30:00.000Z',
    });
    const { events } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const rulesetBytes = readFileSync(rulesPath);

    const { depopPath, manifest } = await writeBundle(events, rules, {
      sessionId: 'sess-ruleset-tamper',
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

    const original = readFileSync(pathJoin(depopPath, 'rules', 'destructive.yaml'));
    const tampered = Buffer.from(original);
    tampered[0] = tampered[0] === 0x20 ? 0x21 : 0x20;
    expect(sha256Hex(tampered)).not.toBe(manifest.rulesetHash);
  });
});
