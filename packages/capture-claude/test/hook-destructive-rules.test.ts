// packages/capture-claude/test/hook-destructive-rules.test.ts
//
// Regression: destructive rules must fire on records the hook wrote.
//
// The hook records every Bash tool call as ['bash', '-c', <command>].
// argvHead rules matched a strict argv prefix, so on active capture no
// rule could ever fire; only the reconstruct-from-JSONL path detected
// anything. Each fixture here is a real PreToolUse payload pushed through
// handlePreToolUse, read back through normalizeCaptureRecords, and
// matched with the default ruleset, which is exactly the production path.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  normalizeCaptureRecords,
  matchDestructiveRules,
  loadDestructiveRules,
  type RuleMatch,
} from '@depose/core';
import { handlePreToolUse, type HookInput } from '../src/hook-entry.js';

const rulesPath = join(__dirname, '../../cli/rules/destructive.default.yaml');
const fixturesDir = join(__dirname, 'fixtures/hook-inputs');
const rules = loadDestructiveRules(rulesPath);

let captureDir: string;

beforeEach(() => {
  captureDir = mkdtempSync(join(tmpdir(), 'depose-hook-rules-'));
  process.env.DEPOSE_CAPTURE_DIR = captureDir;
});

afterEach(() => {
  rmSync(captureDir, { recursive: true, force: true });
});

async function matchesForFixture(name: string): Promise<RuleMatch[]> {
  const input = JSON.parse(readFileSync(join(fixturesDir, name), 'utf-8')) as HookInput;
  await handlePreToolUse(input, { walkProcessTree: () => [], resolveTty: () => null });
  const { events } = normalizeCaptureRecords(captureDir, {
    sessionId: 'sess',
    scope: { agentSessionId: input.session_id },
  });
  expect(events).toHaveLength(1);
  expect(events[0]!.type).toBe('shell_command_pre');
  return matchDestructiveRules(events[0]!, rules);
}

describe('destructive rules on hook-captured records', () => {
  it('fires rm-rf on the DataTalks incident captured through the hook', async () => {
    const matches = await matchesForFixture('datatalks-rm-rf.json');
    expect(matches.map((m) => m.ruleId)).toEqual(['rm-rf']);
    expect(matches[0]!.simpleCommand).toEqual(['rm', '-rf', '/data/training']);
    expect(matches[0]!.simpleCommandIndex).toBe(0);
    expect(matches[0]!.strippedWrappers).toEqual(['bash']);
  });

  it('fires terraform-destroy on the PocketOS incident captured through the hook', async () => {
    const matches = await matchesForFixture('pocketos-terraform-destroy.json');
    expect(matches.map((m) => m.ruleId)).toEqual(['terraform-destroy']);
    expect(matches[0]!.simpleCommand).toEqual(['terraform', 'destroy', '-auto-approve']);
  });

  it('fires through sudo', async () => {
    const matches = await matchesForFixture('evasion-sudo.json');
    expect(matches.map((m) => m.ruleId)).toEqual(['rm-rf']);
    expect(matches[0]!.strippedWrappers).toEqual(['bash', 'sudo']);
  });

  it('fires through env VAR=value', async () => {
    const matches = await matchesForFixture('evasion-env.json');
    expect(matches.map((m) => m.ruleId)).toEqual(['terraform-destroy']);
    expect(matches[0]!.strippedWrappers).toEqual(['bash', 'env', 'X=']);
  });

  it('fires on the second command of a cd && rm chain and records its index', async () => {
    const matches = await matchesForFixture('evasion-cd-chain.json');
    expect(matches.map((m) => m.ruleId)).toEqual(['rm-rf']);
    expect(matches[0]!.simpleCommandIndex).toBe(1);
    expect(matches[0]!.simpleCommandCount).toBe(2);
    expect(matches[0]!.simpleCommand).toEqual(['rm', '-rf', '.']);
  });

  it('fires inside a subshell and inside $(...) substitution', async () => {
    const matches = await matchesForFixture('evasion-subshell.json');
    const byRule = Object.fromEntries(matches.map((m) => [m.ruleId, m]));
    expect(Object.keys(byRule).sort()).toEqual(['git-push-force', 'sql-drop']);
    expect(byRule['sql-drop']!.simpleCommand).toEqual(['psql', '-c', 'DROP TABLE customers']);
    expect(byRule['sql-drop']!.simpleCommandIndex).toBe(2);
    expect(byRule['git-push-force']!.simpleCommandIndex).toBe(3);
    expect(byRule['git-push-force']!.simpleCommandCount).toBe(5);
  });
});
