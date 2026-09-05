// packages/core/test/normalize.merge-correlation.test.ts
//
// What comes after the merge has ordered the events: the timeline it
// builds and the destructive ruleset applied to it. Ordering and gap
// emission are in normalize.merge.test.ts; tool_result correlation is in
// normalize.merge-toolresult.test.ts.

import { describe, it, expect } from 'vitest';
import {
  normalizeClaudeCodeJsonl,
  buildTimeline,
  loadDestructiveRules,
  matchDestructiveRules,
  ulidFromTime,
  sha256,
} from '../src/index.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const fixturesDir = join(__dirname, 'fixtures');
const rulesPath = join(__dirname, '../../cli/rules/destructive.default.yaml');


describe('buildTimeline', () => {
  it('builds a correct timeline from terraform-destroy.jsonl', () => {
    const jsonl = readFileSync(join(fixturesDir, 'terraform-destroy.jsonl'), 'utf-8');
    const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const timeline = buildTimeline(claudeEvents, rules);
    expect(timeline.events.length).toBe(claudeEvents.length);
    expect(timeline.gaps.length).toBe(0);
    expect(timeline.fileChanges.length).toBe(1);
    expect(timeline.errors.length).toBe(0);
    // The fixture's tool_call_intent contains `terraform destroy
    // -auto-approve`. After the tool_call_intent fix, the destructive
    // matcher fires on that intent (rules: terraform-destroy +
    // terraform-apply-auto-approve), so we expect ≥1 destructive op.
    expect(timeline.destructiveOps.length).toBeGreaterThan(0);
    const ruleIds = timeline.destructiveOps.flatMap((op) =>
      op.matches.map((m) => m.ruleId)
    );
    expect(ruleIds).toContain('terraform-destroy');
  });

  it('builds a correct timeline from session-with-gaps.jsonl', () => {
    const jsonl = readFileSync(join(fixturesDir, 'session-with-gaps.jsonl'), 'utf-8');
    const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const timeline = buildTimeline(claudeEvents, rules);
    expect(timeline.events.length).toBe(claudeEvents.length);
    // Should have error events
    expect(timeline.errors.length).toBe(1);
    // Should have file changes
    expect(timeline.fileChanges.length).toBe(1);
  });
});

describe('destructive rules matching', () => {
  it('matches terraform destroy', () => {
    const rules = loadDestructiveRules(rulesPath);
    const event = {
      id: ulidFromTime(Date.now()),
      wallTs: '2025-05-18T15:30:00.000Z',
      monoNs: 0n,
      sessionId: 'sess-1',
      agentId: 'shell' as const,
      parentEventId: null,
      type: 'shell_command_pre' as const,
      payload: {
        argv: ['terraform', 'destroy', '-auto-approve'],
        cwd: '',
        envHash: '',
        envSubset: {},
        ttyId: null,
        user: '',
        hostname: '',
        parentProcessTree: [],
        fileArgs: [],
        source: 'shell-shim' as const,
        captureSchemaVersion: 1 as const,
      },
      payloadHash: sha256({ argv: ['terraform', 'destroy'] }),
    };
    const matches = rules.filter((r) => {
      return matchDestructiveRules(event, [r]).length > 0;
    });
    expect(matches.length).toBeGreaterThanOrEqual(1);
  });
});
