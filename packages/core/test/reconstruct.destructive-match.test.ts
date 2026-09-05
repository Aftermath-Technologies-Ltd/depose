// packages/core/test/reconstruct.destructive-match.test.ts
//
// Rules applied to events: which commands fire which rule, what the
// match records about where in a compound command it fired, and what the
// index looks like across a session. Loading and parsing a ruleset is in
// reconstruct.destructive.test.ts.

import { describe, it, expect } from 'vitest';
import {
  loadDestructiveRules,
  matchDestructiveRules,
  buildDestructiveOpsIndex,
  sha256,
  ulidFromTime,
  type Event,
  type ShellCommandPrePayload,
} from '../src/index.js';
import { join } from 'node:path';

const rulesPath = join(__dirname, '../../cli/rules/destructive.default.yaml');

// ── Helper ───────────────────────────────────────────────────────────

function makeShellPreEvent(argv: string[]): Event {
  const id = ulidFromTime(Date.now());
  const payload: ShellCommandPrePayload = {
    argv,
    cwd: '/home/user/project',
    envHash: '',
    envSubset: {},
    ttyId: null,
    user: 'user',
    hostname: 'localhost',
    parentProcessTree: [],
    fileArgs: [],
    source: 'shell-shim',
    captureSchemaVersion: 1,
  };
  return {
    id,
    wallTs: '2025-05-18T15:30:00.000Z',
    monoNs: 0,
    sessionId: 'sess-1',
    agentId: 'shell',
    parentEventId: null,
    type: 'shell_command_pre',
    payload,
    payloadHash: sha256(payload),
  };
}

// ── Tests ────────────────────────────────────────────────────────────

describe('matchDestructiveRules', () => {
  describe('positive matches', () => {
    it('matches terraform destroy', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['terraform', 'destroy']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.some((m) => m.ruleId === 'terraform-destroy')).toBe(true);
    });

    it('matches terraform apply -auto-approve', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['terraform', 'apply', '-auto-approve']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.some((m) => m.ruleId === 'terraform-apply-auto-approve')).toBe(true);
    });

    it('matches rm -rf', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['rm', '-rf', '/tmp/test']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.some((m) => m.ruleId === 'rm-rf')).toBe(true);
    });

    it('matches aws s3 rb', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['aws', 's3', 'rb', 's3://bucket']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.some((m) => m.ruleId === 'aws-s3-rb')).toBe(true);
    });

    it('matches kubectl delete', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['kubectl', 'delete', 'pod', 'test']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.some((m) => m.ruleId === 'kubectl-delete')).toBe(true);
    });

    it('matches git push --force', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['git', 'push', '--force', 'origin', 'main']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.some((m) => m.ruleId === 'git-push-force')).toBe(true);
    });

    it('matches git reset --hard', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['git', 'reset', '--hard', 'HEAD']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.some((m) => m.ruleId === 'git-reset-hard')).toBe(true);
    });

    it('matches sql drop (regex)', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['psql', '-c', 'DROP TABLE users']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.some((m) => m.ruleId === 'sql-drop')).toBe(true);
    });
  });

  describe('negative matches', () => {
    it('does not match terraform plan (no destructive flag)', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['terraform', 'plan']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.length).toBe(0);
    });

    it('does not match git status', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['git', 'status']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.length).toBe(0);
    });

    it('does not match rm without -rf', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['rm', 'file.txt']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.length).toBe(0);
    });

    it('does not match terraform apply without -auto-approve', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['terraform', 'apply']);
      const matches = matchDestructiveRules(event, rules);
      expect(matches.length).toBe(0);
    });
  });

  describe('severity levels', () => {
    it('returns correct severity for each matched rule', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = makeShellPreEvent(['terraform', 'destroy']);
      const matches = matchDestructiveRules(event, rules);
      const terraformMatch = matches.find((m) => m.ruleId === 'terraform-destroy');
      expect(terraformMatch?.severity).toBe('critical');
    });
  });

  describe('non-shell_command_pre events', () => {
    it('returns empty matches for non-shell events', () => {
      const rules = loadDestructiveRules(rulesPath);
      const event = {
        id: ulidFromTime(Date.now()),
        wallTs: '2025-05-18T15:30:00.000Z',
        monoNs: 0,
        sessionId: 'sess-1',
        agentId: 'claude-code',
        parentEventId: null,
        type: 'prompt' as const,
        payload: { text: 'hello' },
        payloadHash: sha256({ text: 'hello' }),
      };
      const matches = matchDestructiveRules(event, rules);
      expect(matches.length).toBe(0);
    });
  });
});

describe('buildDestructiveOpsIndex', () => {
  it('indexes destructive operations from events', () => {
    const rules = loadDestructiveRules(rulesPath);
    const events: Event[] = [
      makeShellPreEvent(['terraform', 'destroy']),
      makeShellPreEvent(['git', 'status']),
      makeShellPreEvent(['rm', '-rf', '/tmp/test']),
      makeShellPreEvent(['ls', '-la']),
    ];
    const index = buildDestructiveOpsIndex(events, rules);
    expect(index.length).toBe(2);
    expect(index[0].event.payload.argv).toEqual(['terraform', 'destroy']);
    expect(index[1].event.payload.argv).toEqual(['rm', '-rf', '/tmp/test']);
  });
});

// ── Reconstruction-from-JSONL coverage ────────────────────────────────
//
// The headline DEPOSE use case is "agent ran a destructive command,
// reconstruct it from the Claude Code JSONL". That path emits
// tool_call_intent events, not shell_command_pre events. Before this
// suite landed, matchDestructiveRules returned [] for those events and
// the synthetic datatalks/pocketos examples both reported 0 destructive
// operations despite literally containing `rm -rf` and
// `terraform destroy -auto-approve`.

function makeToolCallIntent(toolName: string, command: string): Event {
  const payload = {
    toolName,
    toolInput: { command },
    linkedShellCommandPreId: null,
  };
  return {
    id: ulidFromTime(Date.now()),
    wallTs: '2026-04-12T09:15:15.000Z',
    monoNs: 0,
    sessionId: 'sess-tool-intent',
    agentId: 'claude-code',
    parentEventId: null,
    type: 'tool_call_intent',
    payload,
    payloadHash: sha256(payload),
  };
}

describe('matchDestructiveRules, tool_call_intent (reconstruct from JSONL)', () => {
  it('fires on Bash tool_call_intent for rm -rf', () => {
    const rules = loadDestructiveRules(rulesPath);
    const event = makeToolCallIntent('Bash', 'rm -rf /data/training');
    const matches = matchDestructiveRules(event, rules);
    expect(matches.map((m) => m.ruleId)).toContain('rm-rf');
  });

  it('fires on Bash tool_call_intent for terraform destroy -auto-approve', () => {
    const rules = loadDestructiveRules(rulesPath);
    const event = makeToolCallIntent('Bash', 'terraform destroy -auto-approve');
    const matches = matchDestructiveRules(event, rules);
    const ids = matches.map((m) => m.ruleId);
    expect(ids).toContain('terraform-destroy');
  });

  it('respects double quotes so anyArgvRegex sees the inner string', () => {
    const rules = loadDestructiveRules(rulesPath);
    const event = makeToolCallIntent('Bash', 'psql -c "DROP TABLE customers"');
    const matches = matchDestructiveRules(event, rules);
    expect(matches.map((m) => m.ruleId)).toContain('sql-drop');
  });

  it('does not fire on non-shell tools (Edit, Write)', () => {
    const rules = loadDestructiveRules(rulesPath);
    const event = makeToolCallIntent('Edit', 'rm -rf /data/training');
    const matches = matchDestructiveRules(event, rules);
    expect(matches.length).toBe(0);
  });

  it('does not fire on benign commands', () => {
    const rules = loadDestructiveRules(rulesPath);
    const event = makeToolCallIntent('Bash', 'ls -la');
    const matches = matchDestructiveRules(event, rules);
    expect(matches.length).toBe(0);
  });
});

