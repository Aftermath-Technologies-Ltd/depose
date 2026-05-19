// packages/core/test/reconstruct.destructive.test.ts
//
// Tests for destructive rules matching.
// BUILD_PLAN.md §5 (Phase 1): destructive-operations index.
//
// Tests exercise:
//   1. Positive matches (terraform destroy, rm -rf, git push --force, etc.)
//   2. Negative matches (safe commands that should NOT match)
//   3. Multiple severity levels
//   4. Regex matching (sql-drop)
//   5. Ruleset loading from YAML file
//   6. Ruleset loading from YAML string
//   7. Empty ruleset (graceful degradation)

import { describe, it, expect } from 'vitest';
import {
  loadDestructiveRules,
  parseDestructiveRulesYaml,
  matchDestructiveRules,
  buildDestructiveOpsIndex,
  sha256,
  ulidFromTime,
  type DestructiveRule,
  type Event,
  type ShellCommandPrePayload,
} from '../src/index.js';
import { readFileSync } from 'node:fs';
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

describe('loadDestructiveRules', () => {
  it('loads rules from a YAML file', () => {
    const rules = loadDestructiveRules(rulesPath);
    expect(rules.length).toBeGreaterThan(0);
  });

  it('loads correct number of rules (12 rules in default ruleset)', () => {
    const rules = loadDestructiveRules(rulesPath);
    expect(rules.length).toBe(12);
  });

  it('returns empty ruleset for non-existent file', () => {
    const rules = loadDestructiveRules('/nonexistent/path/rules.yaml');
    expect(rules).toEqual([]);
  });
});

describe('parseDestructiveRulesYaml', () => {
  it('parses a simple ruleset', () => {
    const yaml = `
version: 1
rules:
  - id: test-rule
    matcher:
      argvHead: ["terraform", "destroy"]
    severity: critical
`;
    const rules = parseDestructiveRulesYaml(yaml);
    expect(rules.length).toBe(1);
    expect(rules[0].id).toBe('test-rule');
    expect(rules[0].severity).toBe('critical');
    expect(rules[0].matcher.argvHead).toEqual(['terraform', 'destroy']);
  });

  it('parses rules with argvContainsAny', () => {
    const yaml = `
version: 1
rules:
  - id: rm-rf
    matcher:
      argvHead: ["rm"]
      argvContainsAny: ["-rf", "-fr"]
    severity: critical
`;
    const rules = parseDestructiveRulesYaml(yaml);
    expect(rules.length).toBe(1);
    expect(rules[0].matcher.argvContainsAny).toEqual(['-rf', '-fr']);
  });

  it('parses rules with anyArgvRegex', () => {
    const yaml = `
version: 1
rules:
  - id: sql-drop
    matcher:
      anyArgvRegex: "(?i)\\\\b(DROP\\\\s+(TABLE|DATABASE|SCHEMA))\\\\b"
    severity: critical
`;
    const rules = parseDestructiveRulesYaml(yaml);
    expect(rules.length).toBe(1);
    expect(rules[0].matcher.anyArgvRegex).toContain('DROP');
  });
});

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
