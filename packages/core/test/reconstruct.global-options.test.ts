// packages/core/test/reconstruct.global-options.test.ts
//
// argvHead matching past a tool's global options. Found while building
// examples/kiro-cost-explorer: the incident's own command was
// `terraform -chdir=infra/prod destroy -auto-approve`, and a rule written
// as ["terraform", "destroy"] did not fire on it, because the subcommand
// was not at position one. See docs/decisions.md D24.

import { describe, it, expect } from 'vitest';
import {
  parseDestructiveRulesYaml,
  matchDestructiveRules,
  withoutGlobalOptions,
  type Event,
} from '../src/index.js';

describe('withoutGlobalOptions', () => {
  it('drops an attached option value with the option', () => {
    expect(withoutGlobalOptions(['terraform', '-chdir=infra/prod', 'destroy', '-auto-approve'])).toEqual([
      'terraform',
      'destroy',
      '-auto-approve',
    ]);
  });

  it('drops a separated option value with the option it belongs to', () => {
    expect(withoutGlobalOptions(['git', '-C', '/repo', 'push', '--force'])).toEqual(['git', 'push', '--force']);
  });

  it('stops at the subcommand, so the subcommand keeps its own flags', () => {
    expect(withoutGlobalOptions(['rm', '-rf', '/data'])).toEqual(['rm', '/data']);
    expect(withoutGlobalOptions(['kubectl', '-n', 'staging', 'delete', 'ns', 'staging'])).toEqual([
      'kubectl',
      'delete',
      'ns',
      'staging',
    ]);
  });

  it('leaves a command with no leading options alone', () => {
    const argv = ['terraform', 'destroy', '-auto-approve'];
    expect(withoutGlobalOptions(argv)).toBe(argv);
  });

  it('does not eat a subcommand that looks like an option value', () => {
    // -x is not in the separated-value list, so `push` stays where it is.
    expect(withoutGlobalOptions(['git', '-x', 'push'])).toEqual(['git', 'push']);
  });
});

describe('rules fire through global options', () => {
  const rules = parseDestructiveRulesYaml(`
version: 1
rules:
  - id: terraform-destroy
    matcher:
      argvHead: ["terraform", "destroy"]
    severity: critical
  - id: rm-rf
    matcher:
      argvHead: ["rm", "-rf"]
    severity: critical
  - id: kubectl-delete
    matcher:
      argvHead: ["kubectl", "delete"]
    severity: high
`);

  const fires = (command: string): string[] =>
    matchDestructiveRules(
      {
        id: 'E',
        wallTs: '2025-12-15T16:00:00.000Z',
        monoNs: 0n,
        sessionId: 'S',
        agentId: 'claude-code',
        parentEventId: null,
        type: 'shell_command_pre',
        payload: {
          argv: ['bash', '-c', command],
          cwd: '',
          envHash: '',
          envSubset: {},
          ttyId: null,
          user: '',
          hostname: '',
          parentProcessTree: [],
          fileArgs: [],
          source: 'claude-pretooluse',
          captureSchemaVersion: 3,
          capturedAt: '2025-12-15T16:00:00.000Z',
          capturedAtSource: 'recorded',
          sessionId: null,
        },
        payloadHash: '',
      } as unknown as Event,
      rules
    ).map((m) => m.ruleId);

  it.each([
    ['terraform -chdir=infra/prod destroy -auto-approve', 'terraform-destroy'],
    ['terraform -chdir infra/prod destroy -auto-approve', 'terraform-destroy'],
    ['kubectl -n staging delete ns staging', 'kubectl-delete'],
    ['kubectl --kubeconfig /tmp/kc delete ns staging', 'kubectl-delete'],
  ])('%s fires %s', (command, ruleId) => {
    expect(fires(command)).toContain(ruleId);
  });

  it('still fires on a command whose own flags are part of the rule', () => {
    expect(fires('rm -rf /data')).toContain('rm-rf');
    expect(fires('sudo rm -rf /data')).toContain('rm-rf');
  });

  it('does not fire on a safe subcommand reached through the same options', () => {
    expect(fires('terraform -chdir=infra/prod plan')).toEqual([]);
    expect(fires('kubectl -n staging get pods')).toEqual([]);
  });
});
