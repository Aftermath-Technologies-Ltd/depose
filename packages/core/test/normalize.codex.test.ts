// packages/core/test/normalize.codex.test.ts
//
// The Codex CLI rollout normalizer, against both grammars it reads and
// against the same four evasion shapes the Claude hook path is
// regression-tested on. A destructive command that fires on one agent's
// transcript and not the other's would be a coverage hole nobody notices
// until it matters.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { normalizeCodexJsonl, detectCodexFormat } from '../src/normalize/codex.js';
import { loadRuleset } from '../src/reconstruct/destructive-rules.js';
import { buildDestructiveOpsIndex } from '../src/reconstruct/destructive-match.js';
import type {
  Event,
  PromptPayload,
  AssistantMessagePayload,
  ToolCallIntentPayload,
  ToolResultPayload,
  ShellCommandPrePayload,
} from '../src/events/schema.js';

const fixtures = join(__dirname, 'fixtures', 'codex');
const rulesPath = join(__dirname, '../../cli/rules/destructive.default.yaml');

const read = (name: string): string => readFileSync(join(fixtures, name), 'utf-8');
const typesOf = (events: Event[]): string[] => events.map((e) => e.type);

describe('detectCodexFormat', () => {
  it('recognizes the enveloped grammar current Codex writes', () => {
    expect(detectCodexFormat([{ timestamp: 't', type: 'session_meta', payload: {} }])).toBe('codex-rollout-v2');
  });

  it('recognizes the older bare-item grammar', () => {
    expect(detectCodexFormat([{ id: 's', instructions: 'x' }, { type: 'message', role: 'user' }])).toBe(
      'codex-rollout-v1'
    );
  });

  it('assumes the current grammar for an empty file rather than guessing old', () => {
    expect(detectCodexFormat([])).toBe('codex-rollout-v2');
  });
});

describe('codex-rollout-v2', () => {
  const result = normalizeCodexJsonl(read('codex-rollout-v2.jsonl'), { sessionId: 'S' });

  it('reports which grammar it read, so the bundle can record it', () => {
    expect(result.sourceFormat).toBe('codex-rollout-v2');
    expect(result.cliVersion).toBe('0.130.0');
  });

  it('picks up the session id and cwd that scope capture records', () => {
    expect(result.agentSessionId).toBe('0199a2f1-4c3b-7a11-9b2e-5f6d7c8e9a0b');
    expect(result.cwds).toEqual(['/srv/pocketos']);
  });

  it('emits the same event types the Claude path does, in order', () => {
    expect(typesOf(result.events)).toEqual([
      'prompt',
      'assistant_message',
      'tool_call_intent',
      'shell_command_pre',
      'tool_result',
      'tool_call_intent',
      'shell_command_pre',
      'tool_result',
    ]);
  });

  it('takes the prompt and the assistant text out of the content parts', () => {
    expect((result.events[0]!.payload as PromptPayload).text).toContain('Tear it down');
    expect((result.events[1]!.payload as AssistantMessagePayload).content).toContain("I'll destroy the stack");
  });

  it('does not double the assistant message from the event_msg copy', () => {
    expect(result.events.filter((e) => e.type === 'assistant_message')).toHaveLength(1);
  });

  it('parses the tool arguments out of their JSON string', () => {
    const intent = result.events[2]!.payload as ToolCallIntentPayload;
    expect(intent.toolName).toBe('shell');
    expect(intent.toolUseId).toBe('call_a1');
    expect((intent.toolInput as { command: string[] }).command).toEqual([
      'bash',
      '-lc',
      'terraform destroy -auto-approve',
    ]);
  });

  it('rebuilds a shell_command_pre so rule matching sees the same shape as the hook path', () => {
    const pre = result.events[3]!.payload as ShellCommandPrePayload;
    expect(pre.argv).toEqual(['bash', '-lc', 'terraform destroy -auto-approve']);
    expect(pre.cwd).toBe('/srv/pocketos');
    expect(pre.source).toBe('reconstructed');
    // The time comes from the rollout line, and says so; it was never observed.
    expect(pre.capturedAtSource).toBe('reconstructed');
    expect(pre.capturedAt).toBe('2025-05-18T15:30:05.000Z');
  });

  it('reads the exit code and output out of the tool result envelope', () => {
    const output = result.events[4]!.payload as ToolResultPayload;
    expect(output.exitCode).toBe(0);
    expect(output.output).toContain('Destroy complete!');
    expect(output.toolUseId).toBe('call_a1');
  });

  it('leaves the model reasoning trace out; it is neither an action nor a message', () => {
    expect(result.warnings.filter((w) => w.includes('reasoning'))).toEqual([]);
    expect(typesOf(result.events)).not.toContain('reasoning');
  });

  it('fires the destructive ruleset on both commands', () => {
    const index = buildDestructiveOpsIndex(result.events, loadRuleset(rulesPath).rules);
    const commands = index.map((op) => op.matches[0]!.simpleCommand.join(' '));
    expect(commands).toContain('terraform destroy -auto-approve');
    expect(commands).toContain('rm -rf /srv/pocketos/.terraform');
  });
});

describe('codex-rollout-v1', () => {
  const result = normalizeCodexJsonl(read('codex-rollout-v1.jsonl'), { sessionId: 'S' });

  it('reads the older grammar and says which one it was', () => {
    expect(result.sourceFormat).toBe('codex-rollout-v1');
    expect(result.agentSessionId).toBe('0199a2f1-dead-7a11-9b2e-000000000001');
    expect(result.cwds).toEqual(['/srv/datatalks']);
  });

  it('produces the same event shapes despite the missing envelope', () => {
    expect(typesOf(result.events)).toEqual([
      'prompt',
      'assistant_message',
      'tool_call_intent',
      'shell_command_pre',
      'tool_result',
    ]);
  });

  it('takes a plain string tool output as the output', () => {
    const output = result.events[4]!.payload as ToolResultPayload;
    expect(output.output).toBe('removed 4213 files');
    expect(output.exitCode).toBeNull();
  });

  it('fires the ruleset on the rm', () => {
    const index = buildDestructiveOpsIndex(result.events, loadRuleset(rulesPath).rules);
    expect(index.map((op) => op.matches[0]!.simpleCommand.join(' '))).toContain('rm -rf /data/training-runs');
  });
});

describe('evasion shapes, the same four the hook path is tested on', () => {
  const result = normalizeCodexJsonl(read('codex-rollout-evasions.jsonl'), { sessionId: 'S' });
  const index = buildDestructiveOpsIndex(result.events, loadRuleset(rulesPath).rules);
  const matched = index.map((op) => op.matches[0]!.simpleCommand.join(' '));

  it.each([
    ['sudo prefix', 'rm -rf /srv/prod'],
    ['env with an assignment', 'terraform destroy -auto-approve'],
    ['cd then rm in a compound command', 'rm -rf .'],
  ])('fires through a %s', (_shape, command) => {
    expect(matched).toContain(command);
  });

  it('fires inside a subshell reached through a string command argument', () => {
    // The fourth shape arrives as a bare string rather than an argv array,
    // which is the form older Codex builds and some providers still send.
    const wrapped = result.events.filter(
      (e) => e.type === 'shell_command_pre' && (e.payload as ShellCommandPrePayload).argv[0] === 'bash'
    );
    expect(wrapped.length).toBeGreaterThan(0);
    expect(matched.filter((c) => c === 'rm -rf .').length).toBeGreaterThanOrEqual(2);
  });

  it('keeps an unparseable argument list instead of dropping the call', () => {
    const kept = result.events.find(
      (e) =>
        e.type === 'tool_call_intent' && (e.payload as ToolCallIntentPayload).toolUseId === 'c5'
    );
    expect(kept).toBeDefined();
    expect((kept!.payload as ToolCallIntentPayload).toolInput).toEqual({ raw: '{not json' });
    expect(result.warnings.some((w) => w.includes('not JSON'))).toBe(true);
  });

  it('warns about a response item type it does not know rather than ignoring it', () => {
    expect(result.warnings.some((w) => w.includes('wormhole'))).toBe(true);
  });
});

describe('malformed input', () => {
  it('records an unparseable line as a warning and keeps going', () => {
    const result = normalizeCodexJsonl(
      ['{"timestamp":"2025-05-18T15:30:00.000Z","type":"session_meta","payload":{"id":"s"}}', '{not json', '{"timestamp":"2025-05-18T15:30:02.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"text":"hi"}]}}'].join(
        '\n'
      ),
      { sessionId: 'S' }
    );
    expect(result.warnings.some((w) => w.includes('line 2'))).toBe(true);
    expect(typesOf(result.events)).toEqual(['prompt']);
  });

  it('says so when a file parses but carries no conversation at all', () => {
    const result = normalizeCodexJsonl('{"timestamp":"2025-05-18T15:30:00.000Z","type":"session_meta","payload":{}}\n', {
      sessionId: 'S',
    });
    expect(result.events).toEqual([]);
    expect(result.warnings.some((w) => w.includes('format has drifted'))).toBe(true);
  });
});
