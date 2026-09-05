// packages/cli/test/commands.record-codex.test.ts
//
// `depose record --from-codex` end to end: a Codex rollout in, a sealed
// bundle out, with the detected rollout grammar recorded in the signed
// manifest and the destructive command found by the same ruleset the
// Claude path uses.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadDestructiveRules, parseEventLine, type Event } from '@depose/core';
import { writeBundle, type Manifest } from '@depose/bundle';
import { loadAndMergeEvents } from '../src/pipeline.js';
import { main } from '../src/commands/main.js';
import { DEFAULT_RULES_PATH } from '../src/rules-default.js';

const fixtures = join(__dirname, '../../core/test/fixtures/codex');
let workDir: string;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'depose-codex-'));
});

afterEach(() => {
  rmSync(workDir, { recursive: true, force: true });
});

async function sealCodex(fixture: string): Promise<{ manifest: Manifest; events: Event[]; dir: string }> {
  const merged = loadAndMergeEvents({
    jsonlPath: join(fixtures, fixture),
    source: 'codex',
    sessionId: 'codex-session',
    agentId: 'codex',
    captureDir: join(workDir, 'captures'),
  });
  const rules = loadDestructiveRules(DEFAULT_RULES_PATH);
  const { manifest, depopPath } = await writeBundle(merged.events, rules, {
    sessionId: 'codex-session',
    agentId: 'codex',
    version: '0.1.0',
    producedAt: '2025-05-18T16:00:00.000Z',
    sessionStartedAt: '2025-05-18T15:30:00.000Z',
    sessionEndedAt: '2025-05-18T15:31:00.000Z',
    rules,
    rulesetBytes: readFileSync(DEFAULT_RULES_PATH),
    outputDir: join(workDir, 'out'),
    mode: 'dev-unsigned',
    sourceJsonlPath: join(fixtures, fixture),
    ...(merged.sourceFormat ? { sourceFormat: merged.sourceFormat } : {}),
  });
  const events = readFileSync(join(depopPath, 'events.jsonl'), 'utf-8')
    .trim()
    .split('\n')
    .map((line) => parseEventLine(line));
  return { manifest, events, dir: depopPath };
}

describe('depose record --from-codex', () => {
  it('records which rollout grammar it read in the signed manifest', async () => {
    const { manifest } = await sealCodex('codex-rollout-v2.jsonl');
    expect(manifest.session.sourceFormat).toBe('codex-rollout-v2');
    expect(manifest.session.agentId).toBe('codex');
  });

  it('records the older grammar when that is what the file is', async () => {
    const { manifest } = await sealCodex('codex-rollout-v1.jsonl');
    expect(manifest.session.sourceFormat).toBe('codex-rollout-v1');
  });

  it('finds the destructive commands with the same ruleset the Claude path uses', async () => {
    const { manifest } = await sealCodex('codex-rollout-v2.jsonl');
    expect(manifest.counts.destructiveOperations).toBeGreaterThanOrEqual(2);
  });

  it('tags every event as coming from codex', async () => {
    const { events } = await sealCodex('codex-rollout-v2.jsonl');
    expect(events.length).toBeGreaterThan(0);
    const byAgent = new Set(events.map((e) => e.agentId));
    expect(Array.from(byAgent)).toEqual(['codex']);
  });

  it('copies the rollout into raw/ so the source travels with the bundle', async () => {
    const { dir } = await sealCodex('codex-rollout-v2.jsonl');
    const raw = readdirSync(join(dir, 'raw', 'claude-code'));
    expect(raw).toContain('codex-rollout-v2.jsonl');
  });

  it('links each rebuilt pre-capture to the intent it came from, so nothing is counted twice', async () => {
    const { events } = await sealCodex('codex-rollout-evasions.jsonl');
    const intents = events.filter((e) => e.type === 'tool_call_intent');
    const pres = events.filter((e) => e.type === 'shell_command_pre');

    expect(pres.length).toBeGreaterThan(0);
    // A rebuilt pre-capture describes the same command as the intent
    // above it, so the merge links them and emits no gap for either.
    const linked = intents.filter((e) => e.correlation?.linkedShellCommandPreId !== undefined);
    expect(linked).toHaveLength(pres.length);
    expect(events.filter((e) => e.type === 'gap')).toHaveLength(0);
    // The one intent with no pre-capture is the call whose arguments did
    // not parse, which is kept precisely because it could not be read.
    expect(intents.length - linked.length).toBe(1);
  });

  it('fires the destructive ruleset through every evasion shape', async () => {
    const { manifest } = await sealCodex('codex-rollout-evasions.jsonl');
    // sudo, env with an assignment, cd-then-rm, and the same inside a
    // subshell reached through a string command argument.
    expect(manifest.counts.destructiveOperations).toBeGreaterThanOrEqual(4);
  });

  it('leaves sourceFormat off a Claude bundle, which has one grammar', async () => {
    const merged = loadAndMergeEvents({
      jsonlPath: join(fixtures, '../terraform-destroy.jsonl'),
      agentId: 'claude-code',
      sessionId: 'claude-session',
      captureDir: join(workDir, 'captures'),
    });
    expect(merged.sourceFormat).toBeNull();
  });
});

// The tests above drive the pipeline directly, which covers the mapping
// and skips the four lines that read the flag. Those four lines carried a
// real defect: commander's `--agent-id` default of "claude-code" shadowed
// the codex-derived one, so every Codex bundle was sealed claiming it came
// from Claude Code. Nothing above would have noticed.
describe('the --from-codex flag itself', () => {
  const exit = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`process.exit(${code ?? 0})`);
  }) as never);
  const log = vi.spyOn(console, 'log').mockImplementation(() => {});

  afterEach(() => {
    exit.mockClear();
    log.mockClear();
  });

  async function record(flag: string, fixture: string): Promise<Manifest> {
    const out = join(workDir, 'cli-out');
    await main(['package', flag, fixture, '--output', out, '--skip-timestamp']);
    const dir = readdirSync(out).find((d) => d.startsWith('incident-'));
    expect(dir, 'no bundle was written').toBeDefined();
    return JSON.parse(readFileSync(join(out, dir!, 'manifest.json'), 'utf-8')) as Manifest;
  }

  it('seals a Codex rollout as codex, not as claude-code', async () => {
    const manifest = await record('--from-codex', join(fixtures, 'codex-rollout-v2.jsonl'));
    expect(manifest.session.agentId).toBe('codex');
    expect(manifest.session.sourceFormat).toBe('codex-rollout-v2');
  });

  it('still seals a Claude session as claude-code, with no sourceFormat', async () => {
    const manifest = await record('--from-claude', join(fixtures, '../terraform-destroy.jsonl'));
    expect(manifest.session.agentId).toBe('claude-code');
    expect(manifest.session.sourceFormat).toBeUndefined();
  });

  it('honours an explicit --agent-id over the source flag', async () => {
    const out = join(workDir, 'cli-out-explicit');
    await main([
      'package',
      '--from-codex',
      join(fixtures, 'codex-rollout-v2.jsonl'),
      '--agent-id',
      'shell',
      '--output',
      out,
      '--skip-timestamp',
    ]);
    const dir = readdirSync(out).find((d) => d.startsWith('incident-'))!;
    const manifest = JSON.parse(readFileSync(join(out, dir, 'manifest.json'), 'utf-8')) as Manifest;
    expect(manifest.session.agentId).toBe('shell');
  });
});
