// packages/bundle/test/disclosure.roundtrip.test.ts
//
// Seal, disclose, verify from the disclosure alone. Both example
// incidents go through the real pipeline (normalize, merge, seal with a
// chain and commitments, disclose a subset with two fields withheld) and
// the Go verifier proves the disclosure with no access to the original.
// A 60-event synthetic session discloses 40. Consistency between two
// seals of a growing session is checked through --consistent-with.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import {
  normalizeClaudeCodeJsonl,
  mergeEvents,
  loadRuleset,
  setFixedUlidSeed,
  clearFixedUlidSeed,
  parseEventLine,
  isCommitmentPlaceholder,
  type Event,
} from '@depose/core';
import { generateEd25519KeyPair } from '@depose/chain';
import { writeBundle, buildDisclosure } from '../src/index.js';

const rulesPath = join(__dirname, '../../cli/rules/destructive.default.yaml');
const examplesDir = join(__dirname, '../../../examples');
const outputRoot = join(__dirname, 'test-output-disclosure');
const verifyBinary = process.env.DEPOSE_VERIFY_PATH || join(__dirname, '../../../apps/verify/build/depose-verify');
const hasBinary = () => existsSync(verifyBinary);

function runVerify(args: string): { exitCode: number; stdout: string } {
  try {
    return { exitCode: 0, stdout: execSync(`${verifyBinary} ${args}`, { encoding: 'utf-8' }) };
  } catch (err) {
    const e = err as { status?: number; stdout?: string };
    return { exitCode: e.status ?? 1, stdout: e.stdout ?? '' };
  }
}

function statusOf(stdout: string, check: string): string | null {
  const m = stdout.match(new RegExp(`\\] ${check}: (\\w+)`));
  return m ? m[1]! : null;
}

async function seal(events: Event[], name: string, mode: 'signed' | 'dev-unsigned'): Promise<string> {
  const ruleset = loadRuleset(rulesPath);
  const { depopPath } = await writeBundle(events, ruleset.rules, {
    sessionId: name,
    agentId: 'claude-code',
    version: '0.1.0',
    producedAt: '2025-05-18T16:00:00.000Z',
    sessionStartedAt: '2025-05-18T15:30:00.000Z',
    sessionEndedAt: '2025-05-18T15:31:00.000Z',
    rules: ruleset.rules,
    rulesetBytes: readFileSync(rulesPath),
    outputDir: outputRoot,
    keyPair: generateEd25519KeyPair(),
    mode,
    disclosable: ruleset.disclosable,
    injectedTimestamps: mode === 'signed'
      ? [{ tsa: 'test-tsa', timestamp: '2025-05-18T16:00:30.000Z', tokenBase64: Buffer.from('fake').toString('base64') }]
      : undefined,
  });
  return depopPath;
}

function eventsFromExample(example: string): Event[] {
  const jsonl = readFileSync(join(examplesDir, example, 'session.synthetic.jsonl'), 'utf-8');
  const { events, sessionId } = normalizeClaudeCodeJsonl(jsonl);
  return mergeEvents({ claudeCodeEvents: events }, { sessionId }).events;
}

function syntheticSession(count: number): Event[] {
  const lines: string[] = [];
  for (let i = 0; i < count; i++) {
    const ts = new Date(Date.UTC(2025, 4, 18, 15, 30, i)).toISOString();
    lines.push(JSON.stringify({ type: 'assistant', content: `step ${i}`, timestamp: ts, session_id: 's60',
      tool_calls: [{ tool_name: 'Bash', input: { command: `echo step-${i}` } }] }));
  }
  const { events, sessionId } = normalizeClaudeCodeJsonl(lines.join('\n'));
  return mergeEvents({ claudeCodeEvents: events }, { sessionId }).events;
}

describe('disclosure round trip through depose-verify', () => {
  beforeEach(() => {
    rmSync(outputRoot, { recursive: true, force: true });
    mkdirSync(outputRoot, { recursive: true });
  });
  afterEach(() => {
    clearFixedUlidSeed();
    rmSync(outputRoot, { recursive: true, force: true });
  });

  it.each(['datatalks-reconstruction', 'pocketos-reconstruction'])(
    '%s: discloses a subset with two fields withheld and verifies without the original',
    async (example) => {
      if (!hasBinary()) return;
      const bundle = await seal(eventsFromExample(example), `disc-${example}`, 'dev-unsigned');
      const ids = readFileSync(join(bundle, 'events.jsonl'), 'utf-8').trim().split('\n').map((l) => parseEventLine(l).id);
      // Everything but the last two events, so every event type is disclosed.
      const indices = ids.map((_, i) => i).slice(0, -2);
      const out = join(outputRoot, `${example}-disclosure`);
      const result = buildDisclosure({
        bundleDir: bundle, outDir: out, indices, fields: ['/toolInput', '/argv'],
        version: '0.1.0', producedAt: '2025-05-18T17:00:00.000Z',
      });
      expect(result.document.fields.withheld).toContain('/output');
      expect(result.document.fields.withheld).toContain('/toolCalls');

      // The original is gone; only the disclosure remains.
      rmSync(bundle, { recursive: true, force: true });
      const { exitCode, stdout } = runVerify(`verify ${out}`);
      expect(exitCode).toBe(0);
      expect(stdout).toContain(`disclosure (${indices.length} of ${ids.length} sealed events disclosed)`);
      expect(statusOf(stdout, 'disclosure-inclusion')).toBe('PASS');
      expect(statusOf(stdout, 'disclosure-commitments')).toBe('PASS');
      expect(statusOf(stdout, 'disclosure-files')).toBe('PASS');

      // Withheld fields stay committed in the disclosed events.
      const disclosed = readFileSync(join(out, 'events.jsonl'), 'utf-8').trim().split('\n').map((l) => parseEventLine(l));
      const withOutput = disclosed.filter((e) => e.type === 'tool_result');
      expect(withOutput.length).toBeGreaterThan(0);
      for (const e of withOutput) {
        expect(isCommitmentPlaceholder((e.payload as { output: unknown }).output)).toBe(true);
      }
    }
  );

  it('signed bundle: signature and inclusion pass against the original manifest', async () => {
    if (!hasBinary()) return;
    const bundle = await seal(eventsFromExample('pocketos-reconstruction'), 'disc-signed', 'signed');
    const out = join(outputRoot, 'signed-disclosure');
    buildDisclosure({ bundleDir: bundle, outDir: out, indices: [1, 2, 3], fields: 'all', version: '0.1.0', producedAt: '2025-05-18T17:00:00.000Z' });
    rmSync(bundle, { recursive: true, force: true });
    const { stdout } = runVerify(`verify ${out}`);
    expect(statusOf(stdout, 'signature-verify')).toBe('PASS');
    expect(statusOf(stdout, 'disclosure-parse')).toBe('PASS');
    expect(statusOf(stdout, 'disclosure-inclusion')).toBe('PASS');
    expect(statusOf(stdout, 'disclosure-commitments')).toBe('PASS');
    // The injected token is fake, so only the timestamp check fails.
    expect(statusOf(stdout, 'timestamp-verify')).toBe('FAIL');
  });

  it('discloses 40 of 60 events', async () => {
    if (!hasBinary()) return;
    const bundle = await seal(syntheticSession(60), 'disc-60', 'dev-unsigned');
    const total = readFileSync(join(bundle, 'events.jsonl'), 'utf-8').trim().split('\n').length;
    const out = join(outputRoot, 'sixty');
    const result = buildDisclosure({
      bundleDir: bundle, outDir: out, indices: Array.from({ length: 40 }, (_, i) => i + 10), fields: ['/toolInput'],
      version: '0.1.0', producedAt: '2025-05-18T17:00:00.000Z',
    });
    expect(result.disclosedCount).toBe(40);
    expect(result.withheldCount).toBe(total - 40);
    rmSync(bundle, { recursive: true, force: true });
    const { exitCode, stdout } = runVerify(`verify ${out}`);
    expect(exitCode).toBe(0);
    expect(stdout).toContain(`40 of ${total} sealed events disclosed`);
  });

  it('a later, larger seal of the same session proves consistency with an earlier disclosure', async () => {
    if (!hasBinary()) return;
    setFixedUlidSeed(1716043800000);
    const all = syntheticSession(9);
    const earlierBundle = await seal(all.slice(0, 6), 'consist-a', 'dev-unsigned');
    setFixedUlidSeed(1716043800000);
    const laterBundle = await seal(all, 'consist-b', 'dev-unsigned');
    const earlier = join(outputRoot, 'earlier');
    const later = join(outputRoot, 'later');
    buildDisclosure({ bundleDir: earlierBundle, outDir: earlier, indices: [0, 1], fields: 'all', version: '0.1.0', producedAt: '2025-05-18T17:00:00.000Z' });
    const result = buildDisclosure({
      bundleDir: laterBundle, outDir: later, indices: [0, 1, 7], fields: 'all', version: '0.1.0',
      producedAt: '2025-05-18T18:00:00.000Z', consistentWith: earlier,
    });
    expect(result.document.consistency?.earlierLeafCount).toBe(6);
    expect(result.document.consistency?.proof.length).toBeGreaterThan(0);
    const { exitCode, stdout } = runVerify(`consistency ${earlier} ${later}`);
    expect(exitCode).toBe(0);
    expect(statusOf(stdout, 'tree-consistency')).toBe('PASS');
    expect(statusOf(stdout, 'disclosed-overlap')).toBe('PASS');

    // Without the proof the later disclosure cannot be tied to the earlier one.
    const bare = join(outputRoot, 'later-bare');
    buildDisclosure({ bundleDir: laterBundle, outDir: bare, indices: [0], fields: 'all', version: '0.1.0', producedAt: '2025-05-18T18:00:00.000Z' });
    expect(runVerify(`consistency ${earlier} ${bare}`).exitCode).not.toBe(0);
  });

  it('refuses to disclose from a bundle whose events do not reproduce its root', async () => {
    const bundle = await seal(eventsFromExample('datatalks-reconstruction'), 'disc-bad', 'dev-unsigned');
    const eventsPath = join(bundle, 'events.jsonl');
    const lines = readFileSync(eventsPath, 'utf-8');
    const idx = lines.indexOf('"chainHash":"') + '"chainHash":"'.length;
    const flipped = lines[idx] === '0' ? '1' : '0';
    writeFileSync(eventsPath, lines.slice(0, idx) + flipped + lines.slice(idx + 1));
    expect(() => buildDisclosure({ bundleDir: bundle, outDir: join(outputRoot, 'x'), indices: [0], fields: 'all', version: '0.1.0', producedAt: 't' }))
      .toThrow(/does not reproduce manifest.merkleRoot/);
  });
});
