// packages/bundle/test/e2e.files-map.test.ts
//
// Negative tests for the signed files map, run through the real Go
// verifier. Before the map existed only events.jsonl, the manifest, and
// the ruleset were pinned: a recipient could swap the raw JSONL, add a
// file, delete a timestamp token, or truncate the narrative and the
// bundle still printed PASS. Each of those must now fail a named check.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync, truncateSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import { normalizeClaudeCodeJsonl, loadDestructiveRules } from '@depose/core';
import { generateEd25519KeyPair } from '@depose/chain';
import { writeBundle } from '../src/index.js';

const rulesPath = join(__dirname, '../../cli/rules/destructive.default.yaml');
const outputDir = join(__dirname, 'test-output-files-map');
const verifyBinary = process.env.DEPOSE_VERIFY_PATH ||
  join(__dirname, '../../../apps/verify/build/depose-verify');

const FAKE_TIMESTAMP = [{
  tsa: 'test-tsa',
  timestamp: '2025-05-18T15:31:30.000Z',
  tokenBase64: Buffer.from('fake-rfc3161-token-for-tests').toString('base64'),
}];

function runVerify(bundlePath: string): { exitCode: number; stdout: string } {
  try {
    return { exitCode: 0, stdout: execSync(`${verifyBinary} verify ${bundlePath}`, { encoding: 'utf-8' }) };
  } catch (err) {
    const e = err as { status?: number; stdout?: string };
    return { exitCode: e.status ?? 1, stdout: e.stdout ?? '' };
  }
}

/** The status line the report prints for one check, e.g. "files-map: FAIL". */
function statusOf(stdout: string, check: string): string | null {
  const m = stdout.match(new RegExp(`\\] ${check}: (\\w+)`));
  return m ? m[1]! : null;
}

async function sealBundle(): Promise<string> {
  const srcDir = join(outputDir, 'src');
  mkdirSync(srcDir, { recursive: true });
  const jsonlPath = join(srcDir, 'session.jsonl');
  writeFileSync(jsonlPath, [
    JSON.stringify({ type: 'user', content: 'clean up', timestamp: '2025-05-18T15:30:00.000Z', session_id: 's1' }),
    JSON.stringify({ type: 'assistant', content: 'ok', timestamp: '2025-05-18T15:30:05.000Z', session_id: 's1',
      tool_calls: [{ tool_name: 'Bash', input: { command: 'rm -rf /data/training' } }] }),
  ].join('\n') + '\n');
  const { events } = normalizeClaudeCodeJsonl(readFileSync(jsonlPath, 'utf-8'));
  const rules = loadDestructiveRules(rulesPath);
  const { depopPath } = await writeBundle(events, rules, {
    sessionId: 'sess-files-map',
    agentId: 'claude-code',
    version: '0.1.0',
    producedAt: '2025-05-18T16:00:00.000Z',
    sessionStartedAt: '2025-05-18T15:30:00.000Z',
    sessionEndedAt: '2025-05-18T15:31:00.000Z',
    rules,
    rulesetBytes: readFileSync(rulesPath),
    outputDir,
    keyPair: generateEd25519KeyPair(),
    mode: 'signed',
    injectedTimestamps: FAKE_TIMESTAMP,
    sourceJsonlPath: jsonlPath,
  });
  return depopPath;
}

describe('files map through depose-verify', () => {
  beforeEach(() => {
    rmSync(outputDir, { recursive: true, force: true });
    mkdirSync(outputDir, { recursive: true });
  });
  afterEach(() => rmSync(outputDir, { recursive: true, force: true }));

  const skip = () => !existsSync(verifyBinary);

  it('passes files-map and attestation-files on an untouched bundle', async () => {
    if (skip()) return;
    const bundle = await sealBundle();
    const manifest = JSON.parse(readFileSync(join(bundle, 'manifest.json'), 'utf-8'));
    expect(Object.keys(manifest.files)).toEqual([
      'commitments.json', 'events.jsonl', 'narrative.html', 'narrative.md', 'raw/claude-code/session.jsonl',
      'rules/destructive.yaml', 'verify.txt',
    ]);
    const { stdout } = runVerify(bundle);
    expect(statusOf(stdout, 'files-map')).toBe('PASS');
    expect(statusOf(stdout, 'attestation-files')).toBe('PASS');
  });

  it('fails files-map when the raw JSONL is swapped for different content', async () => {
    if (skip()) return;
    const bundle = await sealBundle();
    const raw = join(bundle, 'raw/claude-code/session.jsonl');
    const original = readFileSync(raw, 'utf-8');
    writeFileSync(raw, original.replace('rm -rf /data/training', 'ls -la /data/training'));
    const { exitCode, stdout } = runVerify(bundle);
    expect(exitCode).not.toBe(0);
    expect(statusOf(stdout, 'files-map')).toBe('FAIL');
    expect(stdout).toContain('raw/claude-code/session.jsonl: sha256 mismatch');
  });

  it('fails files-map when a file is appended to the tree', async () => {
    if (skip()) return;
    const bundle = await sealBundle();
    writeFileSync(join(bundle, 'raw', 'extra-notes.txt'), 'planted after sealing');
    const { exitCode, stdout } = runVerify(bundle);
    expect(exitCode).not.toBe(0);
    expect(statusOf(stdout, 'files-map')).toBe('FAIL');
    expect(stdout).toContain('raw/extra-notes.txt is on disk but not in the files map');
  });

  it('fails attestation-files when a timestamp token is deleted', async () => {
    if (skip()) return;
    const bundle = await sealBundle();
    rmSync(join(bundle, 'attestations/rfc3161-timestamps/0.tsr'));
    const { exitCode, stdout } = runVerify(bundle);
    expect(exitCode).not.toBe(0);
    expect(statusOf(stdout, 'attestation-files')).toBe('FAIL');
    expect(stdout).toContain('0.tsr is missing');
  });

  it('fails files-map when the narrative is truncated', async () => {
    if (skip()) return;
    const bundle = await sealBundle();
    truncateSync(join(bundle, 'narrative.md'), 40);
    const { exitCode, stdout } = runVerify(bundle);
    expect(exitCode).not.toBe(0);
    expect(statusOf(stdout, 'files-map')).toBe('FAIL');
    expect(stdout).toContain('narrative.md: length mismatch');
  });

  it('fails files-map when a pinned file is deleted', async () => {
    if (skip()) return;
    const bundle = await sealBundle();
    rmSync(join(bundle, 'verify.txt'));
    const { exitCode, stdout } = runVerify(bundle);
    expect(exitCode).not.toBe(0);
    expect(stdout).toContain('verify.txt is in the files map but not on disk');
  });

  it('fails files-map when the tree contains a symlink', async () => {
    if (skip()) return;
    const bundle = await sealBundle();
    symlinkSync(join(bundle, 'events.jsonl'), join(bundle, 'raw', 'events-link.jsonl'));
    const { exitCode, stdout } = runVerify(bundle);
    expect(exitCode).not.toBe(0);
    expect(stdout).toContain('symlink');
  });

  it('fails attestation-files when signatures.json disagrees with the manifest', async () => {
    if (skip()) return;
    const bundle = await sealBundle();
    writeFileSync(join(bundle, 'attestations/signatures.json'), JSON.stringify({ blocks: [] }));
    const { exitCode, stdout } = runVerify(bundle);
    expect(exitCode).not.toBe(0);
    expect(statusOf(stdout, 'attestation-files')).toBe('FAIL');
  });
});
