// packages/cli/test/hook-intent-effect-session.ts
//
// Builds the session the intent-and-effect tests run against, by driving
// the real Claude Code hooks over five tool calls against real files.
//
// Every clock and every environment read is injected, and the working
// directory is a fixed absolute path rather than a temp directory,
// because the recorded file paths go into the Go verifier's golden
// fixture and have to be the same on every machine.

import { expect } from 'vitest';
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  runHook,
  writeCaptureRecord,
  type HookDeps,
  type EffectDeps,
} from '@depose/capture-claude';
import {
  loadDestructiveRules,
  generateUlid,
  type Event,
  type GapPayload,
  type ExecveRecordPayload,
} from '@depose/core';
import { writeBundle } from '@depose/bundle';
import { loadAndMergeEvents } from '../src/pipeline.js';
import { DEFAULT_RULES_PATH } from '../src/rules-default.js';

// A fixed absolute path, not a temp directory: the recorded file paths go
// into the golden bundle, so they have to be the same on every machine.
export const WORK_DIR = '/tmp/depose-golden-intent-effect';
const OUT_DIR = join(WORK_DIR, 'out');
export const CAPTURE_DIR = join(WORK_DIR, 'captures');
export const MAIN_TF = join(WORK_DIR, 'main.tf');
const STATE_JSON = join(WORK_DIR, 'state.json');
export const GOLDEN_DIR = join(__dirname, '../../../apps/verify/testdata/golden-intent-effect');
export const verifyBinary = process.env.DEPOSE_VERIFY_PATH || join(__dirname, '../../../apps/verify/build/depose-verify');

const SESSION = 'sess-intent-effect';
export const BASE_MS = Date.UTC(2025, 4, 18, 15, 30, 0);
const HOOK_PIDS = [{ pid: 4242, ppid: 4200, exe: '/usr/bin/node', argv0: 'node' }];
const FIXED_ENV = { USER: 'depose', LOGNAME: 'depose', HOSTNAME: 'evidence-host', AWS_REGION: 'us-east-1' };

let tick = 0;

/** Reset the injected clock; call from beforeEach so runs are identical. */
export function resetClock(): void {
  tick = 0;
}

const nextTime = (): Date => new Date(BASE_MS + ++tick * 1000);

function hookDeps(input: unknown): Partial<HookDeps> {
  return {
    readStdin: async () => JSON.stringify(input),
    env: () => FIXED_ENV,
    walkProcessTree: () => HOOK_PIDS,
    resolveTty: () => '/dev/pts/3',
    now: nextTime,
  };
}

function effectDeps(): Partial<EffectDeps> {
  return { now: nextTime, monoNs: () => BigInt(tick) * 1_000_000n };
}

async function pre(toolName: string, toolInput: Record<string, unknown>): Promise<void> {
  const outcome = await runHook(
    hookDeps({ tool_name: toolName, tool_input: toolInput, cwd: WORK_DIR, session_id: SESSION }),
    'pre'
  );
  expect(outcome.ok).toBe(true);
}

async function post(
  toolName: string,
  toolInput: Record<string, unknown>,
  response: Record<string, unknown>
): Promise<void> {
  const outcome = await runHook(
    hookDeps({
      tool_name: toolName,
      tool_input: toolInput,
      cwd: WORK_DIR,
      session_id: SESSION,
      tool_response: response,
    }),
    'post',
    effectDeps()
  );
  expect(outcome.ok).toBe(true);
}

/** A kernel execve record, written straight into the capture store. */
function kernelExecve(argv: string[], ancestry: number[], pid: number): void {
  const record: ExecveRecordPayload = {
    kind: 'execve',
    pid,
    ppid: ancestry[0] ?? 1,
    ancestry,
    comm: argv[0]!.split('/').pop()!.slice(0, 15),
    exe: argv[0]!,
    argv,
    cwd: WORK_DIR,
    monoNs: String(tick * 1_000_000),
    capturedAt: nextTime().toISOString(),
    sessionId: SESSION,
    source: 'kernel',
    captureSchemaVersion: 3,
  };
  // writeCaptureRecord takes the intent shape; the store is untyped JSON
  // and the reader dispatches on `kind`, which is the point of the field.
  writeCaptureRecord(generateUlid(), record as unknown as Parameters<typeof writeCaptureRecord>[1]);
}

/**
 * Run the whole session through both hook halves and seal the bundle.
 *
 * @returns The merged timeline, the bundle path, and the gap count.
 */
export async function buildSession(): Promise<{ events: Event[]; depopPath: string; gapCount: number }> {
  writeFileSync(MAIN_TF, 'resource "aws_s3_bucket" "logs" {}\n');
  writeFileSync(STATE_JSON, '{"version":1}\n');

  // 1. Edit main.tf, closed by its effect.
  const edit = { file_path: MAIN_TF, old_string: 'logs', new_string: 'audit' };
  await pre('Edit', edit);
  writeFileSync(MAIN_TF, 'resource "aws_s3_bucket" "audit" {}\n');
  await post('Edit', edit, { success: true });

  // 2. A destructive command, closed by its effect.
  const destroy = { command: 'sudo terraform destroy -auto-approve' };
  await pre('Bash', destroy);
  await post('Bash', destroy, { exit_code: 0, stdout: 'Destroy complete!' });

  // 3. Something outside the session rewrites main.tf, then the agent
  //    edits it again: the next intent's pre-state disagrees with the
  //    effect's post-state and that has to surface as a gap.
  writeFileSync(MAIN_TF, 'resource "aws_s3_bucket" "audit" { force_destroy = true }\n');
  const edit2 = { file_path: MAIN_TF, old_string: 'force_destroy', new_string: 'lifecycle' };
  await pre('Edit', edit2);
  writeFileSync(MAIN_TF, 'resource "aws_s3_bucket" "audit" { lifecycle = true }\n');
  await post('Edit', edit2, { success: true });

  // 4. A clean pair straight after: main.tf carries forward from the
  //    previous effect's post-state to this intent's pre-state with
  //    nothing in between, which is the continuity the verifier checks.
  const edit3 = { file_path: MAIN_TF, old_string: 'lifecycle', new_string: 'tags' };
  await pre('Edit', edit3);
  writeFileSync(MAIN_TF, 'resource "aws_s3_bucket" "audit" { tags = {} }\n');
  await post('Edit', edit3, { success: true });

  // 5. An intent whose outcome was lost: no post hook ever ran.
  await pre('Bash', { command: 'rm -rf /srv/pocketos/data' });

  // 6. Two kernel execves: one from inside the hook's process tree, one not.
  kernelExecve(['/usr/bin/terraform', 'destroy', '-auto-approve'], [4242, 4200], 5100);
  kernelExecve(['/usr/local/bin/aws', 's3', 'rb', 's3://pocketos-prod', '--force'], [9001, 9000], 9002);

  const jsonlPath = join(WORK_DIR, 'session.jsonl');
  const line = (type: string, content: string, at: number): string =>
    JSON.stringify({ type, content, timestamp: new Date(BASE_MS + at).toISOString(), session_id: SESSION });
  writeFileSync(
    jsonlPath,
    [
      line('user', 'Rename the bucket and tear down the old stack.', 0),
      line('assistant', 'Renaming the bucket, then destroying the stack.', 500),
      line('assistant', 'Stack destroyed.', 30_000),
    ].join('\n') + '\n'
  );

  const merged = loadAndMergeEvents({
    jsonlPath,
    sessionId: SESSION,
    agentId: 'claude-code',
    captureDir: CAPTURE_DIR,
  });

  const rules = loadDestructiveRules(DEFAULT_RULES_PATH);
  const { depopPath } = await writeBundle(merged.events, rules, {
    sessionId: SESSION,
    agentId: 'claude-code',
    version: '0.1.0',
    producedAt: '2025-05-18T16:00:00.000Z',
    sessionStartedAt: '2025-05-18T15:30:00.000Z',
    sessionEndedAt: '2025-05-18T15:31:00.000Z',
    rules,
    rulesetBytes: readFileSync(DEFAULT_RULES_PATH),
    outputDir: OUT_DIR,
    mode: 'dev-unsigned',
    sourceJsonlPath: jsonlPath,
    captureSourceDir: CAPTURE_DIR,
  });
  return { events: merged.events, depopPath, gapCount: merged.gapCount };
}

/** Events of type gap with the given reason, in timeline order. */
export function gapsOf(events: Event[], reason: GapPayload['reason']): Event[] {
  return events.filter((e) => e.type === 'gap' && (e.payload as GapPayload).reason === reason);
}
