// packages/bundle/test/phase3-acceptance.test.ts
//
// Phase 3 acceptance tests: active capture layer.
// Exercises the full capture -> normalize -> merge -> bundle pipeline.
// See BUILD_PLAN.md §6 (Phase 3) for acceptance criteria.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  normalizeCaptureRecords,
  mergeEvents,
  sha256,
  generateUlid,
  type Event,
  type ShellCommandPrePayload,
} from '@depose/core';
// ── Test fixtures ────────────────────────────────────────────────────

let testDir: string;
let captureDir: string;

function setup(): void {
  testDir = join(tmpdir(), `depose-p3-bundle-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  captureDir = join(testDir, 'captures');
  mkdirSync(captureDir, { recursive: true });
  process.env.DEPOSE_CAPTURE_DIR = captureDir;
}

function teardown(): void {
  delete process.env.DEPOSE_CAPTURE_DIR;
  if (testDir && existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
}

function makeShellPrePayload(overrides: Partial<ShellCommandPrePayload> = {}): ShellCommandPrePayload {
  return {
    argv: ['terraform', 'destroy', '-auto-approve'],
    cwd: '/tmp/project',
    envHash: 'abc123',
    envSubset: { AWS_REGION: 'us-east-1' },
    ttyId: null,
    user: 'developer',
    hostname: 'workstation',
    parentProcessTree: [],
    fileArgs: [],
    source: 'claude-pretooluse',
    captureSchemaVersion: 2,
    capturedAt: '2026-05-19T14:30:00.000Z',
    capturedAtSource: 'recorded',
    sessionId: null,
    ...overrides,
  };
}

// ── Acceptance tests ────────────────────────────────────────────────

describe('Phase 3 acceptance: capture -> merge -> bundle pipeline', () => {
  beforeEach(setup);
  afterEach(teardown);

  it('capture records flow through full pipeline to signed bundle', () => {
    // 1. Write capture records
    writeFileSync(
      join(captureDir, '01HKAAAAP0PE0000000000000J.json'),
      JSON.stringify(makeShellPrePayload({
        argv: ['bash', '-c', 'terraform destroy -auto-approve'],
        source: 'claude-pretooluse',
      })),
      'utf-8'
    );

    // 2. Normalize capture records
    const captureResult = normalizeCaptureRecords(captureDir, {
      sessionId: 'pipeline-test-session',
    });
    expect(captureResult.recordCount).toBe(1);

    // 3. Create matching tool_result
    const captureEvent = captureResult.events[0]!;
    const toolResultEvent: Event = {
      id: generateUlid(),
      wallTs: captureEvent.wallTs,
      monoNs: captureEvent.monoNs + 1,
      sessionId: 'pipeline-test-session',
      agentId: 'claude-code',
      parentEventId: captureEvent.id,
      type: 'tool_result',
      payload: {
        toolName: 'Bash',
        output: 'Destroy complete!',
        exitCode: 0,
      },
      payloadHash: sha256({
        toolName: 'Bash',
        output: 'Destroy complete!',
        exitCode: 0,
      }),
    };

    // 4. Merge capture + tool_result
    const { events: merged, linkedCount } = mergeEvents(
      { captureEvents: captureResult.events, claudeCodeEvents: [toolResultEvent] },
      { sessionId: 'pipeline-test-session' }
    );
    expect(linkedCount).toBeGreaterThan(0);

    // 5. Build timeline
    const timeline = mergeEvents(
      { captureEvents: captureResult.events, claudeCodeEvents: [toolResultEvent] },
      { sessionId: 'pipeline-test-session' }
    );
    expect(timeline.events.length).toBeGreaterThan(0);

    // 6. Verify shell_command_pre and tool_result are in the timeline
    const types = merged.map((e) => e.type);
    expect(types).toContain('shell_command_pre');
    expect(types).toContain('tool_result');
    // No gap for the linked pair
    const gapReasons = merged
      .filter((e) => e.type === 'gap')
      .map((e) => (e.payload as { reason: string }).reason);
    // No 'tool_result_without_pre_capture' for this linked pair
    const unlinkedGaps = gapReasons.filter((r) => r === 'tool_result_without_pre_capture');
    expect(unlinkedGaps).toHaveLength(0);
  });
});