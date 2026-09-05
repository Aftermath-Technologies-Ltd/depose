// packages/core/test/normalize.capture.test.ts
//
// Phase 3 acceptance tests: capture record normalization and merge integration.
// Acceptance criteria: docs/capture-coverage.md.
//
// Tests validate:
//   1. Hook capture record -> normalize -> merge links to tool_result
//   2. Shim capture record -> normalize -> correct source attribution
//   3. Gap events for tool_results without pre-capture
//   4. Gap events for pre-captures without tool_results
//   5. Malformed capture records produce warnings
//   6. Non-existent capture directory returns empty

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
} from '../src/index.js';

// ── Test fixtures ────────────────────────────────────────────────────

let testDir: string;
let captureDir: string;

function setup(): void {
  testDir = join(tmpdir(), `depose-p3-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  captureDir = join(testDir, 'captures');
  mkdirSync(captureDir, { recursive: true });
}

function teardown(): void {
  if (testDir && existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
}

/**
 * Turn a readable label into a valid 26-character Crockford Base32 ULID.
 * The normalizer rejects filenames that are not valid ULIDs, because the
 * filename becomes the event id and an unvalidated one used to be
 * accepted verbatim. Keeping the label as a prefix keeps failures legible.
 */
function testUlid(label: string): string {
  const cleaned = label
    .toUpperCase()
    .replace(/[ILOU]/g, '0') // excluded from the Crockford alphabet
    .replace(/[^0-9A-Z]/g, '0');
  return (cleaned + '0'.repeat(26)).slice(0, 26);
}

function writeCaptureFile(dir: string, label: string, payload: ShellCommandPrePayload): string {
  const ulid = testUlid(label);
  writeFileSync(join(dir, `${ulid}.json`), JSON.stringify(payload), 'utf-8');
  return ulid;
}

const makePayload = (overrides: Partial<ShellCommandPrePayload> = {}): ShellCommandPrePayload => ({
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
});

// ── Phase 3 Acceptance Tests ────────────────────────────────────────

describe('Phase 3 acceptance: normalizeCaptureRecords', () => {
  beforeEach(setup);
  afterEach(teardown);

  it('acceptance 1: hook capture record normalizes and links to tool_result in merge', () => {
    // Write a capture record from hook
    writeCaptureFile(captureDir, '01HKAAAAACCEPTANCE00001', makePayload({
      argv: ['bash', '-c', 'terraform destroy -auto-approve'],
      cwd: '/tmp/project',
      source: 'claude-pretooluse',
    }));

    // Normalize capture records
    const captureResult = normalizeCaptureRecords(captureDir, {
      sessionId: 'acceptance-test-1',
    });
    expect(captureResult.recordCount).toBe(1);
    expect(captureResult.events).toHaveLength(1);

    const captureEvent = captureResult.events[0]!;
    expect(captureEvent.type).toBe('shell_command_pre');
    const payload = captureEvent.payload as ShellCommandPrePayload;
    expect(payload.argv).toEqual(['bash', '-c', 'terraform destroy -auto-approve']);
    expect(payload.source).toBe('claude-pretooluse');
    expect(payload.cwd).toBe('/tmp/project');
    expect(captureEvent.agentId).toBe('claude-code');

    // Create a matching tool_result event
    const toolResultEvent: Event = {
      id: generateUlid(),
      wallTs: captureEvent.wallTs,
      monoNs: captureEvent.monoNs + 1n,
      sessionId: 'acceptance-test-1',
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

    // Merge: capture events + tool result
    const { events: merged, gapCount: _gapCount, linkedCount } = mergeEvents(
      { captureEvents: captureResult.events, claudeCodeEvents: [toolResultEvent] },
      { sessionId: 'acceptance-test-1' }
    );

    // Verify: linked (shell_command_pre matched to tool_result)
    expect(linkedCount).toBeGreaterThan(0);
    // And no gap for this tool_result (it has a matching pre)
    const gapsForThisResult = merged.filter(
      (e) => e.type === 'gap' && (e.payload as { affectedEventIds?: string[] }).affectedEventIds?.includes(toolResultEvent.id)
    );
    expect(gapsForThisResult).toHaveLength(0);
  });

  it('acceptance 2: shim capture record normalizes with shell agentId', () => {
    writeCaptureFile(captureDir, '01HKAAAASHIMTEST000001', makePayload({
      argv: ['terraform', 'destroy', '-auto-approve'],
      source: 'shell-shim',
      user: 'developer',
      envSubset: { AWS_REGION: 'us-east-1' },
    }));

    const captureResult = normalizeCaptureRecords(captureDir, {
      sessionId: 'acceptance-test-2',
    });

    expect(captureResult.recordCount).toBe(1);
    const event = captureResult.events[0]!;
    const payload = event.payload as ShellCommandPrePayload;

    expect(event.agentId).toBe('shell'); // shell-shim -> 'shell' agentId
    expect(payload.argv[0]).toBe('terraform');
    expect(payload.argv[1]).toBe('destroy');
    expect(payload.source).toBe('shell-shim');
    expect(payload.user).toBe('developer');
  });

  it('acceptance 3: gap event when tool_result has no pre-capture', () => {
    // Tool result without any capture records
    const toolResultEvent: Event = {
      id: generateUlid(),
      wallTs: new Date().toISOString(),
      monoNs: 0n,
      sessionId: 'acceptance-test-3',
      agentId: 'claude-code',
      parentEventId: null,
      type: 'tool_result',
      payload: {
        toolName: 'Bash',
        output: 'some output',
        exitCode: 0,
      },
      payloadHash: 'fake-hash',
    };

    // Merge with no capture events
    const { events: merged, gapCount } = mergeEvents(
      { claudeCodeEvents: [toolResultEvent] },
      { sessionId: 'acceptance-test-3' }
    );

    // Verify: gap event emitted
    expect(gapCount).toBe(1);
    const gapEvent = merged.find((e) => e.type === 'gap');
    expect(gapEvent).toBeDefined();
    const gapPayload = gapEvent!.payload as { reason: string; affectedEventIds: string[] };
    expect(gapPayload.reason).toBe('tool_result_without_pre_capture');
    expect(gapPayload.affectedEventIds).toContain(toolResultEvent.id);
  });

  it('acceptance 4: gap event for pre_capture without tool_result', () => {
    // A shell_command_pre with no matching tool_result
    writeCaptureFile(captureDir, '01HKAAAAPRECAGAPS0001', makePayload({
      argv: ['terraform', 'apply'],
      source: 'shell-shim',
    }));

    const captureResult = normalizeCaptureRecords(captureDir, {
      sessionId: 'acceptance-test-4',
    });

    // Merge with no tool results
    const { events: merged, gapCount } = mergeEvents(
      { captureEvents: captureResult.events },
      { sessionId: 'acceptance-test-4' }
    );

    // Verify: gap event for unmatched pre_capture
    expect(gapCount).toBe(1);
    const gapEvent = merged.find((e) => e.type === 'gap');
    expect(gapEvent).toBeDefined();
    const gapPayload = gapEvent!.payload as { reason: string; affectedEventIds: string[] };
    expect(gapPayload.reason).toBe('pre_capture_without_tool_result');
  });

  it('multiple capture records normalize with correct count and sorting', () => {
    for (let i = 0; i < 3; i++) {
      writeCaptureFile(captureDir, `01HKAAAA${i.toString().padStart(17, '0')}`, makePayload({
        argv: ['cmd' + i],
        source: i % 2 === 0 ? 'claude-pretooluse' : 'shell-shim',
      }));
    }

    const result = normalizeCaptureRecords(captureDir, {
      sessionId: 'test-multi',
    });

    expect(result.recordCount).toBe(3);
    expect(result.events).toHaveLength(3);
    expect(result.events[0]!.type).toBe('shell_command_pre');
  });

  it('returns empty for non-existent directory', () => {
    const result = normalizeCaptureRecords('/nonexistent/dir', {
      sessionId: 'test',
    });
    expect(result.events).toHaveLength(0);
    expect(result.recordCount).toBe(0);
  });

  it('skips malformed capture records and reports warnings', () => {
    writeCaptureFile(captureDir, '01HKVALID00000000000001', makePayload({
      argv: ['valid'],
    }));

    writeFileSync(join(captureDir, '01HKINVALID00000000001.json'), '{ bad json', 'utf-8');
    writeFileSync(join(captureDir, '01HKNOARGV000000000001.json'), '{"cwd":"/tmp"}', 'utf-8');

    const result = normalizeCaptureRecords(captureDir, {
      sessionId: 'test-malformed',
    });

    expect(result.recordCount).toBe(1);
    // Both bad-json and missing-argv should produce warnings
    expect(result.warnings.length).toBeGreaterThanOrEqual(1);
  });

  it('sessionId defaults to generated ULID when not provided', () => {
    writeCaptureFile(captureDir, '01HKDEFAULTSESS00000001', makePayload());

    const result = normalizeCaptureRecords(captureDir);
    expect(result.events).toHaveLength(1);
    expect(result.events[0]!.sessionId).toBeTruthy();
    // Should be a valid ULID (26 chars)
    expect(result.events[0]!.sessionId.length).toBe(26);
  });
});