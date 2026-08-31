// packages/core/test/normalize.capture-scoping.test.ts
//
// Regression tests for the two defects that made bundles wrong:
//
//   1. The capture store was read unfiltered, so a bundle for one incident
//      absorbed every capture on the machine. A real run produced 18,796
//      events and 34 distinct working directories across five unrelated
//      projects for a 5-line session fixture.
//   2. Capture events were stamped with the bundle production time rather
//      than the capture time, which put every one of them outside the
//      plus or minus 5s correlation window in mergeEvents. Active capture
//      linked nothing in any real post-incident run.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalizeCaptureRecords } from '../src/normalize/capture.js';
import { mergeEvents } from '../src/normalize/merge.js';
import { sha256 } from '../src/events/canonical-json.js';
import type { Event, ShellCommandPrePayload } from '../src/events/schema.js';

let captureDir: string;

const SESSION = 'sess-under-reconstruction';
const OTHER_SESSION = 'sess-some-other-project';

/** Valid 26-character Crockford Base32 ULID built from a readable label. */
function testUlid(label: string): string {
  const cleaned = label.toUpperCase().replace(/[ILOU]/g, '0').replace(/[^0-9A-Z]/g, '0');
  return (cleaned + '0'.repeat(26)).slice(0, 26);
}

function writeRecord(
  label: string,
  overrides: Partial<ShellCommandPrePayload> = {}
): string {
  const ulid = testUlid(label);
  const payload: ShellCommandPrePayload = {
    argv: ['terraform', 'destroy', '-auto-approve'],
    cwd: '/work/project',
    envHash: '0'.repeat(64),
    envSubset: {},
    ttyId: null,
    user: 'dev',
    hostname: 'workstation',
    parentProcessTree: [],
    fileArgs: [],
    source: 'claude-pretooluse',
    captureSchemaVersion: 2,
    capturedAt: '2026-05-19T14:30:00.000Z',
    capturedAtSource: 'recorded',
    sessionId: SESSION,
    ...overrides,
  };
  writeFileSync(join(captureDir, `${ulid}.json`), JSON.stringify(payload), 'utf-8');
  return ulid;
}

beforeEach(() => {
  captureDir = join(tmpdir(), `depose-scope-${process.pid}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(captureDir, { recursive: true });
});

afterEach(() => {
  if (captureDir && existsSync(captureDir)) rmSync(captureDir, { recursive: true, force: true });
});

describe('capture scoping', () => {
  it('keeps only records belonging to the session being reconstructed', () => {
    writeRecord('mine1');
    writeRecord('mine2');
    writeRecord('theirs1', { sessionId: OTHER_SESSION, cwd: '/unrelated/project' });
    writeRecord('theirs2', { sessionId: OTHER_SESSION, cwd: '/another/project' });

    const result = normalizeCaptureRecords(captureDir, {
      scope: { agentSessionId: SESSION },
    });

    expect(result.storeRecordCount).toBe(4);
    expect(result.recordCount).toBe(2);
    expect(result.excluded['other-session']).toBe(2);
  });

  it('keeps no unrelated working directory out of the event stream', () => {
    writeRecord('mine', { cwd: '/work/project' });
    writeRecord('theirs', { sessionId: OTHER_SESSION, cwd: '/Users/someone/secrets' });

    const { events } = normalizeCaptureRecords(captureDir, {
      scope: { agentSessionId: SESSION },
    });

    const cwds = events.map((e) => (e.payload as ShellCommandPrePayload).cwd);
    expect(cwds).toEqual(['/work/project']);
  });

  it('excludes records with no session id rather than guessing', () => {
    writeRecord('shimrecord', { sessionId: null, source: 'shell-shim' });

    const result = normalizeCaptureRecords(captureDir, {
      scope: { agentSessionId: SESSION },
    });

    expect(result.recordCount).toBe(0);
    expect(result.excluded.unattributed).toBe(1);
  });

  it('includes unattributed records inside the window when explicitly opted in', () => {
    writeRecord('shimrecord', {
      sessionId: null,
      source: 'shell-shim',
      capturedAt: '2026-05-19T14:30:30.000Z',
    });

    const result = normalizeCaptureRecords(captureDir, {
      scope: {
        agentSessionId: SESSION,
        startsAt: '2026-05-19T14:30:00.000Z',
        endsAt: '2026-05-19T14:31:00.000Z',
        includeUnattributed: true,
      },
    });

    expect(result.recordCount).toBe(1);
  });

  it('excludes opted-in records that fall outside the session window', () => {
    writeRecord('longago', {
      sessionId: null,
      source: 'shell-shim',
      capturedAt: '2026-01-01T00:00:00.000Z',
    });

    const result = normalizeCaptureRecords(captureDir, {
      scope: {
        agentSessionId: SESSION,
        startsAt: '2026-05-19T14:30:00.000Z',
        endsAt: '2026-05-19T14:31:00.000Z',
        includeUnattributed: true,
      },
    });

    expect(result.recordCount).toBe(0);
    expect(result.excluded['outside-session-window']).toBe(1);
  });

  it('reports the full store size so exclusions can be disclosed, not hidden', () => {
    writeRecord('mine');
    for (let i = 0; i < 5; i++) {
      writeRecord(`other${i}`, { sessionId: OTHER_SESSION });
    }

    const result = normalizeCaptureRecords(captureDir, {
      scope: { agentSessionId: SESSION },
    });

    expect(result.storeRecordCount).toBe(6);
    expect(result.recordCount).toBe(1);
    const excludedTotal = Object.values(result.excluded).reduce((a, b) => a + b, 0);
    expect(excludedTotal).toBe(5);
  });

  it('rejects a filename that is not a valid ULID instead of using it as an event id', () => {
    // I, L, O and U are excluded from the Crockford alphabet.
    writeFileSync(join(captureDir, 'NOT-A-ULID.json'), JSON.stringify({ argv: ['ls'] }), 'utf-8');

    const result = normalizeCaptureRecords(captureDir, {
      scope: { agentSessionId: SESSION },
    });

    expect(result.recordCount).toBe(0);
    expect(result.excluded.malformed).toBe(1);
    expect(result.warnings.join(' ')).toContain('not a valid ULID');
  });
});

describe('capture timestamps', () => {
  it('stamps events with the capture time, not the time the bundle is built', () => {
    writeRecord('timed', { capturedAt: '2026-05-19T14:30:00.000Z' });

    const { events } = normalizeCaptureRecords(captureDir, {
      scope: { agentSessionId: SESSION },
    });

    expect(events[0]!.wallTs).toBe('2026-05-19T14:30:00.000Z');
  });

  it('falls back to the file mtime for v1 records and labels the time as derived', () => {
    const ulid = testUlid('legacyv1');
    writeFileSync(
      join(captureDir, `${ulid}.json`),
      JSON.stringify({
        argv: ['rm', '-rf', '/data'],
        cwd: '/work/project',
        envHash: '0'.repeat(64),
        envSubset: {},
        ttyId: null,
        user: 'dev',
        hostname: 'workstation',
        parentProcessTree: [],
        fileArgs: [],
        source: 'claude-pretooluse',
        captureSchemaVersion: 1,
      }),
      'utf-8'
    );

    const { events } = normalizeCaptureRecords(captureDir, {
      scope: { agentSessionId: null, includeUnattributed: true },
    });

    const payload = events[0]!.payload as ShellCommandPrePayload;
    expect(payload.capturedAtSource).toBe('derived-from-mtime');
    // Written moments ago, so the derived time must be recent rather than
    // the 1970-or-year-10888 values the random ULID prefix decoded to.
    const ageMs = Date.now() - Date.parse(payload.capturedAt);
    expect(ageMs).toBeGreaterThanOrEqual(0);
    expect(ageMs).toBeLessThan(60_000);
  });

  it('links a capture to its tool_result long after the fact', () => {
    // The whole point of active capture: a bundle built weeks after the
    // incident must still correlate the pre-execution record to the
    // result. Under the old production-time stamp this always failed,
    // because every capture landed outside the 5 second match window.
    const capturedAt = '2026-05-19T14:30:00.000Z';
    writeRecord('linkme', {
      argv: ['bash', '-c', 'terraform destroy -auto-approve'],
      cwd: '/work/project',
      capturedAt,
    });

    const { events: captureEvents } = normalizeCaptureRecords(captureDir, {
      scope: { agentSessionId: SESSION },
    });

    const intentPayload = {
      toolName: 'Bash',
      toolUseId: 'tu-1',
      toolInput: { command: 'terraform destroy -auto-approve', cwd: '/work/project' },
    };
    const resultPayload = { toolName: 'Bash', toolUseId: 'tu-1', output: '', exitCode: 0 };

    const claudeCodeEvents: Event[] = [
      {
        id: testUlid('intent'),
        wallTs: capturedAt,
        monoNs: 1,
        sessionId: SESSION,
        agentId: 'claude-code',
        parentEventId: null,
        type: 'tool_call_intent',
        payload: intentPayload,
        payloadHash: sha256(intentPayload),
      },
      {
        id: testUlid('result'),
        wallTs: '2026-05-19T14:30:02.000Z',
        monoNs: 2,
        sessionId: SESSION,
        agentId: 'claude-code',
        parentEventId: null,
        type: 'tool_result',
        payload: resultPayload,
        payloadHash: sha256(resultPayload),
      },
    ];

    const merged = mergeEvents(
      { claudeCodeEvents, captureEvents },
      { sessionId: SESSION }
    );

    expect(merged.linkedCount).toBeGreaterThan(0);
  });
});
