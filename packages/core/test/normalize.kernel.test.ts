// packages/core/test/normalize.kernel.test.ts
//
// The kernel collector is a separate Go program and this normalizer is
// the only thing that reads what it writes. Neither can call the other,
// so the contract is the capture store on disk: the fixtures under
// apps/collect-execve/testdata/store are produced by the collector's own
// Go test and read back here. A change to the record shape on either
// side breaks one of the two rather than silently dropping kernel
// evidence out of every bundle built after it.
//
// Regenerate the fixtures with:
//   DEPOSE_WRITE_GOLDEN=1 go test ./collector/ -run Fixture

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, cpSync, writeFileSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { normalizeCaptureRecords } from '../src/normalize/capture.js';
import { readExecveRecord } from '../src/normalize/capture-scope.js';
import type { ProcessSpawnPayload } from '../src/events/schema.js';

const collectorStore = join(__dirname, '../../../apps/collect-execve/testdata/store');
let captureDir: string;

beforeEach(() => {
  captureDir = mkdtempSync(join(tmpdir(), 'depose-kernel-'));
  cpSync(collectorStore, captureDir, { recursive: true });
});

afterEach(() => {
  rmSync(captureDir, { recursive: true, force: true });
});

describe('records written by the kernel collector', () => {
  it('has fixtures to read; a missing store means the Go fixture test never ran', () => {
    expect(readdirSync(collectorStore).filter((f) => f.endsWith('.json')).length).toBeGreaterThan(0);
  });

  it('becomes process_spawn events tagged kernel, with the ancestry the collector walked', () => {
    const { events, recordCount } = normalizeCaptureRecords(captureDir, { sessionId: 'sess-kernel' });

    expect(recordCount).toBe(2);
    expect(events.every((e) => e.type === 'process_spawn')).toBe(true);

    const witnessed = events
      .map((e) => e.payload as ProcessSpawnPayload)
      .find((p) => p.comm === 'terraform');
    expect(witnessed).toBeDefined();
    expect(witnessed!.source).toBe('kernel');
    expect(witnessed!.pid).toBe(5100);
    expect(witnessed!.ppid).toBe(4300);
    expect(witnessed!.ancestry).toEqual([4300, 4200, 1]);
    expect(witnessed!.argv).toEqual(['terraform', 'destroy', '-auto-approve']);
    expect(witnessed!.cwd).toBe('/srv/pocketos');
    // Not yet correlated: that happens in the merge, against hook intents.
    expect(witnessed!.matchedIntentEventId).toBeNull();
  });

  it('keeps a monotonic timestamp past 2^53 exact, which a JSON number would not', () => {
    const { events } = normalizeCaptureRecords(captureDir, { sessionId: 'sess-kernel' });
    const monoNs = (events[0]!.payload as ProcessSpawnPayload).monoNs;
    expect(monoNs).toBe('1747583400000000000');
    expect(BigInt(monoNs!)).toBeGreaterThan(2n ** 53n);
  });

  it('carries an exec it could not characterize rather than dropping it', () => {
    const { events } = normalizeCaptureRecords(captureDir, { sessionId: 'sess-kernel' });
    const lost = events
      .map((e) => e.payload as ProcessSpawnPayload)
      .find((p) => p.comm === 'curl');
    expect(lost).toBeDefined();
    expect(lost!.argv).toEqual([]);
    expect(lost!.exe).toBe('');
  });

  it('takes the event id from the record filename, so the bundle can cite the source record', () => {
    const { events } = normalizeCaptureRecords(captureDir, { sessionId: 'sess-kernel' });
    const ids = events.map((e) => e.id).sort();
    expect(ids).toEqual(['01JKRNV0000000000000000001', '01JKRNV0000000000000000002']);
  });

  it('scopes a kernel record to its session like every other record kind', () => {
    const { events, excluded } = normalizeCaptureRecords(captureDir, {
      sessionId: 'bundle-session',
      scope: { agentSessionId: 'a-different-session' },
    });
    expect(events).toHaveLength(0);
    expect(excluded['other-session']).toBe(2);
  });
});

describe('readExecveRecord', () => {
  it('rejects a record with no kind, so another record type is never read as an execve', () => {
    const path = readdirSync(captureDir).find((f) => f.endsWith('.json'))!;
    const raw = JSON.parse(readFileSync(join(captureDir, path), 'utf-8')) as Record<string, unknown>;
    delete raw['kind'];
    expect(readExecveRecord(raw)).toBeNull();
  });

  it('rejects a record whose pid or argv is the wrong type', () => {
    expect(readExecveRecord({ kind: 'execve', pid: '5100', argv: [], capturedAt: '2025-05-18T15:30:00.000Z' })).toBeNull();
    expect(readExecveRecord({ kind: 'execve', pid: 5100, argv: 'terraform', capturedAt: '2025-05-18T15:30:00.000Z' })).toBeNull();
  });

  it('rejects a record with an unparseable capture time', () => {
    expect(readExecveRecord({ kind: 'execve', pid: 1, argv: [], capturedAt: 'whenever' })).toBeNull();
  });

  it('drops non-string argv entries instead of putting them in signed evidence', () => {
    const parsed = readExecveRecord({
      kind: 'execve',
      pid: 1,
      argv: ['rm', 7, '-rf'],
      capturedAt: '2025-05-18T15:30:00.000Z',
    });
    expect(parsed?.argv).toEqual(['rm', '-rf']);
  });

  it('leaves a malformed record out of the timeline and counts it', () => {
    writeFileSync(join(captureDir, '01JKRNV0000000000000000003.json'), '{"kind":"execve","pid":"nope"}');
    const { events, excluded } = normalizeCaptureRecords(captureDir, { sessionId: 'sess-kernel' });
    expect(events).toHaveLength(2);
    expect(excluded.malformed).toBe(1);
  });
});
