// packages/cli/test/commands.export.test.ts
//
// Flag handling and the key checks around the exporters. The mappings
// themselves are covered in packages/bundle/test/export.*.test.ts; what
// matters here is that a bad format is refused by name and that a signed
// export is never produced with a key that did not seal the bundle.

import { describe, it, expect } from 'vitest';
import { parseFormat, renderExport, EXPORT_FORMATS } from '../src/commands/export.js';
import type { LoadedBundle } from '@depose/bundle';

const emptyBundle = (mode: 'signed' | 'dev-unsigned'): LoadedBundle => ({
  path: '/tmp/bundle',
  manifestBytes: Buffer.from('{}'),
  events: [],
  rulesetBytes: null,
  manifest: {
    schemaVersion: 3,
    bundleId: '01BUNDLE',
    producedAt: '2025-05-18T16:00:00.000Z',
    producer: {
      tool: 'depose',
      version: '0.1.0',
      mode,
      host: { os: 'linux', arch: 'x64', nodeVersion: 'v20.0.0', kernel: '6.0' },
    },
    session: {
      agentId: 'claude-code',
      sessionId: 'sess',
      startedAt: '2025-05-18T15:30:00.000Z',
      endedAt: '2025-05-18T15:31:00.000Z',
      host: null,
    },
    rootHash: 'aa',
    merkleRoot: 'bb',
    eventsJsonlSha256: 'cc',
    files: {},
    signatures: [],
    timestamps: [],
    counts: { events: 0, destructiveOperations: 0, gaps: 0, artifactsPre: 0, artifactsPost: 0 },
    rulesetHash: 'dd',
  },
});

describe('parseFormat', () => {
  it.each(EXPORT_FORMATS)('accepts %s', (format) => {
    expect(parseFormat(format)).toBe(format);
  });

  it('names the supported formats when given something else', () => {
    expect(() => parseFormat('csv')).toThrow(/aat, asqav-receipt, scitt-statement/);
    expect(() => parseFormat(undefined)).toThrow(/--format is required/);
  });
});

describe('renderExport', () => {
  it('produces AAT without a key, because AAT signs nothing', () => {
    expect(renderExport(emptyBundle('signed'), 'aat', null).toString('utf-8')).toBe('\n');
  });

  it('refuses a signed format with no key rather than emitting an unsigned one', () => {
    expect(() => renderExport(emptyBundle('signed'), 'asqav-receipt', null)).toThrow(/needs a key/);
    expect(() => renderExport(emptyBundle('signed'), 'scitt-statement', null)).toThrow(/needs a key/);
  });
});
