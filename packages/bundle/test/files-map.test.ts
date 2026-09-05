// packages/bundle/test/files-map.test.ts
//
// The files map is what makes raw/, the narrative, and verify.txt
// integrity-covered. These tests pin its shape: every regular file
// except the manifest and attestation artifacts, sorted keys, real
// hashes, and hard rejection of symlinks and escaping paths.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, symlinkSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { buildFilesMap, assertSafeRelativePath, isFilesMapExcluded } from '../src/files-map.js';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'depose-files-map-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function put(rel: string, content: string): void {
  const abs = join(dir, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

describe('buildFilesMap', () => {
  it('lists every regular file with its sha256 and length, keys sorted', () => {
    put('zeta.txt', 'z');
    put('alpha/b.txt', 'bb');
    put('alpha/a.txt', 'a');
    put('events.jsonl', '{}\n');
    const map = buildFilesMap(dir);
    expect(Object.keys(map)).toEqual(['alpha/a.txt', 'alpha/b.txt', 'events.jsonl', 'zeta.txt']);
    expect(map['alpha/b.txt']).toEqual({
      sha256: createHash('sha256').update('bb').digest('hex'),
      bytes: 2,
    });
  });

  it('omits manifest.json, signatures.json, and the .tsr files', () => {
    put('manifest.json', '{}');
    put('attestations/signatures.json', '{}');
    put('attestations/rfc3161-timestamps/0.tsr', 'tsr');
    put('attestations/other.json', '{}');
    put('narrative.md', '# n');
    expect(Object.keys(buildFilesMap(dir))).toEqual(['attestations/other.json', 'narrative.md']);
  });

  it('rejects a symlink anywhere in the tree', () => {
    put('real.txt', 'x');
    symlinkSync(join(dir, 'real.txt'), join(dir, 'link.txt'));
    expect(() => buildFilesMap(dir)).toThrow(/link\.txt is a symlink/);
  });

  it('ignores empty directories', () => {
    mkdirSync(join(dir, 'attestations/rfc3161-timestamps'), { recursive: true });
    put('a.txt', 'a');
    expect(Object.keys(buildFilesMap(dir))).toEqual(['a.txt']);
  });
});

describe('assertSafeRelativePath', () => {
  it('accepts normalized relative paths', () => {
    expect(() => assertSafeRelativePath('raw/claude-code/s.jsonl')).not.toThrow();
  });

  it('rejects absolute paths, .. segments, backslashes, and empty segments', () => {
    expect(() => assertSafeRelativePath('/etc/passwd')).toThrow(/absolute/);
    expect(() => assertSafeRelativePath('raw/../manifest.json')).toThrow(/\.\./);
    expect(() => assertSafeRelativePath('raw\\x')).toThrow(/backslash/);
    expect(() => assertSafeRelativePath('raw//x')).toThrow(/segment/);
    expect(() => assertSafeRelativePath('')).toThrow(/empty/);
  });
});

describe('isFilesMapExcluded', () => {
  it('excludes exactly the manifest, its signature file, and the tsr directory', () => {
    expect(isFilesMapExcluded('manifest.json')).toBe(true);
    expect(isFilesMapExcluded('attestations/signatures.json')).toBe(true);
    expect(isFilesMapExcluded('attestations/rfc3161-timestamps/0.tsr')).toBe(true);
    expect(isFilesMapExcluded('attestations/rekor-entries.json')).toBe(false);
    expect(isFilesMapExcluded('events.jsonl')).toBe(false);
  });
});
