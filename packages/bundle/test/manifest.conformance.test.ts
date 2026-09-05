// packages/bundle/test/manifest.conformance.test.ts
//
// Shared files-map and manifest-signing vectors. The Go verifier runs
// the same file (apps/verify/cmd/manifest_conformance_test.go): it must
// accept the tree against expectedFilesMap and derive the same unsigned
// canonical bytes and hash. See docs/bundle-format.md#files-map.

import { describe, it, expect } from 'vitest';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { buildFilesMap } from '../src/files-map.js';
import { serializeManifestForSigning } from '../src/manifest-io.js';
import type { Manifest } from '../src/manifest.js';

interface ManifestVector {
  name: string;
  tree: Record<string, string>;
  expectedFilesMap: Record<string, { sha256: string; bytes: number }>;
  manifest: Manifest;
  expectedUnsignedCanonical: string;
  expectedManifestHash: string;
}

const file = JSON.parse(
  readFileSync(join(__dirname, '../../../tests/conformance/manifest-vectors.json'), 'utf-8')
) as { vectors: ManifestVector[] };

function materialize(tree: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'depose-manifest-vec-'));
  for (const [rel, content] of Object.entries(tree)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), content);
  }
  return dir;
}

describe('manifest conformance vectors', () => {
  it.each(file.vectors.map((v) => [v.name, v] as const))('%s', (_name, vector) => {
    const dir = materialize(vector.tree);
    try {
      expect(buildFilesMap(dir)).toEqual(vector.expectedFilesMap);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    const withAttestations: Manifest = {
      ...vector.manifest,
      signatures: [{ scheme: 'ed25519', signature: 'AAAA', publicKey: 'PEM', signedFields: 'manifest.json' }],
      timestamps: [{ tsa: 'X', timestamp: 't', tokenBase64: 'AA==' }],
    };
    const unsigned = serializeManifestForSigning(withAttestations);
    expect(unsigned).toBe(vector.expectedUnsignedCanonical);
    expect(createHash('sha256').update(unsigned, 'utf-8').digest('hex')).toBe(vector.expectedManifestHash);
  });
});
