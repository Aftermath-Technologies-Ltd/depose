// packages/chain/test/merkle.conformance.test.ts
//
// RFC 6962 vectors from an independent Python oracle whose tree heads
// match the certificate-transparency project's published test roots.
// apps/verify/merkle runs the same file. See docs/bundle-format.md#merkle-tree.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  leafHash,
  nodeHash,
  merkleRoot,
  inclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
} from '../src/merkle.js';

interface Vectors {
  leafHashes: Array<{ input: string; leafHash: string }>;
  nodeHash: { left: string; right: string; expected: string };
  roots: Array<{ size: number; root: string }>;
  inclusionProofs: Array<{ size: number; index: number; leafHash: string; path: string[]; root: string }>;
  consistencyProofs: Array<{ first: number; second: number; firstRoot: string; secondRoot: string; proof: string[] }>;
  chainHashTree: {
    chainHashes: string[];
    root: string;
    inclusionProofs: Array<{ index: number; path: string[] }>;
    consistencyProofs: Array<{ first: number; proof: string[]; firstRoot: string }>;
  };
  negative: Array<{ name: string; size: number; index: number; leafHash: string; path: string[]; root: string }>;
}

const { vectors } = JSON.parse(
  readFileSync(join(__dirname, '../../../tests/conformance/merkle-vectors.json'), 'utf-8')
) as { vectors: Vectors };

const hex = (b: Buffer) => b.toString('hex');
const buf = (h: string) => Buffer.from(h, 'hex');
const ctLeaves = vectors.leafHashes.map((v) => buf(v.leafHash));

describe('merkle conformance vectors', () => {
  it('hashes leaves with the 0x00 prefix', () => {
    for (const v of vectors.leafHashes) {
      expect(hex(leafHash(buf(v.input)))).toBe(v.leafHash);
    }
  });

  it('hashes interior nodes with the 0x01 prefix', () => {
    expect(hex(nodeHash(buf(vectors.nodeHash.left), buf(vectors.nodeHash.right)))).toBe(vectors.nodeHash.expected);
  });

  it('reproduces the certificate-transparency tree heads for sizes 0 through 8', () => {
    for (const v of vectors.roots) {
      expect(hex(merkleRoot(ctLeaves.slice(0, v.size)))).toBe(v.root);
    }
    expect(vectors.roots[8]!.root).toBe('5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328');
  });

  it('produces and verifies every inclusion proof', () => {
    for (const v of vectors.inclusionProofs) {
      const leaves = ctLeaves.slice(0, v.size);
      expect(inclusionProof(leaves, v.index).map(hex)).toEqual(v.path);
      expect(verifyInclusion(buf(v.leafHash), v.index, v.size, v.path.map(buf), buf(v.root))).toBe(true);
    }
  });

  it('produces and verifies every consistency proof', () => {
    for (const v of vectors.consistencyProofs) {
      const leaves = ctLeaves.slice(0, v.second);
      expect(consistencyProof(leaves, v.first).map(hex)).toEqual(v.proof);
      expect(verifyConsistency(v.first, v.second, buf(v.firstRoot), buf(v.secondRoot), v.proof.map(buf))).toBe(true);
    }
  });

  it('handles the chain-hash-shaped 13-leaf tree', () => {
    const t = vectors.chainHashTree;
    const leaves = t.chainHashes.map((h) => leafHash(buf(h)));
    const root = merkleRoot(leaves);
    expect(hex(root)).toBe(t.root);
    for (const p of t.inclusionProofs) {
      expect(inclusionProof(leaves, p.index).map(hex)).toEqual(p.path);
      expect(verifyInclusion(leaves[p.index]!, p.index, leaves.length, p.path.map(buf), root)).toBe(true);
    }
    for (const c of t.consistencyProofs) {
      expect(consistencyProof(leaves, c.first).map(hex)).toEqual(c.proof);
      expect(verifyConsistency(c.first, leaves.length, buf(c.firstRoot), root, c.proof.map(buf))).toBe(true);
    }
  });

  it('rejects wrong-index, short, and long audit paths', () => {
    for (const v of vectors.negative) {
      expect(verifyInclusion(buf(v.leafHash), v.index, v.size, v.path.map(buf), buf(v.root)), v.name).toBe(false);
    }
  });

  it('rejects a consistency proof against the wrong later root', () => {
    const v = vectors.consistencyProofs.find((c) => c.first === 3 && c.second === 7)!;
    const wrong = buf(vectors.roots[8]!.root);
    expect(verifyConsistency(3, 7, buf(v.firstRoot), wrong, v.proof.map(buf))).toBe(false);
    expect(verifyConsistency(3, 7, buf(v.firstRoot), buf(v.secondRoot), v.proof.slice(1).map(buf))).toBe(false);
  });
});
