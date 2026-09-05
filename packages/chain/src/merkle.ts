// packages/chain/src/merkle.ts
//
// RFC 6962 Merkle tree over the per-event chain hashes.
//
//   leaf(i)   = SHA-256( 0x00 || chainHash[i] )      (32 raw bytes, not hex)
//   node(l,r) = SHA-256( 0x01 || l || r )
//   MTH([])   = SHA-256( "" )
//   MTH(D[n]) = node( MTH(D[0:k]), MTH(D[k:n]) ), k = largest power of two < n
//
// The tree root sits in the manifest next to the linear chain head and is
// covered by the signature and the RFC 3161 token. Inclusion (audit) and
// consistency proofs follow RFC 6962 §2.1.1 and §2.1.2 exactly, so a
// disclosure bundle can prove a subset of events belongs to the sealed
// set without revealing the rest. Shared vectors:
// tests/conformance/merkle-vectors.json. Spec: docs/bundle-format.md#merkle-tree.

import { createHash } from 'node:crypto';

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function sha256(...parts: Buffer[]): Buffer {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

/**
 * Hash one leaf input with the RFC 6962 leaf prefix.
 *
 * @param input - The leaf's raw bytes (a decoded chainHash for events).
 * @returns The 32-byte leaf hash.
 */
export function leafHash(input: Buffer): Buffer {
  return sha256(LEAF_PREFIX, input);
}

/**
 * Hash two child nodes with the RFC 6962 node prefix.
 *
 * @param left - Left child hash.
 * @param right - Right child hash.
 * @returns The 32-byte interior node hash.
 */
export function nodeHash(left: Buffer, right: Buffer): Buffer {
  return sha256(NODE_PREFIX, left, right);
}

/** Largest power of two strictly less than n (n >= 2). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * Merkle tree head over already-hashed leaves.
 *
 * @param leaves - Leaf hashes in order.
 * @returns MTH(leaves); SHA-256("") for an empty list.
 */
export function merkleRoot(leaves: Buffer[]): Buffer {
  return subtreeRoot(leaves, 0, leaves.length);
}

function subtreeRoot(leaves: Buffer[], start: number, end: number): Buffer {
  const n = end - start;
  if (n === 0) return sha256();
  if (n === 1) return leaves[start]!;
  const k = splitPoint(n);
  return nodeHash(subtreeRoot(leaves, start, start + k), subtreeRoot(leaves, start + k, end));
}

/**
 * RFC 6962 audit path for the leaf at `index` in a tree of `leaves`.
 *
 * @param leaves - Leaf hashes in order.
 * @param index - Zero-based leaf index.
 * @returns Sibling hashes from the leaf up to the root.
 * @throws Error when index is out of range.
 */
export function inclusionProof(leaves: Buffer[], index: number): Buffer[] {
  if (index < 0 || index >= leaves.length) {
    throw new Error(`inclusion proof index ${index} is out of range for ${leaves.length} leaves`);
  }
  return auditPath(leaves, index, 0, leaves.length);
}

function auditPath(leaves: Buffer[], index: number, start: number, end: number): Buffer[] {
  const n = end - start;
  if (n <= 1) return [];
  const k = splitPoint(n);
  if (index < start + k) {
    return [...auditPath(leaves, index, start, start + k), subtreeRoot(leaves, start + k, end)];
  }
  return [...auditPath(leaves, index, start + k, end), subtreeRoot(leaves, start, start + k)];
}

/**
 * Recompute a root from a leaf hash and its audit path (RFC 6962 §2.1.1).
 *
 * @param leaf - The leaf hash.
 * @param index - The leaf's zero-based index.
 * @param size - Number of leaves in the tree.
 * @param proof - The audit path from inclusionProof.
 * @returns The root the path leads to.
 * @throws Error when the path length does not match the tree shape.
 */
export function rootFromInclusionProof(leaf: Buffer, index: number, size: number, proof: Buffer[]): Buffer {
  if (index < 0 || index >= size) {
    throw new Error(`leaf index ${index} is out of range for a tree of ${size}`);
  }
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  let used = 0;
  while (sn > 0) {
    const p = proof[used];
    if (p === undefined) {
      throw new Error(`audit path is too short: ${proof.length} hash(es) for index ${index} of ${size}`);
    }
    used++;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (used !== proof.length) {
    throw new Error(`audit path is too long: ${proof.length} hash(es), ${used} consumed`);
  }
  return r;
}

/**
 * Verify an inclusion proof against an expected root.
 *
 * @returns True when the path from the leaf reproduces `root`.
 */
export function verifyInclusion(leaf: Buffer, index: number, size: number, proof: Buffer[], root: Buffer): boolean {
  try {
    return rootFromInclusionProof(leaf, index, size, proof).equals(root);
  } catch {
    return false;
  }
}

/**
 * RFC 6962 consistency proof from the first `m` leaves to all `leaves`.
 *
 * @param leaves - Leaf hashes of the larger tree.
 * @param m - Size of the earlier tree (0 < m <= leaves.length).
 * @returns The proof; empty when m equals the tree size.
 * @throws Error when m is out of range.
 */
export function consistencyProof(leaves: Buffer[], m: number): Buffer[] {
  const n = leaves.length;
  if (m <= 0 || m > n) {
    throw new Error(`consistency proof needs 0 < m <= n; got m=${m}, n=${n}`);
  }
  if (m === n) return [];
  return subProof(leaves, m, 0, n, true);
}

function subProof(leaves: Buffer[], m: number, start: number, end: number, isRoot: boolean): Buffer[] {
  const n = end - start;
  if (m === n) {
    return isRoot ? [] : [subtreeRoot(leaves, start, end)];
  }
  const k = splitPoint(n);
  if (m <= k) {
    return [...subProof(leaves, m, start, start + k, isRoot), subtreeRoot(leaves, start + k, end)];
  }
  return [...subProof(leaves, m - k, start + k, end, false), subtreeRoot(leaves, start, start + k)];
}

/**
 * Verify a consistency proof between two tree sizes (RFC 6962 §2.1.2 as
 * specified in RFC 9162 §2.1.4.2).
 *
 * @param m - Earlier tree size.
 * @param n - Later tree size.
 * @param rootM - Earlier root.
 * @param rootN - Later root.
 * @param proof - Consistency proof from consistencyProof.
 * @returns True when the proof shows the earlier tree is a prefix of the later.
 */
export function verifyConsistency(m: number, n: number, rootM: Buffer, rootN: Buffer, proof: Buffer[]): boolean {
  if (m <= 0 || m > n) return false;
  if (m === n) return proof.length === 0 && rootM.equals(rootN);
  if (proof.length === 0) return false;

  let fn = m - 1;
  let sn = n - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let idx = 0;
  let fr: Buffer;
  let sr: Buffer;
  if (fn === 0) {
    fr = rootM;
    sr = rootM;
  } else {
    fr = proof[0]!;
    sr = proof[0]!;
    idx = 1;
  }
  while (sn > 0) {
    const c = proof[idx];
    if (c === undefined) return false;
    idx++;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return idx === proof.length && fr.equals(rootM) && sr.equals(rootN);
}
