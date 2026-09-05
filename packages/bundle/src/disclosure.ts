// packages/bundle/src/disclosure.ts
//
// Build a disclosure bundle from a sealed bundle: a subset of events,
// byte-identical to the sealed lines, plus RFC 6962 audit paths that tie
// every position (disclosed or withheld) to the signed Merkle root, and
// the commitment openings for exactly the fields being disclosed.
// Nothing is re-signed; the original manifest, signature, and timestamp
// travel unchanged. Layout: docs/bundle-format.md#disclosure-bundles.

import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import {
  parseEventLine,
  COMMITMENT_ALGORITHM,
  type CommitmentsFile,
  type CommitmentOpening,
} from '@depose/core';
import { leafHash, merkleRoot, inclusionProof, consistencyProof } from '@depose/chain';
import type { Manifest } from './manifest.js';

/** disclosure.json, the proof document of a disclosure bundle. */
export interface DisclosureDocument {
  schemaVersion: 1;
  bundleId: string;
  /** Must equal the original manifest's merkleRoot. */
  merkleRoot: string;
  leafCount: number;
  producedAt: string;
  producer: { tool: 'depose'; version: string };
  disclosed: Array<{ index: number; eventId: string; auditPath: string[] }>;
  withheld: Array<{ index: number; chainHash: string; auditPath: string[] }>;
  fields: { disclosed: string[] | 'all'; withheld: string[] };
  /** Original files carried verbatim; the verifier checks them against manifest.files. */
  includedFiles: string[];
  consistency: { earlierLeafCount: number; earlierRoot: string; proof: string[] } | null;
}

export interface DisclosureOptions {
  /** Sealed bundle directory. */
  bundleDir: string;
  /** Output directory; created. */
  outDir: string;
  /** Zero-based indices of events to disclose. */
  indices: number[];
  /** Field paths (JSON pointers) whose openings are disclosed, or 'all'. */
  fields: string[] | 'all';
  /** Original files to carry verbatim (relative paths). */
  includeFiles?: string[];
  /** Producer version string for the document. */
  version: string;
  producedAt: string;
  /** Earlier disclosure directory to prove consistency with. */
  consistentWith?: string;
}

export interface DisclosureResult {
  outDir: string;
  document: DisclosureDocument;
  disclosedCount: number;
  withheldCount: number;
  openingsDisclosed: number;
}

const ATTESTATION_FILES = ['attestations/signatures.json'];

/**
 * Build a disclosure bundle.
 *
 * @param options - Source, destination, and what to disclose.
 * @returns The written document and counts.
 * @throws Error when the bundle has no Merkle root, its root does not
 *         match its events, an index is out of range, or the earlier
 *         disclosure is not a prefix of this tree.
 */
export function buildDisclosure(options: DisclosureOptions): DisclosureResult {
  const { bundleDir, outDir } = options;
  const manifestBytes = readFileSync(join(bundleDir, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes.toString('utf-8')) as Manifest;
  if (!manifest.merkleRoot) {
    throw new Error(
      `${bundleDir} has no merkleRoot; it was sealed before the Merkle tree existed and cannot be disclosed from. Re-seal it with a current depose.`
    );
  }

  const lines = readFileSync(join(bundleDir, 'events.jsonl'), 'utf-8').split('\n').filter((l) => l.length > 0);
  const events = lines.map((line) => parseEventLine(line));
  const chainHashes = events.map((e, i) => {
    if (!e.chainHash) throw new Error(`event ${i} (${e.id}) has no chainHash; the bundle carries no chain`);
    return e.chainHash;
  });
  const leaves = chainHashes.map((h) => leafHash(Buffer.from(h, 'hex')));
  const root = merkleRoot(leaves).toString('hex');
  if (root !== manifest.merkleRoot) {
    throw new Error(
      `events.jsonl in ${bundleDir} does not reproduce manifest.merkleRoot (computed ${root.slice(0, 16)}..., manifest ${manifest.merkleRoot.slice(0, 16)}...); refusing to disclose from a bundle that does not verify`
    );
  }

  const disclosedSet = new Set<number>();
  for (const i of options.indices) {
    if (!Number.isInteger(i) || i < 0 || i >= events.length) {
      throw new Error(`event index ${i} is out of range; the bundle has ${events.length} events (0..${events.length - 1})`);
    }
    disclosedSet.add(i);
  }
  const disclosedIndices = [...disclosedSet].sort((a, b) => a - b);

  const disclosed = disclosedIndices.map((index) => ({
    index,
    eventId: events[index]!.id,
    auditPath: inclusionProof(leaves, index).map((b) => b.toString('hex')),
  }));
  const withheld: DisclosureDocument['withheld'] = [];
  for (let index = 0; index < events.length; index++) {
    if (disclosedSet.has(index)) continue;
    withheld.push({ index, chainHash: chainHashes[index]!, auditPath: inclusionProof(leaves, index).map((b) => b.toString('hex')) });
  }

  const openings = selectOpenings(bundleDir, disclosedSet, events.map((e) => e.id), options.fields);
  const consistency = options.consistentWith ? buildConsistency(options.consistentWith, leaves) : null;
  const includeFiles = options.includeFiles ?? ['rules/destructive.yaml'];

  const document: DisclosureDocument = {
    schemaVersion: 1,
    bundleId: manifest.bundleId,
    merkleRoot: manifest.merkleRoot,
    leafCount: events.length,
    producedAt: options.producedAt,
    producer: { tool: 'depose', version: options.version },
    disclosed,
    withheld,
    fields: { disclosed: options.fields, withheld: openings.withheldPaths },
    includedFiles: includeFiles,
    consistency,
  };

  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'manifest.json'), manifestBytes);
  copyTree(bundleDir, outDir, 'attestations');
  for (const rel of ATTESTATION_FILES) {
    if (!existsSync(join(outDir, rel))) throw new Error(`${rel} is missing from ${bundleDir}; cannot disclose from an incomplete bundle`);
  }
  for (const rel of includeFiles) {
    if (!manifest.files[rel]) {
      throw new Error(`${rel} is not in the sealed files map and cannot be carried in a disclosure; include only files the seal pins`);
    }
    mkdirSync(dirname(join(outDir, rel)), { recursive: true });
    copyFileSync(join(bundleDir, rel), join(outDir, rel));
  }
  writeFileSync(join(outDir, 'events.jsonl'), disclosedIndices.map((i) => lines[i]!).join('\n') + (disclosedIndices.length > 0 ? '\n' : ''));
  const commitments: CommitmentsFile = { schemaVersion: 1, algorithm: COMMITMENT_ALGORITHM, openings: openings.disclosed };
  writeFileSync(join(outDir, 'commitments.json'), JSON.stringify(commitments, null, 2) + '\n');
  writeFileSync(join(outDir, 'disclosure.json'), JSON.stringify(document, null, 2) + '\n');

  return {
    outDir,
    document,
    disclosedCount: disclosed.length,
    withheldCount: withheld.length,
    openingsDisclosed: openings.disclosed.length,
  };
}

function selectOpenings(
  bundleDir: string,
  disclosedSet: Set<number>,
  ids: string[],
  fields: string[] | 'all'
): { disclosed: CommitmentOpening[]; withheldPaths: string[] } {
  const path = join(bundleDir, 'commitments.json');
  if (!existsSync(path)) return { disclosed: [], withheldPaths: [] };
  const file = JSON.parse(readFileSync(path, 'utf-8')) as CommitmentsFile;
  const disclosedIds = new Set([...disclosedSet].map((i) => ids[i]!));
  const disclosed: CommitmentOpening[] = [];
  const withheldPaths = new Set<string>();
  for (const opening of file.openings) {
    if (!disclosedIds.has(opening.eventId)) continue;
    if (fields === 'all' || fields.includes(opening.path)) {
      disclosed.push(opening);
    } else {
      withheldPaths.add(opening.path);
    }
  }
  return { disclosed, withheldPaths: [...withheldPaths].sort() };
}

function buildConsistency(earlierDir: string, leaves: Buffer[]): DisclosureDocument['consistency'] {
  const earlier = JSON.parse(readFileSync(join(earlierDir, 'disclosure.json'), 'utf-8')) as DisclosureDocument;
  const m = earlier.leafCount;
  if (m > leaves.length) {
    throw new Error(`earlier disclosure has ${m} leaves but this bundle has ${leaves.length}; a consistency proof needs the earlier tree to be a prefix`);
  }
  const prefixRoot = merkleRoot(leaves.slice(0, m)).toString('hex');
  if (prefixRoot !== earlier.merkleRoot) {
    throw new Error(
      `the first ${m} leaves of this bundle do not reproduce the earlier disclosure's root; the two seals do not share a prefix (different salts, ids, or events)`
    );
  }
  return {
    earlierLeafCount: m,
    earlierRoot: earlier.merkleRoot,
    proof: consistencyProof(leaves, m).map((b) => b.toString('hex')),
  };
}

function copyTree(srcRoot: string, dstRoot: string, rel: string): void {
  const src = join(srcRoot, rel);
  if (!existsSync(src)) return;
  mkdirSync(join(dstRoot, rel), { recursive: true });
  for (const name of readdirSync(src, { withFileTypes: true })) {
    const childRel = `${rel}/${name.name}`;
    if (name.isDirectory()) {
      copyTree(srcRoot, dstRoot, childRel);
    } else if (name.isFile()) {
      copyFileSync(join(srcRoot, childRel), join(dstRoot, childRel));
    }
  }
}
