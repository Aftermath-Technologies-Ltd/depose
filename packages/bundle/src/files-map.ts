// packages/bundle/src/files-map.ts
//
// The signed files map: every file in the bundle tree except the manifest
// and the two attestation artifacts that cannot be hashed before they
// exist (see FILES_MAP_EXCLUDED), keyed by relative path with its SHA-256
// and byte length. The writer computes it after every other file is on
// disk and signs it inside the manifest; the verifier walks the tree and
// fails on any file missing from the map, any file the map names that is
// not on disk, and any hash or length mismatch.
//
// Normative layout and walk order: docs/bundle-format.md#files-map.

import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** One file's pinned identity. */
export interface FileEntry {
  /** Lowercase hex SHA-256 of the file's bytes. */
  sha256: string;
  /** Byte length of the file. */
  bytes: number;
}

/** Relative path (forward slashes, no leading slash) to its entry. */
export type FilesMap = Record<string, FileEntry>;

/**
 * Paths never listed in the map. manifest.json holds the map and is
 * covered by the signature; signatures.json holds the signature over the
 * manifest; the .tsr files hold tokens the TSA issues over the finished
 * manifest hash. Each is bound to the manifest another way (the
 * attestation-files verifier check), so none of the tree is unpinned.
 */
export const FILES_MAP_EXCLUDED = {
  exactPaths: ['manifest.json', 'attestations/signatures.json'],
  directoryPrefixes: ['attestations/rfc3161-timestamps/'],
} as const;

/**
 * Whether a relative path is one the map deliberately omits.
 *
 * @param relPath - Forward-slash relative path within the bundle.
 * @returns True when the path is excluded from the files map.
 */
export function isFilesMapExcluded(relPath: string): boolean {
  if ((FILES_MAP_EXCLUDED.exactPaths as readonly string[]).includes(relPath)) return true;
  return FILES_MAP_EXCLUDED.directoryPrefixes.some((prefix) => relPath.startsWith(prefix));
}

/**
 * Reject map keys that could escape the bundle or alias a file.
 *
 * @param relPath - A candidate map key.
 * @throws Error when the path is absolute, contains `..`, backslashes,
 *         empty segments, or a leading `./`.
 */
export function assertSafeRelativePath(relPath: string): void {
  if (relPath.length === 0) {
    throw new Error('files map key is empty; keys must be relative paths inside the bundle');
  }
  if (relPath.startsWith('/') || /^[A-Za-z]:/.test(relPath)) {
    throw new Error(`files map key "${relPath}" is absolute; keys must be relative to the bundle root`);
  }
  if (relPath.includes('\\')) {
    throw new Error(`files map key "${relPath}" contains a backslash; use forward slashes`);
  }
  for (const segment of relPath.split('/')) {
    if (segment === '' || segment === '.' || segment === '..') {
      throw new Error(`files map key "${relPath}" contains a "${segment}" segment; keys must be normalized`);
    }
  }
}

/**
 * Walk a bundle directory and build its files map.
 *
 * Walk order is lexicographic by full relative path (byte order), depth
 * first through sorted directory listings. Symlinks anywhere in the tree
 * are rejected: a bundle must be self-contained.
 *
 * @param bundleDir - Absolute path to the bundle root.
 * @returns The map with keys in sorted order.
 * @throws Error when a symlink or an unsafe path is found.
 */
export function buildFilesMap(bundleDir: string): FilesMap {
  const map: FilesMap = {};
  walk(bundleDir, '', map);
  return sortedMap(map);
}

function walk(bundleDir: string, relDir: string, map: FilesMap): void {
  const absDir = relDir === '' ? bundleDir : join(bundleDir, relDir);
  const names = readdirSync(absDir).sort(compareBytes);
  for (const name of names) {
    const relPath = relDir === '' ? name : `${relDir}/${name}`;
    const absPath = join(bundleDir, relPath);
    const stat = lstatSync(absPath);
    if (stat.isSymbolicLink()) {
      throw new Error(
        `${relPath} is a symlink; bundles must not contain symlinks. Replace it with the file it points at.`
      );
    }
    if (stat.isDirectory()) {
      walk(bundleDir, relPath, map);
      continue;
    }
    if (!stat.isFile()) {
      throw new Error(`${relPath} is not a regular file; bundles may contain only files and directories`);
    }
    if (isFilesMapExcluded(relPath)) continue;
    assertSafeRelativePath(relPath);
    map[relPath] = hashFileEntry(absPath);
  }
}

/**
 * Hash one file into a map entry.
 *
 * @param absPath - Absolute path of the file.
 * @returns Its SHA-256 and byte length.
 */
export function hashFileEntry(absPath: string): FileEntry {
  const bytes = readFileSync(absPath);
  return { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
}

function compareBytes(a: string, b: string): number {
  const ab = Buffer.from(a, 'utf-8');
  const bb = Buffer.from(b, 'utf-8');
  return Buffer.compare(ab, bb);
}

function sortedMap(map: FilesMap): FilesMap {
  const out: FilesMap = {};
  for (const key of Object.keys(map).sort(compareBytes)) {
    out[key] = map[key]!;
  }
  return out;
}
