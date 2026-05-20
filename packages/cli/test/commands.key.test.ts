// Tests for `depose key {fingerprint,rotate,revoke,catalog}`.
//
// These exercise the local Ed25519 key lifecycle commands against an
// isolated temp key directory so they cannot touch the developer's
// real ~/.depose/keys/.
//
// The handlers are imported directly rather than going through
// commander so we can assert on stdout deterministically without
// process.exit side effects.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  handleKeyFingerprint,
  handleKeyRotate,
  handleKeyRevoke,
  handleKeyCatalog,
} from '../src/commands/key.js';

interface CaptureHandle {
  lines: string[];
  restore: () => void;
}

function captureStdout(): CaptureHandle {
  const lines: string[] = [];
  const originalLog = console.log;
  console.log = vi.fn((...args: unknown[]) => {
    lines.push(args.map((a) => (typeof a === 'string' ? a : String(a))).join(' '));
  });
  return {
    lines,
    restore: () => {
      console.log = originalLog;
    },
  };
}

describe('depose key fingerprint', () => {
  let keyDir: string;
  beforeEach(() => {
    keyDir = mkdtempSync(join(tmpdir(), 'depose-key-fingerprint-'));
  });
  afterEach(() => {
    rmSync(keyDir, { recursive: true, force: true });
  });

  it('generates a key and prints a 64-char lowercase hex fingerprint', async () => {
    const cap = captureStdout();
    try {
      await handleKeyFingerprint({ 'key-dir': keyDir });
    } finally {
      cap.restore();
    }
    expect(cap.lines).toHaveLength(1);
    expect(cap.lines[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(existsSync(join(keyDir, 'signing.key'))).toBe(true);
    expect(existsSync(join(keyDir, 'signing.pub'))).toBe(true);
  });

  it('prints ssh-style SHA256:<base64> when --ssh is set', async () => {
    const cap = captureStdout();
    try {
      await handleKeyFingerprint({ 'key-dir': keyDir, ssh: true });
    } finally {
      cap.restore();
    }
    expect(cap.lines[0]).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });
});

describe('depose key rotate', () => {
  let keyDir: string;
  beforeEach(() => {
    keyDir = mkdtempSync(join(tmpdir(), 'depose-key-rotate-'));
  });
  afterEach(() => {
    rmSync(keyDir, { recursive: true, force: true });
  });

  it('generates a fresh active key when none exists', async () => {
    const cap = captureStdout();
    try {
      await handleKeyRotate({ 'key-dir': keyDir });
    } finally {
      cap.restore();
    }
    expect(existsSync(join(keyDir, 'signing.key'))).toBe(true);
    expect(existsSync(join(keyDir, 'signing.pub'))).toBe(true);
    expect(existsSync(join(keyDir, 'catalog.json'))).toBe(true);
    expect(cap.lines.join('\n')).toMatch(/No existing key to rotate/);
  });

  it('archives the old key and marks it rotated', async () => {
    // First, generate a key
    const cap1 = captureStdout();
    try {
      await handleKeyFingerprint({ 'key-dir': keyDir });
    } finally {
      cap1.restore();
    }
    const originalFingerprint = cap1.lines[0];

    // Then rotate
    const cap2 = captureStdout();
    try {
      await handleKeyRotate({ 'key-dir': keyDir });
    } finally {
      cap2.restore();
    }

    // Old key is in archive/<old-fp>/
    expect(existsSync(join(keyDir, 'archive', originalFingerprint!, 'signing.key'))).toBe(true);
    expect(existsSync(join(keyDir, 'archive', originalFingerprint!, 'signing.pub'))).toBe(true);

    // Catalog reflects rotation
    const catalog = JSON.parse(readFileSync(join(keyDir, 'catalog.json'), 'utf-8'));
    const oldEntry = catalog.entries.find((e: { fingerprint: string }) => e.fingerprint === originalFingerprint);
    expect(oldEntry).toBeDefined();
    expect(oldEntry.status).toBe('rotated');
    expect(oldEntry.rotatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);

    // New key is active and has a different fingerprint
    const activeEntries = catalog.entries.filter((e: { status: string }) => e.status === 'active');
    expect(activeEntries).toHaveLength(1);
    expect(activeEntries[0].fingerprint).not.toBe(originalFingerprint);
  });

  it('refuses to rotate if an archive collision exists', async () => {
    // Generate then rotate to set up an archived entry.
    const cap1 = captureStdout();
    try {
      await handleKeyFingerprint({ 'key-dir': keyDir });
    } finally {
      cap1.restore();
    }
    const oldFp = cap1.lines[0]!;
    const cap2 = captureStdout();
    try {
      await handleKeyRotate({ 'key-dir': keyDir });
    } finally {
      cap2.restore();
    }

    // Now contrive a collision: rotate would archive *something* under
    // the *current* active key's fingerprint. To make collision land
    // there, replace the current signing.{key,pub} with the originals.
    const archiveDir = join(keyDir, 'archive', oldFp);
    // Read the originals back and write them as the active key.
    const origPriv = readFileSync(join(archiveDir, 'signing.key'), 'utf-8');
    const origPub = readFileSync(join(archiveDir, 'signing.pub'), 'utf-8');
    writeFileSync(join(keyDir, 'signing.key'), origPriv, { mode: 0o600 });
    writeFileSync(join(keyDir, 'signing.pub'), origPub, { mode: 0o644 });

    // Now rotate again. The archived dir for oldFp already exists with
    // material in it; the command must refuse.
    const cap3 = captureStdout();
    try {
      await expect(handleKeyRotate({ 'key-dir': keyDir })).rejects.toThrow(/archive entry already exists/);
    } finally {
      cap3.restore();
    }
  });
});

describe('depose key revoke', () => {
  let keyDir: string;
  beforeEach(() => {
    keyDir = mkdtempSync(join(tmpdir(), 'depose-key-revoke-'));
  });
  afterEach(() => {
    rmSync(keyDir, { recursive: true, force: true });
  });

  it('requires a reason', async () => {
    // Seed a catalog with one active entry.
    const cap = captureStdout();
    try {
      await handleKeyCatalog({ 'key-dir': keyDir });
    } finally {
      cap.restore();
    }
    const catalog = JSON.parse(readFileSync(join(keyDir, 'catalog.json'), 'utf-8'));
    const fp = catalog.entries[0].fingerprint;

    await expect(handleKeyRevoke(fp, { 'key-dir': keyDir })).rejects.toThrow(/--reason/);
    await expect(handleKeyRevoke(fp, { 'key-dir': keyDir, reason: '   ' })).rejects.toThrow(/--reason/);
  });

  it('marks a fingerprint revoked with reason and timestamp', async () => {
    const cap = captureStdout();
    try {
      await handleKeyCatalog({ 'key-dir': keyDir });
    } finally {
      cap.restore();
    }
    const before = JSON.parse(readFileSync(join(keyDir, 'catalog.json'), 'utf-8'));
    const fp = before.entries[0].fingerprint;

    const cap2 = captureStdout();
    try {
      await handleKeyRevoke(fp, { 'key-dir': keyDir, reason: 'suspected leak on 2026-05-19' });
    } finally {
      cap2.restore();
    }

    const after = JSON.parse(readFileSync(join(keyDir, 'catalog.json'), 'utf-8'));
    const entry = after.entries.find((e: { fingerprint: string }) => e.fingerprint === fp);
    expect(entry.status).toBe('revoked');
    expect(entry.reason).toBe('suspected leak on 2026-05-19');
    expect(entry.revokedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('refuses to revoke a fingerprint absent from the catalog', async () => {
    // Seed catalog with a real entry so loadCatalog has shape.
    const cap = captureStdout();
    try {
      await handleKeyCatalog({ 'key-dir': keyDir });
    } finally {
      cap.restore();
    }
    const unknownFp = '00'.repeat(32);
    await expect(
      handleKeyRevoke(unknownFp, { 'key-dir': keyDir, reason: 'not in catalog' }),
    ).rejects.toThrow(/not in catalog/);
  });
});

describe('depose key catalog', () => {
  let keyDir: string;
  beforeEach(() => {
    keyDir = mkdtempSync(join(tmpdir(), 'depose-key-catalog-'));
  });
  afterEach(() => {
    rmSync(keyDir, { recursive: true, force: true });
  });

  it('seeds an entry from the active key if the catalog is empty', async () => {
    const cap = captureStdout();
    try {
      await handleKeyCatalog({ 'key-dir': keyDir });
    } finally {
      cap.restore();
    }
    const catalog = JSON.parse(readFileSync(join(keyDir, 'catalog.json'), 'utf-8'));
    expect(catalog.entries).toHaveLength(1);
    expect(catalog.entries[0].status).toBe('active');
    expect(catalog.entries[0].fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it('exports the catalog to a file when --export is given', async () => {
    const exportPath = join(keyDir, 'exported.json');
    const cap = captureStdout();
    try {
      await handleKeyCatalog({ 'key-dir': keyDir, export: exportPath });
    } finally {
      cap.restore();
    }
    expect(existsSync(exportPath)).toBe(true);
    const exported = JSON.parse(readFileSync(exportPath, 'utf-8'));
    expect(exported.schemaVersion).toBe(1);
    expect(exported.entries).toHaveLength(1);
  });
});
