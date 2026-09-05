// packages/capture-claude/test/capture-helpers.test.ts
//
// The three pieces the hook composes: the environment allowlist, file
// hashing, and the capture-record store. The hook handler itself is in
// hook-entry.test.ts.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
} from '../src/hook-entry.js';
import {
  getCaptureDir,
  writeCaptureRecord,
  readCaptureRecords,
} from '../src/capture-record.js';
import {
  filterEnv,
  isEnvAllowed,
} from '../src/env-allowlist.js';
import {
  hashFile,
  fileSize,
  hashFileArgs,
} from '../src/file-hash.js';

// ── Test fixtures ────────────────────────────────────────────────────


function setupCaptureDir(): string {
  const dir = join(tmpdir(), `depose-test-captures-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  process.env.DEPOSE_CAPTURE_DIR = dir;
  return dir;
}

function teardownCaptureDir(dir: string): void {
  delete process.env.DEPOSE_CAPTURE_DIR;
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── Tests ────────────────────────────────────────────────────────────


describe('env-allowlist', () => {
  it('allows AWS_ prefixed keys', () => {
    expect(isEnvAllowed('AWS_REGION')).toBe(true);
    expect(isEnvAllowed('AWS_SECRET_KEY')).toBe(true);
  });

  it('allows GH_ prefixed keys', () => {
    expect(isEnvAllowed('GH_TOKEN')).toBe(true);
  });

  it('allows OPENAI_ prefixed keys', () => {
    expect(isEnvAllowed('OPENAI_API_KEY')).toBe(true);
  });

  it('allows ANTHROPIC_ prefixed keys', () => {
    expect(isEnvAllowed('ANTHROPIC_API_KEY')).toBe(true);
  });

  it('allows RAILWAY_ prefixed keys', () => {
    expect(isEnvAllowed('RAILWAY_TOKEN')).toBe(true);
  });

  it('rejects non-allowlisted keys', () => {
    expect(isEnvAllowed('HOME')).toBe(false);
    expect(isEnvAllowed('PATH')).toBe(false);
    expect(isEnvAllowed('MY_SECRET')).toBe(false);
  });

  it('supports extra prefixes', () => {
    expect(isEnvAllowed('CUSTOM_VAR', ['CUSTOM_'])).toBe(true);
    expect(isEnvAllowed('OTHER_VAR', ['CUSTOM_'])).toBe(false);
  });

  it('filterEnv returns subset and hash', () => {
    const env = {
      AWS_REGION: 'us-east-1',
      HOME: '/home/user',
      PATH: '/usr/bin',
    };
    const { envSubset, envHash } = filterEnv(env);
    expect(envSubset).toEqual({ AWS_REGION: 'us-east-1' });
    expect(envHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('filterEnv includes extra prefixes', () => {
    const env = {
      CUSTOM_VAR: 'yes',
      HOME: '/home/user',
    };
    const { envSubset } = filterEnv(env, ['CUSTOM_']);
    expect(envSubset).toEqual({ CUSTOM_VAR: 'yes' });
  });
});

describe('file-hash', () => {
  it('hashFile returns null for non-existent file', () => {
    expect(hashFile('/nonexistent/file.txt')).toBeNull();
  });

  it('fileSize returns null for non-existent file', () => {
    expect(fileSize('/nonexistent/file.txt')).toBeNull();
  });

  it('hashFile returns hex digest for existing file', () => {
    // Use a known system file
    const hash = hashFile('/etc/hosts');
    if (hash !== null) {
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('hashFileArgs extracts file_path from Edit tool', () => {
    const args = hashFileArgs('Edit', { file_path: '/nonexistent/test.ts' });
    expect(args).toHaveLength(1);
    expect(args[0].path).toBe('/nonexistent/test.ts');
    expect(args[0].preSha256).toBeNull(); // file doesn't exist
  });

  it('hashFileArgs extracts file_path from Write tool', () => {
    const args = hashFileArgs('Write', { file_path: '/nonexistent/new.ts' });
    expect(args).toHaveLength(1);
    expect(args[0].path).toBe('/nonexistent/new.ts');
  });

  it('hashFileArgs returns empty for Bash with no file paths', () => {
    const args = hashFileArgs('Bash', { command: 'echo hello' });
    expect(args).toHaveLength(0);
  });

  it('hashFileArgs deduplicates paths', () => {
    // MultiEdit with duplicate file_path
    const args = hashFileArgs('MultiEdit', {
      edits: [
        { file_path: '/tmp/same.ts', old_string: 'a', new_string: 'b' },
        { file_path: '/tmp/same.ts', old_string: 'c', new_string: 'd' },
      ],
    });
    expect(args).toHaveLength(1);
  });
});

describe('capture-record', () => {
  let dir: string;

  beforeEach(() => {
    dir = setupCaptureDir();
  });

  afterEach(() => {
    teardownCaptureDir(dir);
  });

  it('writeCaptureRecord creates a file', () => {
    const ulid = '01HKVALIDULID00000000000001';
    const path = writeCaptureRecord(ulid, {
      argv: ['terraform', 'destroy'],
      cwd: '/tmp',
      envHash: 'abc123',
      envSubset: {},
      ttyId: null,
      user: 'test',
      hostname: 'localhost',
      parentProcessTree: [],
      fileArgs: [],
      source: 'claude-pretooluse',
      captureSchemaVersion: 1,
    });

    expect(existsSync(path)).toBe(true);
    const content = readFileSync(path, 'utf-8');
    const parsed = JSON.parse(content);
    expect(parsed.argv).toEqual(['terraform', 'destroy']);
    expect(parsed.source).toBe('claude-pretooluse');
  });

  it('readCaptureRecords returns sorted records', () => {
    // Write two records
    writeCaptureRecord('01HKAAAA00000000000000001', {
      argv: ['cmd1'],
      cwd: '/tmp',
      envHash: '',
      envSubset: {},
      ttyId: null,
      user: '',
      hostname: '',
      parentProcessTree: [],
      fileArgs: [],
      source: 'claude-pretooluse',
      captureSchemaVersion: 1,
    });
    writeCaptureRecord('01HKAAAA00000000000000002', {
      argv: ['cmd2'],
      cwd: '/tmp',
      envHash: '',
      envSubset: {},
      ttyId: null,
      user: '',
      hostname: '',
      parentProcessTree: [],
      fileArgs: [],
      source: 'shell-shim',
      captureSchemaVersion: 1,
    });

    const records = readCaptureRecords();
    expect(records).toHaveLength(2);
    expect(records[0].ulid).toBe('01HKAAAA00000000000000001');
    expect(records[1].ulid).toBe('01HKAAAA00000000000000002');
  });

  it('getCaptureDir creates directory with 0700 if not exists', () => {
    const newDir = join(tmpdir(), `depose-test-newdir-${Date.now()}`);
    process.env.DEPOSE_CAPTURE_DIR = newDir;
    try {
      const result = getCaptureDir();
      expect(result).toBe(newDir);
      expect(existsSync(newDir)).toBe(true);
    } finally {
      delete process.env.DEPOSE_CAPTURE_DIR;
      rmSync(newDir, { recursive: true, force: true });
    }
  });
});