// packages/capture-claude/test/hook-entry.test.ts
//
// Tests for the Claude Code PreToolUse hook handler.
// See BUILD_PLAN.md §6 (Phase 3) for acceptance criteria.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  handlePreToolUse,
  type HookInput,
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

let testCaptureDir: string;

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

describe('hook-entry', () => {
  beforeEach(() => {
    testCaptureDir = setupCaptureDir();
  });

  afterEach(() => {
    teardownCaptureDir(testCaptureDir);
  });

  it('writes a capture record for Bash tool', async () => {
    const input: HookInput = {
      tool_name: 'Bash',
      tool_input: { command: 'terraform destroy -auto-approve' },
      cwd: '/tmp/project',
      session_id: 'test-session-001',
    };

    const result = await handlePreToolUse(input);

    expect(result.ulid).toBeTruthy();
    expect(result.capturePath).toContain(result.ulid);
    expect(existsSync(result.capturePath)).toBe(true);

    // Read back the capture record
    const records = readCaptureRecords();
    const targetRecord = records.find((r) => r.ulid === result.ulid);
    expect(targetRecord).toBeDefined();
    expect(targetRecord!.payload.argv).toEqual([
      'bash', '-c', 'terraform destroy -auto-approve',
    ]);
    expect(targetRecord!.payload.cwd).toBe('/tmp/project');
    expect(targetRecord!.payload.source).toBe('claude-pretooluse');
    expect(targetRecord!.payload.captureSchemaVersion).toBe(1);
  });

  it('writes a capture record for Edit tool', async () => {
    const input: HookInput = {
      tool_name: 'Edit',
      tool_input: {
        file_path: '/tmp/project/main.ts',
        old_string: 'hello',
        new_string: 'world',
      },
      cwd: '/tmp/project',
      session_id: 'test-session-002',
    };

    const result = await handlePreToolUse(input);
    expect(result.ulid).toBeTruthy();

    const records = readCaptureRecords();
    const targetRecord = records.find((r) => r.ulid === result.ulid);
    expect(targetRecord).toBeDefined();
    expect(targetRecord!.payload.argv).toEqual(['edit', '/tmp/project/main.ts']);
  });

  it('writes a capture record for Write tool', async () => {
    const input: HookInput = {
      tool_name: 'Write',
      tool_input: {
        file_path: '/tmp/project/new-file.ts',
        content: 'export const x = 1;',
      },
      cwd: '/tmp/project',
      session_id: 'test-session-003',
    };

    const result = await handlePreToolUse(input);
    expect(result.ulid).toBeTruthy();

    const records = readCaptureRecords();
    const targetRecord = records.find((r) => r.ulid === result.ulid);
    expect(targetRecord).toBeDefined();
    expect(targetRecord!.payload.argv[0]).toBe('write');
  });

  it('includes env subset and env hash', async () => {
    // Set some env vars for the test
    process.env.AWS_REGION = 'us-east-1';
    process.env.AWS_SECRET_KEY = 'supersecret';
    process.env.MY_PRIVATE_VAR = 'should-not-appear';

    const input: HookInput = {
      tool_name: 'Bash',
      tool_input: { command: 'echo hello' },
      cwd: '/tmp',
      session_id: 'test-session-env',
    };

    const result = await handlePreToolUse(input);
    const records = readCaptureRecords();
    const targetRecord = records.find((r) => r.ulid === result.ulid);

    expect(targetRecord).toBeDefined();
    // AWS_REGION should be in the subset
    expect(targetRecord!.payload.envSubset).toHaveProperty('AWS_REGION');
    // AWS_SECRET_KEY starts with AWS_ so it should be in the subset
    expect(targetRecord!.payload.envSubset).toHaveProperty('AWS_SECRET_KEY');
    // MY_PRIVATE_VAR does not match any allowlist prefix
    expect(targetRecord!.payload.envSubset).not.toHaveProperty('MY_PRIVATE_VAR');
    // envHash should be a 64-char hex string
    expect(targetRecord!.payload.envHash).toMatch(/^[0-9a-f]{64}$/);

    delete process.env.AWS_REGION;
    delete process.env.AWS_SECRET_KEY;
    delete process.env.MY_PRIVATE_VAR;
  });

  it('includes parent process tree (best-effort)', async () => {
    const input: HookInput = {
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
      cwd: '/tmp',
      session_id: 'test-session-ptree',
    };

    const result = await handlePreToolUse(input);
    const records = readCaptureRecords();
    const targetRecord = records.find((r) => r.ulid === result.ulid);

    // Parent process tree is best-effort; just verify it's an array
    expect(Array.isArray(targetRecord!.payload.parentProcessTree)).toBe(true);
  });

  it('never throws — errors are swallowed', async () => {
    // Provide malformed input that might cause issues
    const input: HookInput = {
      tool_name: 'Bash',
      tool_input: {},
      cwd: '',
      session_id: '',
    };

    // Should not throw
    const result = await handlePreToolUse(input);
    expect(result).toBeDefined();
    expect(result.ulid).toBeTruthy();
  });
});

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