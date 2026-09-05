// packages/capture-claude/test/hook-entry.test.ts
//
// Tests for the Claude Code PreToolUse hook handler.
// Acceptance criteria: docs/hook-installation.md.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  handlePreToolUse,
  type HookInput,
} from '../src/hook-entry.js';
import {
  readCommandRecords,
} from '../src/capture-record.js';
import {
} from '../src/env-allowlist.js';
import {
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
    const records = readCommandRecords();
    const targetRecord = records.find((r) => r.ulid === result.ulid);
    expect(targetRecord).toBeDefined();
    expect(targetRecord!.payload.argv).toEqual([
      'bash', '-c', 'terraform destroy -auto-approve',
    ]);
    expect(targetRecord!.payload.cwd).toBe('/tmp/project');
    expect(targetRecord!.payload.source).toBe('claude-pretooluse');
    expect(targetRecord!.payload.captureSchemaVersion).toBe(3);
  });

  it('records the capture time so the event is not stamped at bundle time', async () => {
    const before = Date.now();
    const result = await handlePreToolUse({
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /data', cwd: '/tmp/project' },
      cwd: '/tmp/project',
      session_id: 'session-capturedat',
    });
    const after = Date.now();

    const record = readCommandRecords().find((r) => r.ulid === result.ulid)!;
    expect(record.payload.capturedAtSource).toBe('recorded');

    const capturedMs = Date.parse(record.payload.capturedAt);
    expect(capturedMs).toBeGreaterThanOrEqual(before);
    expect(capturedMs).toBeLessThanOrEqual(after);
  });

  it('records the agent session id so captures can be scoped to a session', async () => {
    const result = await handlePreToolUse({
      tool_name: 'Bash',
      tool_input: { command: 'terraform destroy', cwd: '/tmp/project' },
      cwd: '/tmp/project',
      session_id: 'session-scoping-abc',
    });

    const record = readCommandRecords().find((r) => r.ulid === result.ulid)!;
    expect(record.payload.sessionId).toBe('session-scoping-abc');
  });

  it('leaves sessionId null when the hook payload carries no session', async () => {
    const result = await handlePreToolUse({
      tool_name: 'Bash',
      tool_input: { command: 'ls', cwd: '/tmp/project' },
      cwd: '/tmp/project',
      session_id: '',
    });

    const record = readCommandRecords().find((r) => r.ulid === result.ulid)!;
    expect(record.payload.sessionId).toBeNull();
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

    const records = readCommandRecords();
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

    const records = readCommandRecords();
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
    const records = readCommandRecords();
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
    const records = readCommandRecords();
    const targetRecord = records.find((r) => r.ulid === result.ulid);

    // Parent process tree is best-effort; just verify it's an array
    expect(Array.isArray(targetRecord!.payload.parentProcessTree)).toBe(true);
  });

  it('never throws; errors are swallowed', async () => {
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
