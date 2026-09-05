// packages/cli/test/commands.install.test.ts
//
// Phase 3 tests for `depose install --claude | --shell` and uninstall.
// Acceptance criteria: docs/hook-installation.md and docs/shim-installation.md.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, existsSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  installClaudeHook,
  installShellShims,
  uninstallShellShims,
  SHIM_ALLOWLIST,
  buildHookCommand,
} from '../src/commands/install.js';

// ── Test fixtures ────────────────────────────────────────────────────

let testDir: string;

function setup(): void {
  testDir = join(tmpdir(), `depose-install-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(testDir, { recursive: true });
}

function teardown(): void {
  if (testDir && existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
}

// ── SHIM_ALLOWLIST constant tests ───────────────────────────────────

describe('Phase 3: SHIM_ALLOWLIST', () => {
  it('contains expected destructive binaries', () => {
    expect(SHIM_ALLOWLIST).toContain('terraform');
    expect(SHIM_ALLOWLIST).toContain('aws');
    expect(SHIM_ALLOWLIST).toContain('rm');
    expect(SHIM_ALLOWLIST).toContain('gh');
    expect(SHIM_ALLOWLIST).toContain('kubectl');
    expect(SHIM_ALLOWLIST).toContain('psql');
    expect(SHIM_ALLOWLIST).toContain('gcloud');
    expect(SHIM_ALLOWLIST).toContain('railway');
  });

  it('is a non-empty readonly array', () => {
    expect(SHIM_ALLOWLIST.length).toBeGreaterThan(0);
  });
});

// ── install --claude tests ──────────────────────────────────────────

describe('Phase 3: installClaudeHook', () => {
  let capDir: string;

  beforeEach(() => {
    setup();
    capDir = join(testDir, 'captures');
  });

  afterEach(teardown);

  /** Read the settings.json the installer actually wrote. */
  function writtenSettings(result: { settingsPath: string }): {
    hooks: Record<string, Array<{ matcher: string; hooks: Array<{ type: string; command: string }> }>>;
  } {
    return JSON.parse(readFileSync(result.settingsPath, 'utf-8'));
  }

  it('registers both halves of the tool call, not just the pre half', () => {
    const projectRoot = join(testDir, 'project');
    mkdirSync(join(projectRoot, '.claude'), { recursive: true });
    writeFileSync(join(projectRoot, '.claude', 'settings.json'), '{}', 'utf-8');

    const result = installClaudeHook({ project: true, projectRoot, captureDir: capDir });

    expect(result.conflicts).toEqual([]);
    expect(result.captureDir).toBe(capDir);
    const { hooks } = writtenSettings(result);
    expect(hooks['PreToolUse']![0]!.hooks[0]!.command).toContain('pretooluse');
    expect(hooks['PostToolUse']![0]!.hooks[0]!.command).toContain('posttooluse');
    expect(hooks['PreToolUse']![0]!.matcher).toBe('Bash|Edit|Write');
    expect(hooks['PostToolUse']![0]!.matcher).toBe('Bash|Edit|Write');
  });

  it('leaves hooks registered by anything else alone', () => {
    const projectRoot = join(testDir, 'project-other');
    mkdirSync(join(projectRoot, '.claude'), { recursive: true });
    writeFileSync(
      join(projectRoot, '.claude', 'settings.json'),
      JSON.stringify({
        hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'other-tool' }] }] },
      }),
      'utf-8'
    );

    const result = installClaudeHook({ project: true, projectRoot, captureDir: capDir });

    const { hooks } = writtenSettings(result);
    expect(hooks['PreToolUse']).toHaveLength(2);
    expect(hooks['PreToolUse']![0]!.hooks[0]!.command).toBe('other-tool');
  });

  it('refuses to install twice over an existing depose hook, per event', () => {
    const projectRoot = join(testDir, 'project-conflict');
    mkdirSync(join(projectRoot, '.claude'), { recursive: true });
    writeFileSync(
      join(projectRoot, '.claude', 'settings.json'),
      JSON.stringify({
        hooks: {
          PreToolUse: [{ matcher: 'Bash|Edit|Write', hooks: [{ type: 'command', command: 'depose-hook pretooluse' }] }],
        },
      }),
      'utf-8'
    );

    const result = installClaudeHook({ project: true, projectRoot, captureDir: capDir });

    expect(result.conflicts).toHaveLength(1);
    expect(result.conflicts[0]).toContain('PreToolUse');
    const { hooks } = writtenSettings(result);
    // The pre half is left as it was; the post half, which was absent, is added.
    expect(hooks['PreToolUse']).toHaveLength(1);
    expect(hooks['PostToolUse']![0]!.hooks[0]!.command).toContain('posttooluse');
  });

  it('backs up the settings file before touching it', () => {
    const projectRoot = join(testDir, 'project-backup');
    mkdirSync(join(projectRoot, '.claude'), { recursive: true });
    writeFileSync(join(projectRoot, '.claude', 'settings.json'), '{"model":"opus"}', 'utf-8');

    const result = installClaudeHook({ project: true, projectRoot, captureDir: capDir });

    expect(result.backupPath).toBeTruthy();
    expect(readFileSync(result.backupPath!, 'utf-8')).toBe('{"model":"opus"}');
  });

  it('buildHookCommand names the half it is registering', () => {
    expect(buildHookCommand()).toContain('pretooluse');
    expect(buildHookCommand('pre')).toContain('pretooluse');
    expect(buildHookCommand('post')).toContain('posttooluse');
  });
});

// ── install --shell tests ──────────────────────────────────────────

describe('Phase 3: installShellShims', () => {
  let binDir: string;
  let capDir: string;

  beforeEach(() => {
    setup();
    binDir = join(testDir, 'bin');
    capDir = join(testDir, 'captures');
  });

  afterEach(teardown);

  it('creates shim directory and reports installed binaries', () => {
    const result = installShellShims({
      binDir,
      captureDir: capDir,
      shimBinary: null,
    });

    expect(existsSync(binDir)).toBe(true);
    expect(result.pathInstruction).toContain('export PATH');
    expect(result.pathInstruction).toContain(binDir);
  });

  it('creates capture directory', () => {
    installShellShims({
      binDir,
      captureDir: capDir,
      shimBinary: null,
    });

    expect(existsSync(capDir)).toBe(true);
  });

  it('returns empty installed binaries without real shim binary', () => {
    // Without a real shim binary, symlinks may be created but point to nothing
    const result = installShellShims({
      binDir,
      captureDir: capDir,
      shimBinary: null,
    });

    expect(result).toBeDefined();
    expect(result.binDir).toBe(binDir);
  });
});

// ── uninstall --shell tests ──────────────────────────────────────

describe('Phase 3: uninstallShellShims', () => {
  let binDir: string;

  beforeEach(() => {
    setup();
    binDir = join(testDir, 'bin');
    mkdirSync(binDir, { recursive: true });
  });

  afterEach(teardown);

  it('handles non-existent directory gracefully', () => {
    const result = uninstallShellShims({
      binDir: join(testDir, 'nonexistent'),
    });
    expect(result.removed).toEqual([]);
    expect(result.binDirRemoved).toBe(false);
  });

  it('removes known shim symlinks from bin dir', () => {
    // Create some dummy files for known shim names
    for (const name of ['terraform', 'rm', 'gh']) {
      const fp = join(binDir, name);
      writeFileSync(fp, '#!/bin/sh\necho shim', 'utf-8');
    }

    const result = uninstallShellShims({ binDir });
    expect(result.removed).toContain('terraform');
    expect(result.removed).toContain('rm');
    expect(result.removed).toContain('gh');

    // Files should be gone
    expect(existsSync(join(binDir, 'terraform'))).toBe(false);
    expect(existsSync(join(binDir, 'rm'))).toBe(false);
  });
});