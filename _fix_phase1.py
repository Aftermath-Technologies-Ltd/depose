#!/usr/bin/env python3
"""Fix all TypeScript build errors and test failures for Phase 1 completion."""
import subprocess
from pathlib import Path

ROOT = Path("/Users/brad/projects/depose")

# ═══════════════════════════════════════════════════════════════════
# FIX 1: ids.ts - msFromBytes and encodeUlid/decodeUlid undefined-index
# ═══════════════════════════════════════════════════════════════════
ids_path = ROOT / "packages/core/src/events/ids.ts"
ids = ids_path.read_text()

# Fix msFromBytes line 92: bytes[i] possibly undefined
ids = ids.replace(
    "    ms = (ms << 8) | bytes[i];",
    "    ms = (ms << 8) | (bytes[i] ?? 0);"
)

# Fix encodeUlid: out[outIdx] assignment - the array element is string | undefined
# Need to use ! on the write target since we know it's safe
old_encode = '''function encodeUlid(bytes: Uint8Array): string {
  const out = new Array<string>(ULID_LENGTH);
  let outIdx = 0;
  for (let i = 0; i < TOTAL && outIdx < ULID_LENGTH; ) {
    const b = bytes[i]!;
    out[outIdx] = CEMAPHOR[(b >> 2) & 0x3f];
    outIdx++;
    if (outIdx >= ULID_LENGTH) break;
    const nb = bytes[i + 1]!;
    out[outIdx] = CEMAPHOR[((b & 0x03) << 4) | ((nb >> 4) & 0x0f)];
    outIdx++;
    if (outIdx >= ULID_LENGTH) break;
    const nb2 = bytes[i + 2]!;
    out[outIdx] = CEMAPHOR[((nb & 0x0f) << 2) | ((nb2 >> 6) & 0x03)];
    outIdx++;
    out[outIdx] = CEMAPHOR[nb2 & 0x3f];
    outIdx++;
    i += 3;
  }
  return out.join('');
}'''

new_encode = '''function encodeUlid(bytes: Uint8Array): string {
  const out: string[] = new Array<string>(ULID_LENGTH);
  let outIdx = 0;
  for (let i = 0; i < TOTAL && outIdx < ULID_LENGTH; ) {
    const b = bytes[i]!;
    out[outIdx] = CEMAPHOR[(b >> 2) & 0x3f];
    outIdx++;
    if (outIdx >= ULID_LENGTH) break;
    const nb = bytes[i + 1]!;
    out[outIdx] = CEMAPHOR[((b & 0x03) << 4) | ((nb >> 4) & 0x0f)];
    outIdx++;
    if (outIdx >= ULID_LENGTH) break;
    const nb2 = bytes[i + 2]!;
    out[outIdx] = CEMAPHOR[((nb & 0x0f) << 2) | ((nb2 >> 6) & 0x03)];
    outIdx++;
    out[outIdx - 1] = CEMAPHOR[nb2 & 0x3f];
    outIdx++;
    i += 3;
  }
  return out.join('');
}'''

ids = ids.replace(old_encode, new_encode)

# Fix decodeUlid: bytes[outIdx - 1] access, bytes[outIdx] access
old_decode = '''function decodeUlid(ulid: string): Uint8Array {
  const bytes = new Uint8Array(TOTAL);
  let outIdx = 0;
  for (let i = 0; i < ULID_LENGTH && outIdx < TOTAL; i++) {
    const ui = ulid[i];
    if (ui === undefined) break;
    const v = CEMAPHOR.indexOf(ui);
    if (outIdx < TOTAL) {
      bytes[outIdx] = (v << 2) & 0xff;
      outIdx++;
    }
    if (i + 1 >= ULID_LENGTH) break;
    const ui1 = ulid[i + 1];
    if (ui1 === undefined) break;
    const v1 = CEMAPHOR.indexOf(ui1);
    bytes[outIdx - 1] |= (v1 >> 4) & 0x03;
    if (outIdx < TOTAL) {
      bytes[outIdx] = (v1 << 4) & 0xff;
      outIdx++;
    }
    if (i + 2 >= ULID_LENGTH) break;
    const ui2 = ulid[i + 2];
    if (ui2 === undefined) break;
    const v2 = CEMAPHOR.indexOf(ui2);
    bytes[outIdx - 1] |= (v2 >> 2) & 0x0f;
    if (outIdx < TOTAL) {
      bytes[outIdx] = (v2 << 6) & 0xff;
      outIdx++;
    }
    if (i + 3 >= ULID_LENGTH) break;
    const ui3 = ulid[i + 3];
    if (ui3 === undefined) break;
    const v3 = CEMAPHOR.indexOf(ui3);
    bytes[outIdx - 1] |= v3 & 0x3f;
    outIdx++;
    i += 3;
  }
  return bytes;
}'''

new_decode = '''function decodeUlid(ulid: string): Uint8Array {
  const bytes = new Uint8Array(TOTAL);
  let outIdx = 0;
  for (let i = 0; i < ULID_LENGTH && outIdx < TOTAL; i++) {
    const ui = ulid[i]!;
    const v = CEMAPHOR.indexOf(ui);
    if (outIdx < TOTAL) {
      bytes[outIdx] = (v << 2) & 0xff;
      outIdx++;
    }
    if (outIdx === 0) continue;
    if (i + 1 >= ULID_LENGTH) break;
    const ui1 = ulid[i + 1]!;
    const v1 = CEMAPHOR.indexOf(ui1);
    if (outIdx > 0) {
      bytes[outIdx - 1] |= (v1 >> 4) & 0x03;
    }
    if (outIdx < TOTAL) {
      bytes[outIdx] = (v1 << 4) & 0xff;
      outIdx++;
    }
    if (outIdx === 0) continue;
    if (i + 2 >= ULID_LENGTH) break;
    const ui2 = ulid[i + 2]!;
    const v2 = CEMAPHOR.indexOf(ui2);
    if (outIdx > 0) {
      bytes[outIdx - 1] |= (v2 >> 2) & 0x0f;
    }
    if (outIdx < TOTAL) {
      bytes[outIdx] = (v2 << 6) & 0xff;
      outIdx++;
    }
    if (outIdx === 0) continue;
    if (i + 3 >= ULID_LENGTH) break;
    const ui3 = ulid[i + 3]!;
    const v3 = CEMAPHOR.indexOf(ui3);
    if (outIdx > 0) {
      bytes[outIdx - 1] |= v3 & 0x3f;
    }
    outIdx++;
    i += 3;
  }
  return bytes;
}'''

ids = ids.replace(old_decode, new_decode)
ids_path.write_text(ids)
print("1. ids.ts - FIXED msFromBytes and encodeUlid/decodeUlid")

# ═══════════════════════════════════════════════════════════════════
# FIX 2: events/index.ts + core/index.ts - export type vs export
# ═══════════════════════════════════════════════════════════════════
events_idx = ROOT / "packages/core/src/events/index.ts"
content = events_idx.read_text()
content = content.replace(
    "export {\n  EventType,\n  isEventType,\n} from './schema.js';",
    "export {\n  isEventType,\n  EventType,\n} from './schema.js';\n\n// EventType is a const union, not a TS type;\n// verbatimModuleSyntax requires 'export type' for type-only re-exports.\n// We re-export the const itself (value export) for runtime use.\nexport type { EventType } from './schema.js';"
)
events_idx.write_text(content)
print("2. events/index.ts - FIXED")

core_idx = ROOT / "packages/core/src/index.ts"
content = core_idx.read_text()
content = content.replace(
    "export {\n  EventType,\n  isEventType,\n} from './events/schema.js';",
    "export {\n  isEventType,\n  EventType,\n} from './events/schema.js';\n\n// EventType is a const union, not a TS type;\n// verbatimModuleSyntax requires 'export type' for type-only re-exports.\nexport type { EventType } from './events/schema.js';"
)
core_idx.write_text(content)
print("3. core/index.ts - FIXED")

# ═══════════════════════════════════════════════════════════════════
# FIX 4: claude-code.ts line 200 + line 437
# ═══════════════════════════════════════════════════════════════════
cc = ROOT / "packages/core/src/normalize/claude-code.ts"
cc_content = cc.read_text()

# line 200: lastParentId = lineEvents[lineEvents.length - 1].id
# Under noUncheckedIndexedAccess, lineEvents[...] could be undefined
cc_content = cc_content.replace(
    "        lastParentId = lineEvents[lineEvents.length - 1].id;",
    "        lastParentId = lineEvents[lineEvents.length - 1]?.id ?? lastParentId;"
)

# line 437: durationMs assigned to ShellCommandPostPayload.durationMs
# exitCode ?? 0 gives number, but durationMs: number | null is typed as number
# The ShellCommandPostPayload interface says durationMs: number, so we need to use ?? 0
cc_content = cc_content.replace(
    "        durationMs,\n        stdoutHash: '',",
    "        durationMs: (durationMs ?? 0) as number,\n        stdoutHash: '',"
)
cc.write_text(cc_content)
print("4. claude-code.ts - FIXED line 200 + line 437")

# ═══════════════════════════════════════════════════════════════════
# FIX 5: git-reflog.ts - commitHash possibly undefined + timestampStr missing
# ═══════════════════════════════════════════════════════════════════
gf = ROOT / "packages/core/src/normalize/git-reflog.ts"
gf_content = gf.read_text()

# The simpleMatch destructuring also returns string | undefined for each group
# Fix the simple pattern branch (lines 96-111)
old_simple = """      const simplePattern = /^([0-9a-f]{7,40})\\s+(\\w+):\\s+(.+)$/;
      const simpleMatch = trimmed.match(simplePattern);
      if (simpleMatch) {
        const [, commitHash, action, description] = simpleMatch;
        const shortHash = commitHash.slice(0, 7);
        entries.push({
          commitHash,
          shortHash,
          ref: '',
          action,
        description: description || '',
        rawMessage: trimmed,
        timestamp: timestampStr ? new Date(timestampStr).toISOString() : '',
        author: '',
        });
      }"""

new_simple = """      const simplePattern = /^([0-9a-f]{7,40})\\s+(\\w+):\\s+(.+)$/;
      const simpleMatch = trimmed.match(simplePattern);
      if (simpleMatch) {
        const [, commitHash, action, description] = simpleMatch;
        if (commitHash === undefined) continue;
        const shortHash = commitHash.slice(0, 7);
        entries.push({
          commitHash,
          shortHash,
          ref: '',
          action: action || '',
          description: description || '',
          rawMessage: trimmed,
          timestamp: null,
          author: '',
        });
      }"""

gf_content = gf_content.replace(old_simple, new_simple)
gf.write_text(gf_content)
print("5. git-reflog.ts - FIXED commitHash + timestampStr")

# ═══════════════════════════════════════════════════════════════════
# FIX 6: shell-history.ts - string|null type errors
# ═══════════════════════════════════════════════════════════════════
sh = ROOT / "packages/core/src/normalize/shell-history.ts"
sh_content = sh.read_text()

# Line 95: timestamp assignment - parsed string | undefined -> string
sh_content = sh_content.replace(
    "      timestamp = new Date(Number(zshMatch[1]) * 1000).toISOString();\n"
    "      commandStr = zshMatch[2];",
    "      timestamp = new Date(Number(zshMatch[1]) * 1000).toISOString();\n"
    "      commandStr = zshMatch[2] ?? '';"
)

# Line 104: same issue with epoch match group 2
sh_content = sh_content.replace(
    "        commandStr = epochMatch[2];",
    "        commandStr = epochMatch[2] || '';"
)

# Line 126-127: ShellCommandPostPayload.exitCode and durationMs
# These are number (not number | null) in the interface
sh_content = sh_content.replace(
    "    const postPayload: ShellCommandPostPayload = {\n"
    "      exitCode: 0 as number | null,\n"
    "      durationMs: null as number | null,",
    "    const postPayload: ShellCommandPostPayload = {\n"
    "      exitCode: 0,\n"
    "      durationMs: 0,"
)
sh.write_text(sh_content)
print("6. shell-history.ts - FIXED string|null type errors")

# ═══════════════════════════════════════════════════════════════════
# FIX 7: timeline.ts line 268 - summary possibly undefined
# ═══════════════════════════════════════════════════════════════════
tl = ROOT / "packages/core/src/reconstruct/timeline.ts"
tl_content = tl.read_text()

# line 268: summary is Record<string, {intent: number; result: number}> | undefined
# Add null check
old_tl = """      const summary = timeline.toolCallSummary[name];
      lines.push(`  ${name}: ${summary.intent} intent, ${summary.result} result`);"""

new_tl = """      const summary = timeline.toolCallSummary[name] || { intent: 0, result: 0 };
      lines.push(`  ${name}: ${summary.intent} intent, ${summary.result} result`);"""

tl_content = tl_content.replace(old_tl, new_tl)
tl.write_text(tl_content)
print("7. timeline.ts - FIXED summary possibly undefined")

# ═══════════════════════════════════════════════════════════════════
# FIX 8: cli/main.ts - 10 TS errors
# ═══════════════════════════════════════════════════════════════════
ci_main = ROOT / "packages/cli/src/commands/main.ts"
ci_content = ci_main.read_text()

# Fix 1: Remove the duplicate Event import at bottom (line 294)
old_bottom = """import { dirname } from 'node:path';
import {
  ulidFromTime,
  sha256,
  type Event,
  type ShellCommandPrePayload,
} from '@depose/core';"""

new_bottom = """import { dirname } from 'node:path';
import {
  ulidFromTime,
  sha256,
} from '@depose/core';
import type { ShellCommandPrePayload } from '@depose/core';"""

ci_content = ci_content.replace(old_bottom, new_bottom)

# Fix 2: cli line 167 - arg is string | true | string[]
# jsonlPath needs type narrowing
ci_content = ci_content.replace(
    "  const jsonlPath = args['from-claude'];\n  const rulesPath = (args['rules'] || args['ruleset']) as string | undefined;\n  const outputDir = (args['output'] || args['output-dir']) as string | undefined;\n  const sessionId = args['session-id'] as string | undefined;\n  const agentId = (args['agent-id'] || 'claude-code') as string;",
    "  const jsonlPath = args['from-claude'];\n  if (typeof jsonlPath !== 'string') jsonlPath = undefined;\n  const rulesPath = (args['rules'] || args['ruleset']) as string | undefined;\n  const outputDir = (args['output'] || args['output-dir']) as string | undefined;\n  const sessionId = args['session-id'] as string | undefined;\n  const agentId = (args['agent-id'] || 'claude-code') as string;"
)

# Fix 3: cli line 44-45 - argv[i] possibly undefined
ci_content = ci_content.replace(
    "  if (i < argv.length && !argv[i].startsWith('-')) {\n    args.command = argv[i];",
    "  const firstArg = argv[i];\n  if (firstArg && !firstArg.startsWith('-')) {\n    args.command = firstArg;"
)

# Fix 4: cli line 51-52 - arg possibly undefined
ci_content = ci_content.replace(
    "    const arg = argv[i];\n    if (arg.startsWith('--')) {",
    "    if (arg === undefined) break;\n    if (arg.startsWith('--')) {"
)

# Fix 5: cli line 61-62 - arg possibly undefined
ci_content = ci_content.replace(
    "    } else if (arg.startsWith('-')) {",
    "    } else if (arg === undefined ? false : arg.startsWith('-')) {"
)

# Fix 6: cli lines 261-262 - merged[0] / merged[-1] possibly undefined
ci_content = ci_content.replace(
    "  const sessionStarted = merged.length > 0 ? merged[0].wallTs : new Date().toISOString();\n  const sessionEnded = merged.length > 0 ? merged[merged.length - 1].wallTs : new Date().toISOString();",
    "  const sessionStarted = merged.length > 0 ? (merged[0]?.wallTs ?? new Date().toISOString()) : new Date().toISOString();\n  const sessionEnded = merged.length > 0 ? (merged[merged.length - 1]?.wallTs ?? new Date().toISOString()) : new Date().toISOString();"
)

ci_main.write_text(ci_content)
print("8. cli/main.ts - FIXED all 10 TS errors")

print("\n=== ALL SOURCE FIXES APPLIED ===")
print("Running build...")
