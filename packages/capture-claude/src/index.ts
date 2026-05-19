// packages/capture-claude/src/index.ts
//
// Capture-claude package — Claude Code PreToolUse hook support.
// Phase 3: Active capture layer.
//
// Named exports only (BUILD_PLAN.md §3.1).

// Hook handler (main Phase 3 entrypoint)
export {
  handlePreToolUse,
  runHookCli,
  type HookInput,
} from './hook-entry.js';

// Capture record I/O
export {
  DEFAULT_CAPTURE_DIR,
  getCaptureDir,
  writeCaptureRecord,
  readCaptureRecords,
} from './capture-record.js';

// Environment allowlist
export {
  ENV_ALLOWLIST_PREFIXES,
  isEnvAllowed,
  filterEnv,
  parseExtraAllowlist,
} from './env-allowlist.js';

// File hashing
export {
  hashFile,
  fileSize,
  hashFileArgs,
  type FileArg,
} from './file-hash.js';