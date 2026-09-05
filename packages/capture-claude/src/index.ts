// packages/capture-claude/src/index.ts
//
// Capture-claude package, Claude Code PreToolUse hook support.
// Phase 3: Active capture layer.
//
// Named exports only.

// Hook handlers
export {
  handlePreToolUse,
  runHook,
  runHookCli,
  clearProcessTreeCache,
  type HookInput,
  type HookDeps,
  type HookHalf,
  type HookOutcome,
} from './hook-entry.js';

export {
  handlePostToolUse,
  mergeFileStates,
  type EffectDeps,
} from './hook-effect.js';

export {
  parseHookInput,
  buildArgv,
  canonicalInputHash,
  readExitCode,
  reduceEnv,
} from './hook-input.js';

// Intent markers, the pre half's handoff to the post half
export {
  getPendingDir,
  writePendingIntent,
  takePendingIntent,
  type PendingIntent,
} from './pending.js';

// Failure evidence
export {
  writeCaptureFailedRecord,
  buildCaptureFailedPayload,
  sanitizeErrorMessage,
  type HookPhase,
  type HookFailure,
  type CaptureFailedOutcome,
} from './capture-failed.js';

// Capture record I/O
export {
  DEFAULT_CAPTURE_DIR,
  getCaptureDir,
  writeCaptureRecord,
  writeEffectRecord,
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