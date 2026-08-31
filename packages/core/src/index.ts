// packages/core/src/index.ts
//
// Core package, event schema, normalizers, reconstruction.
// Named exports only (BUILD_PLAN.md §3.1).

// Event types and payloads
export type {
  AgentId,
  Event,
  EventBase,
  EventCorrelation,
  ProcessNode,
  PromptPayload,
  AssistantMessagePayload,
  ToolCallIntentPayload,
  ToolCallExecutedPayload,
  ToolResultPayload,
  FileDiffPayload,
  ShellCommandPrePayload,
  ShellCommandPostPayload,
  EnvChangePayload,
  ProcessSpawnPayload,
  ErrorPayload,
  GapPayload,
} from './events/schema.js';

export { isEventType } from './events/schema.js';
export type { EventType } from './events/schema.js';

// ULID helpers
export {
  generateUlid,
  ulidFromTime,
  isValidUlid,
  ulidToTime,
  setFixedUlidSeed,
  clearFixedUlidSeed,
} from './events/ids.js';

// Canonical JSON and hashing
export {
  canonicalJson,
  sortKeys,
  sha256,
  sha256String,
  sha256Bytes,
} from './events/canonical-json.js';

// Normalizers
export {
  normalizeClaudeCodeJsonl,
  type ClaudeCodeLine,
  type ClaudeCodeNormalizeOptions,
  type ClaudeCodeNormalizationResult,
} from './normalize/claude-code.js';

export {
  parseShellHistory,
  parseBashHistory,
  parseFishHistory,
  tokenize,
  type ShellHistoryCommand,
  type ShellHistoryParser,
} from './normalize/shell-history.js';

export {
  parseGitReflog,
  reflogToEvents,
  type GitReflogEntry,
} from './normalize/git-reflog.js';

export {
  mergeEvents,
  type MergeOptions,
  type MergeResult,
} from './normalize/merge.js';

export {
  normalizeCaptureRecords,
  DEFAULT_CAPTURE_DIR,
  type CaptureNormalizeOptions,
  type CaptureNormalizeResult,
  type CaptureScope,
  type CaptureExclusionReason,
} from './normalize/capture.js';

// Reconstruction
export {
  buildTimeline,
  formatTimelineSummary,
  type ReconstructionTimeline,
  type TimelineNode,
  loadDestructiveRules,
  parseDestructiveRulesYaml,
  matchDestructiveRules,
  buildDestructiveOpsIndex,
  type DestructiveRule,
  type RuleMatcher,
  type RuleMatch,
} from './reconstruct/index.js';
