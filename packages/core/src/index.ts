// packages/core/src/index.ts
//
// Core package, event schema, normalizers, reconstruction.
// Named exports only.

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
  CaptureFailedPayload,
  ToolCallEffectPayload,
  FileEffect,
  ExecveRecordPayload,
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
  generateSalt,
} from './events/ids.js';

// Field commitments
export {
  COMMITMENT_KEY,
  COMMITMENT_ALGORITHM,
  computeCommitment,
  isCommitmentPlaceholder,
  parseDisclosableSpec,
  commitEventFields,
  commitEvents,
  openCommitment,
  restoreEvent,
  type CommitmentOpening,
  type CommitmentsFile,
  type CommitmentPlaceholder,
} from './events/commitments.js';

// Event wire form
export {
  serializeEvent,
  parseEventLine,
  parseMonoNs,
  compareByTime,
  bigintReplacer,
} from './events/event-io.js';

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
  looksLikeFishHistory,
  unescapeFishValue,
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
  normalizeCodexJsonl,
  detectCodexFormat,
  CODEX_FORMATS,
  type CodexFormat,
  type CodexNormalizeOptions,
  type CodexNormalizationResult,
} from './normalize/codex.js';

export {
  mergeEvents,
  type MergeOptions,
  type MergeResult,
} from './normalize/merge.js';

export {
  bindIntentAndEffect,
  type IntentEffectOptions,
  type IntentEffectResult,
} from './normalize/merge-intent-effect.js';

export {
  correlateKernelExecves,
  type KernelCorrelationOptions,
  type KernelCorrelationResult,
} from './normalize/merge-kernel.js';

export {
  normalizeCaptureRecords,
  DEFAULT_CAPTURE_DIR,
  CAPTURE_FAILED_SIDECAR,
  type CaptureNormalizeOptions,
  type CaptureNormalizeResult,
  type CaptureScope,
  type CaptureExclusionReason,
} from './normalize/capture.js';

export {
  readCaptureFailed,
  readEffectRecord,
  readExecveRecord,
} from './normalize/capture-scope.js';

// Reconstruction
export {
  buildTimeline,
  formatTimelineSummary,
  type ReconstructionTimeline,
  type TimelineNode,
  loadDestructiveRules,
  parseDestructiveRulesYaml,
  parseRulesetYaml,
  loadRuleset,
  DEFAULT_DISCLOSABLE,
  parseTsaList,
  type Ruleset,
  type RulesetTsa,
  matchDestructiveRules,
  buildDestructiveOpsIndex,
  simpleCommandsForEvent,
  splitShellCommand,
  expandArgv,
  expandCommandString,
  type DestructiveRule,
  type RuleMatcher,
  type RuleMatch,
  type RuleSeverity,
  type RawSimpleCommand,
  type SimpleCommandOrigin,
  type SimpleCommand,
} from './reconstruct/index.js';
