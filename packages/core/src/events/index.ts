// packages/core/src/events/index.ts
//
// Named exports only (BUILD_PLAN.md §3.1).
// Re-exports all event types, payloads, and utilities.

export type {
  AgentId,
  Event,
  EventBase,
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
} from './schema.js';

export { isEventType } from './schema.js';
export type { EventType } from './schema.js';

export {
  generateUlid,
  ulidFromTime,
  isValidUlid,
  ulidToTime,
  setFixedUlidSeed,
  clearFixedUlidSeed,
} from './ids.js';

export {
  canonicalJson,
  sortKeys,
  sha256,
  sha256String,
  sha256Bytes,
} from './canonical-json.js';
