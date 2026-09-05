// packages/core/src/reconstruct/index.ts
//
// Named exports only. Re-exports reconstruction utilities.

export {
  buildTimeline,
  formatTimelineSummary,
  type ReconstructionTimeline,
  type TimelineNode,
} from './timeline.js';

export {
  loadDestructiveRules,
  parseDestructiveRulesYaml,
  type DestructiveRule,
  type RuleMatcher,
  type RuleMatch,
  type RuleSeverity,
} from './destructive-rules.js';

export {
  matchDestructiveRules,
  buildDestructiveOpsIndex,
  simpleCommandsForEvent,
} from './destructive-match.js';

export {
  splitShellCommand,
  type RawSimpleCommand,
  type SimpleCommandOrigin,
} from './shell-split.js';

export {
  expandArgv,
  expandCommandString,
  type SimpleCommand,
} from './shell-expand.js';
