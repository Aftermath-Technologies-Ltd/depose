// packages/narrative/src/narrative-data.ts
//
// The view model both renderers work from. Building it is render.ts's
// job; turning it into Markdown or HTML is render-markdown.ts's and
// render-html.ts's. Keeping the shape here means neither renderer can
// reach past it into the timeline.

export interface NarrativeData {
  bundleId: string;
  producedAt: string;
  agentId: string;
  sessionId: string;
  sessionStartedAt: string;
  sessionEndedAt: string;
  totalCount: number;
  destructiveCount: number;
  gapCount: number;
  capturesAttributed: number;
  capturesExcluded: number;
  sections: Array<{ header: string; events: Array<{ type: string; wallTs: string; id: string; summary: string; detail: string }> }>;
  destructiveOps: Array<{ severity: string; wallTs: string; command: string; position: string; ruleId: string; eventId: string }>;
  gaps: Array<{ reason: string; wallTs: string; detail: string; id: string }>;
  /**
   * Intents with no recorded outcome. Kept out of the gap list and given
   * their own section because "the agent ran something and we lost what
   * happened" is the finding a reader most needs to see first.
   */
  lostOutcomes: Array<{ wallTs: string; detail: string; id: string }>;
  lostOutcomeCount: number;
  /** Kernel-witnessed execves in the agent's process tree that no hook saw. */
  unwitnessedExecves: Array<{ wallTs: string; detail: string; id: string }>;
  unwitnessedExecveCount: number;
}

