// packages/narrative/src/index.ts
//
// @depose/narrative, Deterministic narrative renderer for DEPOSE bundles.
//
// BUILD_PLAN.md §6 Phase 4:
//   "Template-driven, deterministic, every claim cites event ID.
//    No LLM in signed path."
//
// Named exports only (BUILD_PLAN.md §3.1).

export {
  renderMarkdown,
  renderHtml,
  buildNarrativeData,
  summarizeEvent,
  groupEventsIntoSections,
  type RenderOptions,
} from './render.js';

export {
  renderRule902Cert,
  buildCertDataFromManifest,
  type Rule902CertData,
} from './rule-902.js';