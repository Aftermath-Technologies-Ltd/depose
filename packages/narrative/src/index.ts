// packages/narrative/src/index.ts
//
// @depose/narrative, Deterministic narrative renderer for DEPOSE bundles.
//
// Template-driven, deterministic, every claim cites an event ID.
// No LLM in the signed path.
//
// Named exports only.

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