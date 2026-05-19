// packages/bundle/src/index.ts
//
// Bundle package — manifest, deterministic writer, layout.
// Named exports only (BUILD_PLAN.md §3.1).

export {
  buildManifest,
  serializeManifest,
  serializeManifestForSigning,
  hashManifest,
  hashManifestForSigning,
  type BundleMode,
  type Manifest,
  type SignatureBlock,
  type Rfc3161Token,
  type RekorEntry,
} from './manifest.js';

export {
  writeBundle,
  type BundleWriterOptions,
  type BundleOutput,
} from './writer.js';

export {
  BUNDLE_DIR_PREFIX,
  MANIFEST_FILENAME,
  EVENTS_FILENAME,
  RAW_CLAUDE_DIR,
  RAW_CODEX_DIR,
  RAW_SHELL_DIR,
  RAW_REFLOG_FILENAME,
  RAW_CAPTURE_DIR,
  ARTIFACTS_PRE_DIR,
  ARTIFACTS_POST_DIR,
  ATTESTATIONS_DIR,
  ATTESTATIONS_SIGNATURES,
  ATTESTATIONS_TIMESTAMPS_DIR,
  ATTESTATIONS_REKOR,
  RULES_DIR,
  RULES_FILENAME,
  NARRATIVE_MD,
  NARRATIVE_HTML,
  VERIFY_TXT,
} from './layout.js';
