// packages/bundle/src/index.ts
//
// Bundle package, manifest, deterministic writer, layout.
// Named exports only.

export {
  MANIFEST_SCHEMA_VERSION,
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

export { VERIFIER_DOWNLOAD_URL, GITHUB_REPO_SLUG, DEPOSE_RELEASE_TAG } from './constants.js';

export {
  buildDisclosure,
  type DisclosureDocument,
  type DisclosureOptions,
  type DisclosureResult,
} from './disclosure.js';

export {
  buildFilesMap,
  hashFileEntry,
  isFilesMapExcluded,
  assertSafeRelativePath,
  FILES_MAP_EXCLUDED,
  type FileEntry,
  type FilesMap,
} from './files-map.js';

// IETF export targets. See docs/export-mapping.md.
export {
  loadBundle,
  timestampTokens,
  type LoadedBundle,
} from './export/read-bundle.js';

export {
  exportAat,
  aatRecords,
  DEPOSE_TRUST_LEVEL,
  type AatRecord,
} from './export/aat.js';

export {
  aatAction,
  aatOutcome,
  actionDetail,
  uuidFromUlid,
  UUID_NAMESPACE_EVENT,
  UUID_NAMESPACE_SESSION,
} from './export/aat-map.js';

export {
  exportAsqavReceipts,
  asqavReceipts,
  isReceiptable,
  GENESIS_PREVIOUS_HASH,
  type AsqavReceipt,
  type AsqavSignature,
} from './export/asqav.js';

export {
  receiptPayload,
  toolName,
  type AsqavPayload,
  type ReceiptContext,
} from './export/asqav-map.js';

export {
  exportScittStatement,
  buildCapsule,
  capsuleId,
  CAPSULE_CONTENT_TYPE,
  CAPSULE_SPEC_VERSION,
  CAPSULE_FORMAT_VERSION,
  type Capsule,
} from './export/capsule.js';
