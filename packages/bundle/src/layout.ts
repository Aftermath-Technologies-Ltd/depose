// packages/bundle/src/layout.ts
//
// Bundle path conventions and constants.
// See docs/bundle-format.md#directory-layout for the full layout.

export const BUNDLE_DIR_PREFIX = 'incident';
export const MANIFEST_FILENAME = 'manifest.json';
export const EVENTS_FILENAME = 'events.jsonl';
export const RAW_CLAUDE_DIR = 'claude-code';
export const RAW_CODEX_DIR = 'codex';
export const RAW_SHELL_DIR = 'shell-history';
export const RAW_REFLOG_FILENAME = 'git-reflog.txt';
export const RAW_CAPTURE_DIR = 'capture';
export const ARTIFACTS_PRE_DIR = 'files-pre';
export const ARTIFACTS_POST_DIR = 'files-post';
export const ATTESTATIONS_DIR = 'attestations';
export const ATTESTATIONS_SIGNATURES = 'signatures.json';
export const ATTESTATIONS_TIMESTAMPS_DIR = 'rfc3161-timestamps';
export const ATTESTATIONS_REKOR = 'rekor-entries.json';
export const RULES_DIR = 'rules';
export const RULES_FILENAME = 'destructive.yaml';
export const NARRATIVE_MD = 'narrative.md';
export const NARRATIVE_HTML = 'narrative.html';
export const VERIFY_TXT = 'verify.txt';
