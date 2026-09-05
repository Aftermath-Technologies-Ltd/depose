// packages/capture-claude/src/env-allowlist.ts
//
// Environment variable allowlist for pre-execution capture.
// Only allowlisted keys are stored in plaintext in capture records.
// The full env is hashed (not stored) for tamper-evidence.
//
// See docs/threat-model.md §4 (env allowlist) and §3.1 (capture store).

/**
 * Default allowlist of environment variable prefixes to capture.
 * User-extensible via $DEPOSE_ENV_ALLOWLIST (comma-separated prefixes).
 */
export const ENV_ALLOWLIST_PREFIXES = [
  'AWS_',
  'GH_',
  'OPENAI_',
  'ANTHROPIC_',
  'RAILWAY_',
] as const;

/**
 * Check if an environment variable name matches any allowlisted prefix.
 */
export function isEnvAllowed(key: string, extraPrefixes?: string[]): boolean {
  const prefixes = extraPrefixes
    ? [...ENV_ALLOWLIST_PREFIXES, ...extraPrefixes]
    : ENV_ALLOWLIST_PREFIXES;
  return prefixes.some((prefix) => key.startsWith(prefix));
}

/**
 * Regex matching env variable names that likely hold secrets.
 * Keys matching this pattern have their values redacted in the subset
 * (replaced with a SHA-256 hash of the value) unless --capture-secret-values
 * is enabled.
 */
const SECRET_KEY_PATTERN = /SECRET|TOKEN|KEY|PASSWORD|CREDENTIALS/i;

/**
 * Options for filterEnv.
 */
export interface FilterEnvOptions {
  /** Extra allowlist prefixes beyond the defaults */
  extraPrefixes?: string[];
  /**
   * If true, secret values are captured in plaintext (dangerous, only
   * for debugging). Default: false (secret values are redacted to
   * "sha256:<hex>").
   *
   * Can also be enabled via $DEPOSE_CAPTURE_SECRET_VALUES=1.
   */
  captureSecretValues?: boolean;
}

/**
 * Filter an env object to only allowlisted keys.
 * Returns both the filtered subset and a SHA-256 hash of the full env
 * (for tamper-evidence without exposing secrets).
 *
 * Secret-name keys (matching SECRET_KEY_PATTERN) have their values
 * redacted to "sha256:<hex>" by default, so the envSubset never
 * contains plaintext secrets. Enable captureSecretValues to store
 * them in plaintext (not recommended, intended for local debugging only).
 */
export function filterEnv(
  env: Record<string, string>,
  extraPrefixes?: string[]
): {
  envSubset: Record<string, string>;
  envHash: string;
};
export function filterEnv(
  env: Record<string, string>,
  options: FilterEnvOptions
): {
  envSubset: Record<string, string>;
  envHash: string;
};
export function filterEnv(
  env: Record<string, string>,
  extraPrefixesOrOptions?: string[] | FilterEnvOptions
): {
  envSubset: Record<string, string>;
  envHash: string;
} {
  // Overload resolution
  let extraPrefixes: string[] | undefined;
  let captureSecretValues = resolveCaptureSecretValues();

  if (Array.isArray(extraPrefixesOrOptions)) {
    extraPrefixes = extraPrefixesOrOptions;
  } else if (extraPrefixesOrOptions && typeof extraPrefixesOrOptions === 'object') {
    const opts = extraPrefixesOrOptions as FilterEnvOptions;
    extraPrefixes = opts.extraPrefixes;
    if (opts.captureSecretValues !== undefined) {
      captureSecretValues = opts.captureSecretValues;
    }
  }

  const filtered: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (isEnvAllowed(key, extraPrefixes)) {
      if (!captureSecretValues && SECRET_KEY_PATTERN.test(key)) {
        // Redact the value, store only its SHA-256 hash
        filtered[key] = `sha256:${sha256String(value)}`;
      } else {
        filtered[key] = value;
      }
    }
  }
  // Hash the full sorted env for tamper-evidence using canonical JSON (JCS).
  // This ensures deterministic serialization regardless of key insertion order.
  const sorted = sortedRecord(env);
  const envHash = sha256String(canonicalJson(sorted));
  return { envSubset: filtered, envHash };
}

// ── Internal ─────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';
import { canonicalJson } from '@depose/core';

/** Sort a record's keys for canonical JSON serialization. */
function sortedRecord(record: Record<string, string>): Record<string, string> {
  return Object.entries(record)
    .sort(([a], [b]) => a.localeCompare(b))
    .reduce<Record<string, string>>((acc, [k, v]) => { acc[k] = v; return acc; }, {});
}

function sha256String(input: string): string {
  return createHash('sha256').update(input, 'utf-8').digest('hex');
}

/**
 * Parse extra allowlist prefixes from $DEPOSE_ENV_ALLOWLIST.
 * Format: comma-separated prefixes (e.g., "CUSTOM_,OTHER_").
 * Returns empty array if not set.
 */
export function parseExtraAllowlist(): string[] {
  const raw = process.env.DEPOSE_ENV_ALLOWLIST;
  if (!raw) return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Resolve whether secret values should be captured in plaintext.
 * Controlled by $DEPOSE_CAPTURE_SECRET_VALUES (set to "1" to enable).
 * Default: false (secret values are redacted).
 */
function resolveCaptureSecretValues(): boolean {
  return process.env.DEPOSE_CAPTURE_SECRET_VALUES === '1';
}