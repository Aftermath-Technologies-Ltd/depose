// packages/capture-claude/src/env-allowlist.ts
//
// Environment variable allowlist for pre-execution capture.
// Only allowlisted keys are stored in plaintext in capture records.
// The full env is hashed (not stored) for tamper-evidence.
//
// See BUILD_PLAN.md §7.2 (Privacy) and §7.3 (Security).

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
 * Filter an env object to only allowlisted keys.
 * Returns both the filtered subset and a SHA-256 hash of the full env
 * (for tamper-evidence without exposing secrets).
 */
export function filterEnv(
  env: Record<string, string>,
  extraPrefixes?: string[]
): {
  envSubset: Record<string, string>;
  envHash: string;
} {
  const filtered: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (isEnvAllowed(key, extraPrefixes)) {
      filtered[key] = value;
    }
  }
  // Hash the full sorted key-value for tamper-evidence
  const fullEnvCanonical = Object.entries(env)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
  const envHash = sha256String(fullEnvCanonical);
  return { envSubset: filtered, envHash };
}

// ── Internal ─────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';

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