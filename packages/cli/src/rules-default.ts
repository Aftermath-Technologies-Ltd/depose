import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { readFileSync } from 'node:fs';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export const DEFAULT_RULES_PATH = resolve(PACKAGE_ROOT, 'rules/destructive.default.yaml');

export function readDefaultRulesBytes(): Buffer {
  return readFileSync(DEFAULT_RULES_PATH);
}
