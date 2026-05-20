// packages/cli/src/commands/key.ts
//
// `depose key` subcommands — local Ed25519 signing key lifecycle.
//
//   fingerprint  — print the SHA-256 fingerprint of the active key
//   rotate       — archive the current key, generate a new active one
//   revoke <fp>  — mark a fingerprint as revoked (with --reason)
//   catalog      — print/export the local key catalog
//
// The fingerprint is what recipients pin against. The producer
// publishes it (and the catalog) out-of-band — a .well-known page,
// a signed git tag, an attorney's printed handshake. The verifier
// rejects bundles signed under a fingerprint the recipient has not
// pinned, and (when `--revocation-list <path>` is set) rejects
// bundles whose fingerprint is marked `revoked` in the catalog.
//
// See docs/key-management.md.

import {
  existsSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  renameSync,
} from 'node:fs';
import { join } from 'node:path';
import {
  fingerprintPublicKeyPem,
  formatFingerprintSshStyle,
  getDefaultKeyDir,
  getDefaultPublicKeyPath,
  generateEd25519KeyPair,
  loadOrGenerateKeyPair,
  loadCatalog,
  saveCatalog,
  recordActive,
  markRotated,
  markRevoked,
  findEntry,
} from '@depose/chain';

const SIGNING_KEY_FILE = 'signing.key';
const PUBLIC_KEY_FILE = 'signing.pub';
const CATALOG_FILE = 'catalog.json';

export interface KeyCommandArgs {
  'key-dir'?: string;
  /** Print fingerprint in ssh-style (SHA256:<base64>) instead of hex. */
  ssh?: boolean;
  /** Free-form reason. Required for `revoke`. */
  reason?: string;
  /** Optional output path for `catalog --export <path>`. */
  export?: string;
  [key: string]: string | boolean | string[] | undefined;
}

function resolveKeyDir(args: KeyCommandArgs): string {
  return (args['key-dir'] as string | undefined) ?? getDefaultKeyDir();
}

function catalogPath(args: KeyCommandArgs): string {
  return join(resolveKeyDir(args), CATALOG_FILE);
}

function readPublicKeyOrGenerate(keyDir: string): string {
  const pubPath = keyDir ? join(keyDir, PUBLIC_KEY_FILE) : getDefaultPublicKeyPath();
  if (existsSync(pubPath)) return readFileSync(pubPath, 'utf-8');
  return loadOrGenerateKeyPair(keyDir).publicKeyPem;
}

// ── fingerprint ────────────────────────────────────────────────────

export async function handleKeyFingerprint(args: KeyCommandArgs): Promise<void> {
  const keyDir = resolveKeyDir(args);
  const publicKeyPem = readPublicKeyOrGenerate(keyDir);
  const hex = fingerprintPublicKeyPem(publicKeyPem);
  if (args.ssh) {
    console.log(formatFingerprintSshStyle(hex));
  } else {
    console.log(hex);
  }
}

// ── rotate ─────────────────────────────────────────────────────────

export async function handleKeyRotate(args: KeyCommandArgs): Promise<void> {
  const keyDir = resolveKeyDir(args);
  mkdirSync(keyDir, { recursive: true });

  const privPath = join(keyDir, SIGNING_KEY_FILE);
  const pubPath = join(keyDir, PUBLIC_KEY_FILE);
  const catPath = catalogPath(args);

  let catalog = loadCatalog(catPath);

  // If a current key exists, archive it under archive/<old-fingerprint>/.
  if (existsSync(privPath) && existsSync(pubPath)) {
    const oldPub = readFileSync(pubPath, 'utf-8');
    const oldFp = fingerprintPublicKeyPem(oldPub);
    catalog = recordActive(catalog, oldFp, oldPub);
    catalog = markRotated(catalog, oldFp);

    const archiveDir = join(keyDir, 'archive', oldFp);
    // Refuse to overwrite archived material. If archive/<oldFp>/
    // already contains a signing.key or signing.pub, a previous
    // rotate likely failed or was redone manually; demand the user
    // resolve it rather than silently clobbering.
    const archivedPriv = join(archiveDir, SIGNING_KEY_FILE);
    const archivedPub = join(archiveDir, PUBLIC_KEY_FILE);
    if (existsSync(archivedPriv) || existsSync(archivedPub)) {
      throw new Error(
        `Refusing to rotate: archive entry already exists for ${oldFp} at ${archiveDir}. ` +
          `Move or remove it manually, then re-run depose key rotate.`,
      );
    }
    mkdirSync(archiveDir, { recursive: true });
    renameSync(privPath, archivedPriv);
    renameSync(pubPath, archivedPub);
    console.log(`Archived previous key ${oldFp} -> ${archiveDir}`);
  } else {
    console.log('No existing key to rotate; generating fresh active key.');
  }

  // Generate the new active key.
  const newKey = generateEd25519KeyPair();
  writeFileSync(privPath, newKey.privateKeyPem, { mode: 0o600 });
  writeFileSync(pubPath, newKey.publicKeyPem, { mode: 0o644 });
  const newFp = fingerprintPublicKeyPem(newKey.publicKeyPem);
  catalog = recordActive(catalog, newFp, newKey.publicKeyPem);
  saveCatalog(catPath, catalog);

  console.log(`New active key fingerprint: ${newFp}`);
  console.log(`Catalog updated: ${catPath}`);
  console.log('');
  console.log('Next steps:');
  console.log('  1. Republish your fingerprint over your trusted channel.');
  console.log('  2. Share the updated catalog with recipients (out-of-band).');
}

// ── revoke ─────────────────────────────────────────────────────────

export async function handleKeyRevoke(
  fingerprint: string,
  args: KeyCommandArgs,
): Promise<void> {
  if (!fingerprint || !fingerprint.trim()) {
    throw new Error('Usage: depose key revoke <fingerprint> --reason "<why>"');
  }
  const reason = (args.reason as string | undefined) ?? '';
  if (!reason.trim()) {
    throw new Error('depose key revoke requires --reason "<why>". Refusing to revoke without one.');
  }

  const catPath = catalogPath(args);
  let catalog = loadCatalog(catPath);

  // If the user is revoking the currently-active key, warn so they
  // don't accidentally sign new bundles under a fingerprint the
  // catalog now says is revoked. The revocation still applies; the
  // operator chose to do it. The warning surfaces the operational
  // next step so it isn't easy to miss.
  const target = findEntry(catalog, fingerprint);
  const wasActive = target?.status === 'active';

  // If the user is revoking a key that's not in the catalog yet (e.g.
  // a long-archived one), surface a clear error from markRevoked()
  // rather than silently no-op'ing.
  catalog = markRevoked(catalog, fingerprint, reason);
  saveCatalog(catPath, catalog);

  console.log(`Revoked ${fingerprint}`);
  console.log(`Reason: ${reason}`);
  console.log(`Catalog: ${catPath}`);
  console.log('');
  console.log('Share the updated catalog with recipients so depose-verify');
  console.log('--revocation-list rejects bundles signed under this key.');
  if (wasActive) {
    console.log('');
    console.log('WARNING: you revoked the currently-active key. Run');
    console.log('  depose key rotate');
    console.log('immediately to install a fresh active key. Until you do, new');
    console.log('bundles will be signed under a fingerprint the catalog marks revoked.');
  }
}

// ── catalog ────────────────────────────────────────────────────────

export async function handleKeyCatalog(args: KeyCommandArgs): Promise<void> {
  const catPath = catalogPath(args);
  const exportPath = args.export as string | undefined;

  // If no catalog yet, seed one from the current active key so the
  // file the producer publishes isn't empty.
  let catalog = loadCatalog(catPath);
  if (catalog.entries.length === 0) {
    const keyDir = resolveKeyDir(args);
    const publicKeyPem = readPublicKeyOrGenerate(keyDir);
    const fp = fingerprintPublicKeyPem(publicKeyPem);
    if (!findEntry(catalog, fp)) {
      catalog = recordActive(catalog, fp, publicKeyPem);
      saveCatalog(catPath, catalog);
    }
  }

  if (exportPath) {
    writeFileSync(exportPath, JSON.stringify(catalog, null, 2) + '\n', 'utf-8');
    console.log(`Exported catalog → ${exportPath}`);
    return;
  }

  console.log(`# Key catalog: ${catPath}`);
  console.log(JSON.stringify(catalog, null, 2));
}
