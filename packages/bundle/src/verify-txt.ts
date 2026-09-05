// packages/bundle/src/verify-txt.ts
//
// Recipient-facing text the writer emits alongside the evidence:
// verify.txt (instructions written for an attorney, not an engineer) and
// the banners a dev-unsigned bundle carries so nobody mistakes it for
// evidence.

import type { Manifest } from './manifest.js';
import { VERIFIER_DOWNLOAD_URL } from './constants.js';

/** Prepended to narrative.md and verify.txt in dev-unsigned mode. */
export const DEV_UNSIGNED_BANNER = [
  '═══════════════════════════════════════════════════════════════════',
  '  THIS IS A DEVELOPMENT BUNDLE, NOT EVIDENCE',
  '',
  '  This bundle was produced with mode="dev-unsigned". It carries',
  '  NO Ed25519 signature and NO RFC 3161 timestamp. It is suitable',
  '  for pipeline testing only. It is NOT admissible as evidence.',
  '═══════════════════════════════════════════════════════════════════',
  '',
].join('\n');

/**
 * Inject the dev-unsigned banner at the top of an HTML body.
 *
 * @param html - The rendered narrative HTML.
 * @returns The HTML with the banner as the first body element.
 */
export function wrapHtmlBanner(html: string): string {
  const banner = '<div style="background:#7a1f1f;color:#fff;padding:1em 1.5em;border-bottom:4px solid #ff0;font-family:-apple-system,Segoe UI,sans-serif;font-weight:bold"><strong>THIS IS A DEVELOPMENT BUNDLE, NOT EVIDENCE.</strong> mode="dev-unsigned": no signature, no timestamp.</div>';
  if (html.includes('<body>')) {
    return html.replace('<body>', `<body>${banner}`);
  }
  if (html.includes('<body ')) {
    return html.replace(/<body([^>]*)>/, `<body$1>${banner}`);
  }
  return banner + html;
}

/**
 * Build verify.txt, plain-English instructions for the recipient.
 *
 * @param manifest - The manifest whose identity and counts the text cites.
 * @returns The file contents.
 */
export function buildVerifyTxt(manifest: Manifest): string {
  return [
    `DEPOSE Evidence Bundle Verification Instructions`,
    `═══════════════════════════════════════════════════`,
    '',
    `Bundle ID: ${manifest.bundleId}`,
    `Produced: ${manifest.producedAt}`,
    `Session: ${manifest.session.sessionId}`,
    `Agent: ${manifest.session.agentId}`,
    '',
    `This bundle contains a chronological record of an AI coding agent session.`,
    `The record is cryptographically signed and timestamped to prove it has not`,
    `been altered since creation.`,
    '',
    `To verify this bundle:`,
    '',
    `  1. Download the depose-verify binary, SHA256SUMS, SHA256SUMS.sig,`,
    `     and SHA256SUMS.pem from:`,
    `     ${VERIFIER_DOWNLOAD_URL}`,
    '',
    `  2. (Recommended) Verify the binary was built by the official`,
    `     GitHub Actions release workflow and not tampered with in`,
    `     transit. With cosign (https://docs.sigstore.dev/system_config/installation/):`,
    '',
    `     cosign verify-blob \\`,
    `       --certificate SHA256SUMS.pem \\`,
    `       --signature SHA256SUMS.sig \\`,
    `       --certificate-identity-regexp '^https://github.com/Aftermath-Technologies-Ltd/depose/' \\`,
    `       --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\`,
    `       SHA256SUMS`,
    '',
    `     Then check that your downloaded binary's SHA-256 matches the`,
    `     corresponding line in SHA256SUMS.`,
    '',
    `  3. Run:`,
    `     ./depose-verify verify <path-to-this-folder>`,
    '',
    `  4. A PASS result means:`,
    `     - Every event in this bundle matches its recorded hash chain`,
    `     - The manifest signature is valid`,
    `     - A trusted timestamp authority confirmed this bundle existed at ${manifest.producedAt}`,
    `     - Every file in this folder matches the signed files map: nothing`,
    `       has been added, removed, or modified since creation`,
    '',
    `  5. A FAIL result means the bundle may have been altered.`,
    '',
    `This bundle contains ${manifest.counts.events} events,`,
    `${manifest.counts.destructiveOperations} destructive operations,`,
    `and ${manifest.counts.gaps} coverage gaps.`,
    '',
    `For questions, contact the bundle producer.`,
  ].join('\n');
}
