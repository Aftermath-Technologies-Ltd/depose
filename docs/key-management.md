# DEPOSE key management

DEPOSE bundles in `signed` mode carry an Ed25519 signature over the
canonical JSON of the manifest. Two questions follow:

1. Where does the producer's key come from?
2. How does a recipient know it's the *right* key?

The answers depend on whether the producer has an OIDC identity
provider available. Today, only the air-gapped local-key flow is
implemented end to end. The Sigstore keyless path is scaffolded but
not yet operational (see §6).

---

## 1. Two key flows

### 1.1 Sigstore keyless (preferred for CI, not yet implemented)

A producer running in GitHub Actions, GitLab CI, or any environment
that can mint an OIDC token would sign with an *ephemeral* private
key. Its public counterpart would be bound to the OIDC identity via a
short-lived Fulcio certificate; the binding would be recorded in
Rekor. No long-lived key would exist afterwards.

Recipients would verify with the Go verifier and an identity
allowlist:

```
depose-verify verify --signer-identity '^https://github.com/Aftermath-Technologies-Ltd/depose/' <bundle>
```

Status today:

- `packages/chain/src/sign-sigstore.ts` is a scaffold; every entry
  point throws.
- The verifier accepts `--signer-identity` as a flag, but enforcement
  is not wired in.
- Use the air-gapped flow below in the meantime.

### 1.2 Air-gapped local key with published fingerprint

For sealed-environment producers, DEPOSE uses a local Ed25519 keypair
under `~/.depose/keys/`:

```
~/.depose/keys/
  signing.key            # PEM-encoded Ed25519 private key, 0600
  signing.pub            # PEM-encoded Ed25519 public key,  0644
  catalog.json           # signed lifecycle record, 0644
  archive/<old-fp>/
    signing.key          # retired key material, 0600
    signing.pub          # retired public key,   0644
```

The keys are auto-generated on first signed bundle. `signing.key` is
written with 0600 permissions and never logged. The public key
fingerprint is what the recipient pins.

---

## 2. Fingerprint format

A fingerprint is `SHA-256` of the SPKI DER bytes of the public key,
formatted as lowercase hex. The TypeScript producer and the Go
verifier compute it identically, so a fingerprint printed by
`depose key fingerprint` matches what `manifest.producer.keyFingerprint`
records inside the bundle.

For human display, ssh-style `SHA256:<base64>` is available via the
`--ssh` flag. The on-the-wire form in the manifest stays hex so it's
grep-able and unambiguous.

```bash
$ depose key fingerprint
9c2d4f3a6b8e1c7d5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e

$ depose key fingerprint --ssh
SHA256:nC1POmuOHH1fSjsyHQ7p+KdsXU4/KhsMnY58alW0w24
```

---

## 3. Recipient verification

The recipient binds verification to the producer's identity by passing
the fingerprint they obtained out of band:

```bash
depose-verify verify \
  --expected-key-fingerprint 9c2d4f3a6b8e1c7d5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e \
  incident-01JABC.../
```

A bundle whose embedded fingerprint disagrees with
`--expected-key-fingerprint` is rejected. A bundle that omits the
field is also rejected (no silent "ok if missing").

When the producer has rotated or revoked keys, the recipient additionally
pins the published catalog:

```bash
depose-verify verify \
  --expected-key-fingerprint <current-active-fingerprint> \
  --revocation-list ./catalog.json \
  incident-01JABC.../
```

Any bundle signed under a fingerprint marked `revoked` in the catalog
fails verification, regardless of which fingerprint the recipient
expected.

---

## 4. Distributing your fingerprint

The producer must publish the fingerprint, and ideally the full
catalog, on a channel the recipient already trusts. The fingerprint
itself is safe to publish (it is a public hash of a public key); the
*trust* is in the channel.

Practical options, in increasing order of formality:

1. **Project README or company .well-known page.** Plain text on a
   page served from a domain the recipient trusts. The recipient
   reads the fingerprint over TLS, types it into
   `--expected-key-fingerprint`. Acceptable for routine evidence
   sharing; the trust root is your domain.
2. **Signed git tag.** Tag a release with the fingerprint in the tag
   message, sign the tag with your existing git signing key
   (`git tag -s`). Recipients verify the git signature, then read the
   tag message. Trust root: your git signing key (which is usually
   already known to your collaborators).
3. **Printed handshake.** For high-stakes evidentiary contexts
   (litigation, regulatory submission), print the fingerprint and
   hand it to opposing counsel or the regulator in person. Trust
   root: the in-person delivery.
4. **Published catalog.** Export the catalog with
   `depose key catalog --export catalog.json` and host it alongside
   the fingerprint. The catalog covers rotations and revocations
   over time, not just the active fingerprint. Recipients pin the
   catalog URL the same way they pin a single fingerprint.

The catalog file is plain JSON. It is intended to be safe to publish
on a public page. It does not contain private key material.

---

## 5. Lifecycle commands

### 5.1 Print the active fingerprint

```bash
depose key fingerprint              # lowercase hex
depose key fingerprint --ssh        # SHA256:<base64>
```

If no key exists yet, this generates one (matching the side-effect of
the first `depose record` run).

### 5.2 Rotate

Use rotation for routine key hygiene (annual rotation, after a
laptop change, after staff turnover). Bundles signed by the old key
remain cryptographically valid; recipients who still trust the old
fingerprint continue to verify them.

```bash
depose key rotate
```

This command:

1. Reads the current active key, computes its fingerprint, and marks
   it `rotated` in the catalog.
2. Moves the current `signing.key` / `signing.pub` into
   `archive/<old-fingerprint>/`.
3. Generates a fresh Ed25519 keypair, writes it as the new
   `signing.key` / `signing.pub` (0600 / 0644), and records it as
   `active` in the catalog.
4. Prints the new fingerprint and the catalog path.

After rotation, republish the new fingerprint over your trusted
channel. The catalog now contains both fingerprints (old =
`rotated`, new = `active`); export and share it so recipients who
still need to verify pre-rotation bundles can keep doing so.

If `archive/<old-fp>/` already exists (e.g., from a botched previous
rotate), the command fails closed with a clear error rather than
overwriting archived material.

### 5.3 Revoke

Use revocation when a key may be compromised. A revoked key cannot
sign new bundles, and the verifier rejects existing bundles signed
under it when run with `--revocation-list`.

```bash
depose key revoke <fingerprint> --reason "<plain English why>"
```

Revocation is deliberately blocking: `--reason` is required. The
catalog records `revokedAt` and the reason text verbatim. There is
no `--force` to revoke without a reason because the absence of a
reason in the public record is itself a signal that the revocation
might not be legitimate.

After revoking:

1. If the revoked key is the active one, run `depose key rotate`
   immediately to install a fresh active key. Until you do, every
   subsequent `depose record` will succeed cryptographically but will
   embed a fingerprint that the catalog says is revoked.
2. Republish the catalog. Recipients who pin
   `--revocation-list <catalog>` will refuse the revoked key from
   that moment on.
3. Notify recipients out of band that a revocation occurred. The
   reason field is for the public record; the operational context
   (what was leaked, what action they should take) belongs in a
   direct notification.

### 5.4 Catalog

```bash
depose key catalog                  # print catalog JSON to stdout
depose key catalog --export catalog.json   # write to a file for publishing
```

If the catalog file does not exist yet, `catalog` seeds it from the
current active key so the published file is never empty.

Catalog schema (verbatim from `packages/chain/src/key-catalog.ts`):

```jsonc
{
  "schemaVersion": 1,
  "updatedAt": "2026-05-19T09:00:00.000Z",
  "entries": [
    {
      "fingerprint": "9c2d4f3a...",
      "status": "active",                // active | rotated | revoked
      "issuedAt": "2026-05-19T08:30:00.000Z",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n..."
    }
  ]
}
```

`rotated` entries also carry `rotatedAt`. `revoked` entries also
carry `revokedAt` and `reason`. Revocation wins over rotation; once
a fingerprint is `revoked`, marking it `rotated` is a no-op.

---

## 6. Threat model alignment

The air-gapped flow protects against:

- A recipient receiving a bundle signed by an unrelated key
  (`--expected-key-fingerprint` rejects it).
- A bundle signed by a key the producer has retired
  (`--revocation-list` rejects it once the producer publishes the
  revocation).
- Silent omission of the fingerprint from the manifest (verifier
  rejects bundles without `manifest.producer.keyFingerprint` in
  signed mode).

It does not protect against:

- Compromise of the producer's `signing.key` before the producer
  notices and revokes. RFC 3161 timestamps and the
  `timestamp-backdating` check still bound when the attacker can
  claim a bundle existed, but a key holder during the validity window
  can sign new bundles that verify.
- A compromised channel between producer and recipient (e.g., the
  fingerprint published on a hijacked domain). The trust root is
  whatever channel the recipient uses; harden it accordingly.

The Sigstore keyless path, when implemented, will close the
long-lived-key risk by removing the long-lived key entirely. The
verifier's `--signer-identity` flag is already parsed; producer-side
support lands in a follow-up.

For the broader threat surface, see `docs/threat-model.md`.

---

## 7. Catalog signing (planned)

The catalog is currently trusted at the same level as the
fingerprint pin: both must reach the recipient over a channel the
recipient trusts. A future iteration will sign the catalog with the
producer's active key, so any change to the catalog requires the
active key as well, and the recipient can detect tampering with the
catalog independently of how they obtained it.

Until catalog signing lands, publish the catalog on a hardened
channel (HTTPS-served domain you control, signed git tag, printed
handshake), the same as the bare fingerprint.
