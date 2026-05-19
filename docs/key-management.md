# DEPOSE key management

DEPOSE bundles in `signed` mode carry an Ed25519 signature over the
canonical JSON of the manifest. Two questions follow:

1. **Where does the producer's key come from?**
2. **How does a recipient know it's the *right* key?**

The answers depend on whether the producer has an OIDC identity
provider available.

## Two key flows

### Sigstore keyless (preferred for CI)

A producer running in GitHub Actions, GitLab CI, or any environment
that can mint an OIDC token signs with an *ephemeral* private key.
That key's public counterpart is bound to the OIDC identity via a
short-lived Fulcio certificate; the binding is recorded in Rekor's
transparency log. The bundle carries the cert and signature; no
long-lived key exists anywhere afterwards.

Recipients verify with the Go verifier and an identity allowlist:

```
depose-verify verify --signer-identity '^https://github.com/Aftermath-Technologies-Ltd/depose/' <bundle>
```

The Sigstore code path is currently scaffolded
(`packages/chain/src/sign-sigstore.ts`). The verifier's
`--signer-identity` flag is recognized today; the producer-side
flow lands in a follow-up.

### Air-gapped local key with published fingerprint

For sealed-environment producers, DEPOSE uses a local Ed25519
keypair at `~/.depose/keys/signing.key` (auto-generated on first
use, `0600` perms). To make this trustworthy, the producer publishes
the **fingerprint** out-of-band:

- Print it: `depose key fingerprint` (hex) or `depose key
  fingerprint --ssh` (`SHA256:<base64>`).
- Publish it on a `.well-known` page, a key catalog, a printed
  handshake to the recipient's counsel, etc.

The producer's fingerprint goes into the bundle as
`manifest.producer.keyFingerprint`. The recipient pins it:

```
depose-verify verify --expected-key-fingerprint <hex> <bundle>
```

A bundle whose embedded fingerprint disagrees with the
`--expected-key-fingerprint` is rejected. A bundle that omits the
field is also rejected (no silent "ok if missing").

## Fingerprint format

The fingerprint is `SHA-256` of the SPKI DER bytes of the public
key, formatted as lowercase hex. The TS producer and the Go
verifier compute it the same way, so a fingerprint printed by
`depose key fingerprint` matches what `producer.keyFingerprint`
contains.

For human display, ssh-style `SHA256:<base64>` is available; the
on-the-wire form in the manifest stays hex so it's grep-able and
unambiguous.

## Rotation and revocation (TODO)

The current design has no formal rotation or revocation primitive.
A producer rotating their key publishes the new fingerprint and
asks the recipient to update `--expected-key-fingerprint`. Bundles
signed by an old, retired key still verify against their
contemporaneous fingerprint; recipients who only know the new
fingerprint will reject them.

A future iteration may add a signed key catalog (one DEPOSE bundle
that lists the producer's authorized fingerprints over time) to
make this multi-key story honest.
