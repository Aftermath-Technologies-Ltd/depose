# Security Policy

## Supported versions

DEPOSE is pre-1.0. The current release line (`0.x`) receives security
fixes; older `0.x` releases do not. Every produced bundle records the
verifier release it was intended to be checked against
(`manifest.verifier.downloadUrl`); use *that* release of `depose-verify`
to validate a bundle, not "whatever is latest".

| Version | Supported |
|--------:|:----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

**Do not file public GitHub issues for security reports.**

Email: **security@aftermath-technologies.com**

Please include:

- A description of the issue and the impact you believe it has.
- Reproducer (commands, sample input, environment).
- Whether the issue affects the producer (`depose` / `depose-hook`), the
  verifier (`depose-verify`), the shell shim (`depose-shim`), or the
  bundle format itself.
- Whether you've already disclosed the issue elsewhere.

We will acknowledge receipt within **3 business days** and aim to
publish a fix or mitigation within **90 days** of confirmed receipt,
coordinating disclosure with you. Critical vulnerabilities in the
cryptographic trust path (chain, signature, RFC 3161, key handling) are
prioritized.

## Threat model

The threat model is published in [`docs/threat-model.md`](docs/threat-model.md).
Reports that fall outside the stated threat model are still welcome but
will be triaged accordingly.

## Hall of fame

Disclosures that lead to a confirmed fix are credited in the release
notes (with the reporter's permission).
