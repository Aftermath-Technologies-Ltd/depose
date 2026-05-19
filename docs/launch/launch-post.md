# Depose the Agent. Produce the Record.

**TL;DR:** DEPOSE is a forensic toolkit that turns AI coding agent sessions into
court-admissible evidence bundles — hash-chained, Ed25519-signed, RFC 3161-timestamped,
and narrativized. If an AI agent ran `terraform destroy -auto-approve` on your infra,
you can **produce the record** of who told it to, when, and what it did.

---

## The Problem

AI coding agents (Claude Code, Codex, Cursor, etc.) now execute destructive shell
commands autonomously: `rm -rf`, `git push --force`, `terraform destroy`, `kubectl delete`.
When something goes wrong, you need to answer:

1. **Who** authorized the destructive action?
2. **What** was the state before and after?
3. **Can you prove it** — without the defense claiming the logs were tampered with?

Standard logs don't cut it. They're append-only at best, unsigned, untampered-proof,
and easy to fabricate after the fact. A git log shows you what happened, but not who
was in the room.

## What DEPOSE Does

DEPOSE captures every agent action into a **reconstruction bundle** (`.depo`) that is:

| Property | Mechanism |
|---|---|
| **Tamper-evident** | Hash chain (IRONROOT): each event includes the SHA-256 of the prior event. Altering any event invalidates the entire chain. |
| **Authenticating** | Ed25519 signatures: the producer signs the manifest root hash. Private key never leaves the machine. |
| **Time-anchored** | RFC 3161 timestamps from DigiCert/Google TSA. Cryptographic proof the bundle existed at a specific time. |
| **Complete** | Gaps are disclosed, not hidden. A `tool_result` without a matching `shell_command_pre` produces an explicit **gap event**. |
| **Deterministic** | Same inputs → same bundle. The narrative renderer uses Handlebars templates with no side-effect helpers. |
| **Honest** | The narrative (`narrative.md`, `narrative.html`) is **excluded from the signed content**. It's derived from signed events. Modifying it does not affect validity. |

## How It Works

```
┌──────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────┐
│  Capture  │──▶│  Normalize   │──▶│  Reconstruct │──▶│  Bundle  │
│ (hooks +  │   │ (merge JSONL │   │ (timeline +  │   │ (sign +  │
│  shims)   │   │  + captures) │   │  destructive │   │ timestamp│
│           │   │              │   │  rules)      │   │  + narrate│
└──────────┘   └──────────────┘   └──────────────┘   └──────────┘
```

1. **Capture**: A Claude Code `PreToolUse` hook intercepts every `Bash`, `Edit`, and
   `Write` call *before* execution. A Go shim (`depose-shim`) wraps destructive binaries
   (`terraform`, `aws`, `kubectl`, etc.) to capture `argv`, `cwd`, `user`, file hashes,
   and filtered environment variables. **Observation-only** — never blocks or denies.

2. **Normalize**: Claude Code JSONL + capture records are merged into a canonical event
   stream. Capture records are linked to corresponding `tool_result` events. Gaps are
   explicitly generated where pre-capture is missing.

3. **Reconstruct**: The event stream is built into a timeline with parent-child links,
   destructive operation detection (9 built-in rules: `rm-rf`, `git-push-force`,
   `terraform-destroy`, `aws-s3-rb`, `kubectl-delete`, `sql-drop`, etc.), and coverage
   gap analysis.

4. **Bundle**: Events are hash-chained, the manifest is Ed25519-signed, and RFC 3161
   timestamps are acquired. A deterministic narrative is rendered (Markdown + HTML).
   The `commentary.md` (from `depose explain`) is explicitly excluded from `rootHash`.

## Legal Posture

DEPOSE is designed for **defensibility**, not automatic admissibility:

- **FRE 901(b)(9)**: The hash chain + signature scheme satisfies the "process or system"
  authentication requirement. The verifier (`depose-verify`) is open-source and
  reproducible.
- **FRE 902(13)/(14)**: Self-authentication templates are included. A certifier declaration
  + Ed25519 signature qualifies under 902(13); RFC 3161 timestamps qualify under 902(14).
- **Gaps are disclosed**: The system does not hide incomplete capture coverage. Every
  `tool_result` without a pre-execution snapshot generates a gap event. This honesty
  strengthens credibility — opposing counsel can't claim you concealed anything.

**Not legal advice.** Consult your attorney before relying on DEPOSE bundles in
proceedings.

## Quick Start

```bash
# Install the Claude Code hook (observation-only, never blocks)
depose install --claude

# Install shell shims for destructive binaries
depose install --shell
# Add ~/.depose/bin to PATH before /usr/local/bin

# After an incident, produce a signed bundle
depose package --from-claude ~/.claude/projects/*/session.jsonl

# Verify a bundle
depose-verify path/to/incident-ULID.depo/
```

## Example Bundles

Two synthetic reconstructions are included:

- **PocketOS**: An agent runs `terraform destroy -auto-approve` and `aws s3 rb --force`.
  Demonstrates critical-destructive detection and gap disclosure.
- **DataTalks**: An agent `DROP`s a production database via `psql`. Demonstrates
  SQL-drop detection and reflog gap analysis.

Run them: `cd examples/pocketos-reconstruction && bash produce.sh`

## Technical Specifications

- **Language**: TypeScript ESM (NodeNext) + Go 1.23
- **Hash**: SHA-256 over canonical JSON (RFC 8785 deterministic serialization)
- **Signature**: Ed25519 (libsodium-wrappers-sumo via @depose/chain)
- **Timestamp**: RFC 3161 with SHA-256, DigiCert/Google TSA
- **Bundle format**: `.depo` directory — `manifest.json`, `events.jsonl`, `raw/`,
  `artifacts/`, `attestations/`, `narrative.md`, `narrative.html`
- **Test coverage**: 198 tests across 17 test files

## What DEPOSE Is Not

- It is **not a sandbox**. Capture hooks are observation-only. They do not block or deny
  tool calls. Use existing permission systems for that.
- It is **not a guarantee of admissibility**. Legal admissibility depends on jurisdiction,
  foundation, and judicial discretion. DEPOSE provides technical authenticity; your
  attorney provides legal foundation.
- It is **not secret**. Everything is open-source. The verifier is reproducible. The
  bundle format is documented. Opposing counsel can verify too.

---

*Depose the agent. Produce the record.*