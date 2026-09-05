# Export Mapping

`depose export <bundle> --format <name>` renders a sealed bundle into an
IETF interchange format. Three targets:

| `--format` | Draft | Output |
|---|---|---|
| `aat` | [draft-sharif-agent-audit-trail-00](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/) | JSON Lines, one Agent Audit Trail record per sealed event |
| `asqav-receipt` | [draft-marques-asqav-compliance-receipts-08](https://datatracker.ietf.org/doc/draft-marques-asqav-compliance-receipts/) | JSON Lines, one signed compliance receipt per agent action |
| `scitt-statement` | [draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/) + [draft-mih-scitt-agent-action-capsule-04](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/) | One COSE_Sign1 Signed Statement carrying an Agent Action Capsule |

Each exporter is pure: the same bundle (and, for the two signed formats,
the same key) always produces the same bytes. Ed25519 signatures are
deterministic (RFC 8032 §5.1.6), so the checked-in golden exports under
`packages/bundle/test/golden-exports/` are byte comparisons.

```bash
depose export incident-01JABC... --format aat
depose export incident-01JABC... --format asqav-receipt --key-dir ~/.depose/keys
depose export incident-01JABC... --format scitt-statement --out statement.cose
```

The two signed formats refuse to run with a key whose fingerprint differs
from `manifest.producer.keyFingerprint`. A signed export asserts the
sealing producer's identity, so signing one as a different party has to be
asked for with `--allow-key-mismatch`, not defaulted into.

All three drafts are Internet-Drafts, not RFCs, and none is endorsed by
the IETF. Field names will move. The version each exporter targets is in
its module header, and `spec_version` is carried inside the capsule.

---

## Where a draft was ambiguous

The rule applied throughout: pick the reading that keeps the DEPOSE
guarantee intact. DEPOSE's claim is that a recipient can check what
happened against a signature and a timestamp. Any mapping that would put
an unverifiable assertion into the export loses to one that says less.

### AAT identifiers are UUIDv8, not UUIDv4

AAT makes `record_id` and `session_id` UUID v4. Version 4 asserts the
value was randomly generated. DEPOSE identifies events by ULID, and
minting a random UUID would sever the export from the bundle it came
from: nobody holding both could tell which record was which event.

The export emits **UUID version 8** (RFC 9562 §5.8, custom format):

```
uuid = SHA-256("depose:aat:event:" + <event ULID>)[0..16]
       with octet 6 high nibble set to 8 and octet 8 variant bits set to 10
```

`session_id` uses the namespace `depose:aat:session`. Both are
well-formed RFC 9562 UUIDs with the RFC 4122 variant, so a consumer
parsing the field as a UUID accepts it, and anyone with the bundle can
recompute the mapping. A validator that specifically requires version 4
will reject these; that is the trade, made deliberately.

The DEPOSE event ULID also appears verbatim in
`action_detail.depose_event_id`, so no derivation is needed to get back
to the bundle.

### AAT has no value for "we did not observe this"

`outcome` is one of success, failure, timeout, denied, escalated. A
DEPOSE `gap` event is none of those: it records a hole in coverage. The
export reports gaps as `outcome: "failure"` with
`action_detail.event: "coverage_gap"` and the gap reason. Reporting a
hole as a success would be the one mapping choice that misleads a reader
holding the export alone.

### AAT trust level

`trust_level` is REQUIRED and DEPOSE has no equivalent field. Every
record is exported as **L2**. DEPOSE observes and never gates, so a level
that implies enforcement would be false; L2 ("operates under policy with
logging") is what a hook-observed agent actually is. The value is a
constant, not a measurement, and a reader should treat it as one.

### ASQAV records an observation, not a decision

The receipt profile is built around access-control decisions:
`decision` is one of allow, deny, rate_limit, observation. DEPOSE never
allowed or denied anything; the hook is observation-only by design
(threat-model.md §1). Every receipt therefore carries
`decision: "observation"`, and `reason` is absent because the profile
requires it only for deny and rate_limit.

### The RFC 3161 token is not an ASQAV anchor

The profile defines an anchor's scope as
`SHA-256(JCS({payload, signature}))`, the receipt envelope with `anchors`
removed. DEPOSE's RFC 3161 token commits to the bundle manifest instead.
It says nothing about any receipt.

Putting it in `anchors` would be a false claim about what the TSA saw.
The export instead carries it in the OPTIONAL `rfc3161_timestamp` field,
which the profile describes as caller-supplied, and emits `anchors: []`.

**Consequence:** these receipts do not meet the profile's requirement of
at least one timestamping anchor. Meeting it needs a fresh TSA call over
the receipt envelope, which `depose export` does not make: an exporter
that reached the network would not be a pure function of the bundle, and
a second anchor would attest to the export's creation time rather than to
the incident. Anchor the receipts yourself if your regime requires it;
the DEPOSE timestamp over the manifest is the one that dates the evidence.

### The capsule draft's envelope is not a SCITT Signed Statement

draft-mih-scitt-agent-action-capsule-04 defines a "Producer Envelope":
a COSE_Sign1 with exactly three protected entries (`alg`,
`content_type: application/agent-action-capsule-id`, `kid`), an empty
unprotected map, and the raw 32-byte capsule id as payload. It carries no
CWT claims.

draft-ietf-scitt-architecture REQUIRES `CWT_Claims` (label 15) with `iss`
and `sub` in the protected header of a Signed Statement. The two cannot
both be satisfied.

Registration with a transparency service is the stated purpose, and that
is the SCITT side, so `--format scitt-statement` emits the
SCITT-conforming form:

| Protected header | Value |
|---|---|
| `1` (alg) | `-8` (EdDSA) |
| `3` (content type) | `application/agent-action-capsule+json` |
| `4` (kid) | the 32 raw Ed25519 public key bytes |
| `15` (CWT_Claims) | `{1: "did:key:z6Mk...", 2: "depose:bundle:<bundleId>"}` |

The payload is the capsule as JCS-canonicalized JSON, attached rather
than detached. To produce the capsule draft's own envelope instead, sign
the 32 bytes of `capsule_id` from the payload of this statement.

### One capsule per bundle, not per event

A capsule is "a digest-committed record of one agent action". DEPOSE
exports the session as one action: the AAT export already covers the
per-event view, and a per-event capsule stream would duplicate it while
adding nothing registrable. `effect.response_digest` is the signed chain
head, which commits to every event in the session.

### A dev-unsigned bundle cannot become a Signed Statement

`--format scitt-statement` refuses a bundle whose `producer.mode` is
`dev-unsigned`. A statement puts a signature on a claim about the bundle,
and the bundle carries none of its own. `--format aat` has no such
restriction because it signs nothing.

---

## DEPOSE to AAT

Per-event fields.

| AAT field | DEPOSE source |
|---|---|
| `record_id` | UUIDv8 derived from `event.id` |
| `timestamp` | `event.wallTs` |
| `agent_id` | `urn:agent:` + `manifest.session.agentId` |
| `agent_version` | `manifest.producer.version` |
| `session_id` | UUIDv8 derived from `manifest.session.sessionId` |
| `action_type` | mapped from `event.type` (below) |
| `action_detail` | per-type, always including `depose_event_type` and `depose_event_id` |
| `outcome` | `failure` for gap, capture_failed, and error; otherwise from the exit code, defaulting to `success` |
| `trust_level` | constant `L2` |
| `parent_record_id` | UUIDv8 derived from `event.parentEventId`, or null |
| `prev_hash` | recomputed over the AAT records: `hex(SHA-256(JCS(previous record)))` |
| `input_hash` | `event.payloadHash` |
| `output_hash` | `file_diff.postHash` or `shell_command_post.stdoutHash` |
| `latency_ms` | `durationMs` from an effect, executed, or post event |

`action_type` mapping:

| DEPOSE event type | AAT action_type |
|---|---|
| `prompt`, `assistant_message` | `decision` |
| `tool_call_intent`, `tool_call_executed`, `shell_command_pre`, `process_spawn` | `tool_call` |
| `tool_call_effect`, `tool_result`, `shell_command_post`, `file_diff` | `tool_response` |
| `error` | `error` |
| `gap`, `env_change`, `capture_failed` | `lifecycle` |

`prev_hash` is recomputed over the AAT records rather than carried from
DEPOSE. The two chains commit to different bytes, and reusing a DEPOSE
chain hash under AAT's field name would be a value that does not verify
under AAT's own rule.

### DEPOSE fields with no AAT equivalent

These are in the bundle and not in the AAT export. An AAT consumer is
seeing less than a DEPOSE verifier does.

| DEPOSE field | Why it does not map |
|---|---|
| `chainHash`, `manifest.rootHash` | AAT chains its own records; there is no field for a second chain over different bytes. |
| `manifest.merkleRoot` | No AAT field. Verifiable disclosure has no AAT counterpart at all. |
| `manifest.signatures`, `manifest.timestamps` | AAT's `signature` is per-record ECDSA P-256 over the record. DEPOSE signs the manifest with Ed25519, so no per-record signature is emitted rather than a re-signature that would assert something new. |
| `manifest.files` | No AAT field for a signed files map. |
| `commitments.json` and field commitments | No AAT counterpart. A committed field exports as its `$commitment` placeholder object. |
| `correlation.linkedEffectId`, `linkedIntentId` | Partially preserved: `action_detail.closes_record_id` on an effect. The reverse direction has no field. |
| `shell_command_pre.envSubset`, `envHash`, `parentProcessTree`, `ttyId`, `user`, `hostname` | AAT's `action_detail` is action-type-specific with no defined members for execution environment. Adding them would put DEPOSE's schema inside a field the draft defines differently. |
| `shell_command_pre.fileArgs`, `tool_call_effect.files` | Only the changed paths of an effect survive, in `action_detail.files_changed`. The pre-state and post-state hashes have no AAT home. |
| Destructive rule matches | No AAT field. `risk_score` exists but is a number DEPOSE does not compute, and inventing one would be a fabricated measurement. |
| `manifest.counts.capturesExcluded` | No AAT field for records deliberately left out of the bundle. |

---

## DEPOSE to ASQAV receipts

One receipt per action event: `tool_call_intent`, `tool_call_executed`,
`tool_call_effect`, `shell_command_pre`, `process_spawn`, and `gap`.
Conversation turns produce no receipt; a receipt records an action.

| Receipt field | DEPOSE source |
|---|---|
| `type` | constant `protectmcp:decision` |
| `issued_at` | `event.wallTs` |
| `issuer_id` | bare did:key of the signing key, e.g. `key:z6Mk...` |
| `payload_digest.hash` | `sha256:` + `event.payloadHash` |
| `payload_digest.size` | byte length of the canonical event payload |
| `action_ref` | `SHA-256(JCS({tool, payloadHash}))` |
| `iteration_id` | `manifest.session.sessionId` |
| `previousReceiptHash` | `hex(SHA-256(JCS(previous receipt payload)))`, 64 zeros for the first |
| `decision` | constant `observation` |
| `tool_name` | the tool, or `depose:gap:<reason>` / `depose:<eventType>` when the event has none |
| `policy_digest` | `sha256:` of the destructive ruleset bytes |
| `unsigned_gap` | on gap receipts: `{count: 1, from, to}` at the gap's time |
| `rfc3161_timestamp` | the bundle's first RFC 3161 token, base64 |
| `signature` | `{alg: "EdDSA", kid: issuer_id, sig: base64(Ed25519 over JCS(payload)))}` |
| `anchors` | empty; see above |

### DEPOSE fields with no ASQAV equivalent

| DEPOSE field | Why it does not map |
|---|---|
| Event payload content | The profile is digest-only by design: `payload_digest` commits to it and the content stays in the bundle. This is a feature, not a loss, but it means a receipt alone does not say what ran. |
| `manifest.merkleRoot`, disclosure proofs | No receipt field. |
| `manifest.files` | No receipt field for a signed files map. |
| Destructive rule matches | `policy_digest` names the ruleset, not the verdict. `risk_class` exists but its vocabulary is operator-defined, so DEPOSE emits nothing rather than inventing a class. |
| Intent and effect binding | Both halves get their own receipt and the chain orders them, but there is no field that says one closes the other. `action_ref` differs between them because the payload hashes differ. |
| `capture_failed` records | Merged into `gap` events upstream, so they arrive as gap receipts. |

The profile's server-built fields (`authorized_under_mandate`,
`controls_evaluated`) are absent throughout: DEPOSE ran no controls, and
the profile's own rule is that an absent control key means the control
did not execute. Omission is the correct encoding.

---

## DEPOSE to an Agent Action Capsule

One capsule per bundle.

| Capsule field | DEPOSE source |
|---|---|
| `spec_version` | `draft-mih-scitt-agent-action-capsule-04` |
| `format_version` | `4` |
| `canonicalization_id` | `jcs` |
| `capsule_id` | `SHA-256(JCS(capsule without capsule_id))` |
| `action_id` | `manifest.bundleId` |
| `action_type` | `fyi`; DEPOSE never gates, so there is no disposition to report and `decide` would require one |
| `operator` | `manifest.session.sessionId` |
| `developer` | `<agentId>@<producer.version>` |
| `timestamp` | `manifest.producedAt` |
| `effect.type` | `destructive_operation` when the ruleset fired, else `agent_session` |
| `effect.status` | `confirmed` when the bundle has a chain, `dispatched` when it does not |
| `effect.irreversibility_class` | `one_way_consequential` when the ruleset fired, else `two_way` |
| `effect.response_digest` | `sha256:` + `manifest.rootHash` |
| `effect.effect_attestation` | `gate_executed` when a chain exists, else `runtime_claimed` |
| `assurance.attestation_mode` | `anchored` when the bundle carries a timestamp, else `self_attested` |
| `assurance.effect_mode` | `confirmed` when the bundle has a chain, else `dispatched_unconfirmed` |
| `assurance.ledger_mode` | `anchored` when timestamped, else `chained` |
| `constraints[]` | `destructive_ruleset`, `coverage_gaps`, and `intent_without_effect` when present, each `blocking: false` |
| `references[]` | typed digests of `events.jsonl`, the ruleset, and the Merkle root |

Every constraint is `blocking: false`. A rule firing in DEPOSE records a
finding; it never gated the command. That is the one field in this export
a reader could act on wrongly, so it says what actually happened.

### DEPOSE fields with no capsule equivalent

| DEPOSE field | Why it does not map |
|---|---|
| Per-event detail | The capsule is one action. Use `--format aat` for the timeline. |
| `disposition` | Not emitted. It is REQUIRED only for `action_type: "decide"`, and DEPOSE decides nothing. |
| `chain` | Not emitted. It links capsules across state transitions; a single bundle has no predecessor capsule. `depose anchor` and incremental sealing would give it one. |
| Field commitments and disclosure | No capsule field. A disclosure bundle is DEPOSE's own mechanism. |
| `manifest.counts.capturesExcluded` | No capsule field. |
