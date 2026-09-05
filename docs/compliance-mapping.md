# Compliance Mapping

What a DEPOSE bundle contains, and which record-keeping obligation each
part answers.

**Read this first.** DEPOSE does not make an AI system compliant, and
nothing here decides whether a given system is in scope. Whether a coding
agent is a high-risk AI system under Annex III of the EU AI Act, whether
an outage is a major ICT-related incident under DORA, and whether a
record is a required book or record under SEC Rule 17a-4 are the
operator's determinations, made with counsel. What the tables below say
is narrower and checkable: for each obligation, which bundle field or
verifier check produces the evidence, and where DEPOSE stops.

The last column of every table is the one that matters. "Produces the
record" means the bundle contains the thing the obligation asks to be
recorded. "Partial" means it contains some of it. "No" means the
obligation is about something DEPOSE does not do, and the row is there so
a reader does not assume otherwise.

Citations are to the articles and paragraphs as in force on
2026-09-05. Regulations change; re-check before relying on a row.

---

## Regulation (EU) 2024/1689, the AI Act

Obligations for high-risk AI systems under Annex III have applied since
**2 August 2026** (Article 113(c)). Annex I high-risk systems follow on
2 August 2027.

| Article | What it requires | What DEPOSE produces | Status |
|---|---|---|---|
| 12(1) | High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system. | The capture layer records events at execution time, not from a transcript afterwards: `shell_command_pre` (argv, cwd, env subset, process ancestry, pre-state file hashes), `tool_call_effect` (exit status, post-state hashes), and, on Linux with the eBPF collector, `process_spawn` tagged `source: kernel`. | Produces the record |
| 12(2)(a) | Logging shall enable recording of events relevant for identifying situations that may result in the system presenting a risk under Article 79(1) or in a substantial modification. | `rules/destructive.yaml` is applied at reconstruction time and every match is an indexed destructive operation, counted in `manifest.counts.destructiveOperations` and named in the narrative with the simple command that fired and its position in the compound command. | Produces the record |
| 12(2)(b) | Logging shall facilitate post-market monitoring (Article 72). | `events.jsonl` is a complete ordered timeline with a per-event hash chain and an RFC 6962 Merkle root, so a monitoring programme can pool bundles across sessions without trusting the pooling. | Produces the record |
| 12(2)(c) | Logging shall facilitate the monitoring of operation referred to in Article 26(5). | `manifest.counts` (events, destructive operations, gaps, captures attributed and excluded) is inside the signed form, so an operational summary cannot be softened after the fact. | Produces the record |
| 12(3) | For Annex III point 1(a) systems, logs shall record the period of use, the reference database, the input data, and the persons involved in verification. | Period of use is `session.startedAt` and `session.endedAt`. Input data and reference databases are recorded only where the agent's own tool calls named them. Persons involved are not recorded at all: DEPOSE identifies a producer key, not a natural person. | Partial |
| 19(1) | Providers shall keep the automatically generated logs for at least six months. | A bundle is a directory the provider retains; DEPOSE imposes no expiry and `depose captures prune` requires an explicit `--older-than` and `--yes`. Retention is the provider's policy and DEPOSE neither enforces nor shortens it. | The retention floor is the operator's; DEPOSE does not delete |
| 26(6) | Deployers shall keep the logs under their control for at least six months, unless Union or national law requires longer. | As above. `manifest.producedAt` and the RFC 3161 token date the bundle, so the start of the retention window is provable rather than asserted. | The retention floor is the operator's; DEPOSE dates the record |
| 26(5) | Deployers shall monitor operation and inform the provider of a risk under Article 79(1). | Gap events, and `manifest.counts.gaps`, state what the record does not cover. A bundle with zero gaps is a bundle where every observable action correlated; a bundle with gaps says where monitoring was blind. | Produces the record |
| 73 | Providers shall report serious incidents to market surveillance authorities. | `depose disclose` produces a subset bundle that proves membership in the sealed set without revealing withheld events, so a report can carry evidence without carrying the whole session. | Produces the record |

**What the AI Act asks for that DEPOSE does not produce.** Article 11 and
Annex IV technical documentation, Article 9 risk management system
records, Article 10 data governance records, Article 14 human oversight
design, and Article 15 accuracy and robustness metrics. DEPOSE records
what one session did. It says nothing about how the system was built.

---

## Regulation (EU) 2022/2554, DORA

| Article | What it requires | What DEPOSE produces | Status |
|---|---|---|---|
| 17(1) | Financial entities shall define, establish and implement an ICT-related incident management process to detect, manage and notify ICT-related incidents. | The process is the entity's. DEPOSE is the evidence step inside it: `depose record` at the point of the incident. | No; DEPOSE is an input to the process |
| 17(2) | Financial entities shall record all ICT-related incidents and significant cyber threats, and ensure root causes are identified, documented and addressed. | The bundle is the record of one incident: the prompt that started it, every tool call, the destructive operations that fired, the files that changed and their hashes before and after, and the gaps. Root cause analysis is human work; the bundle is what it works from. | Produces the record |
| 17(3)(b) | Procedures to identify, track, log, categorise and classify ICT-related incidents according to priority and severity. | Every destructive-rule match carries a severity (`critical`, `high`, `medium`, `low`) from the ruleset, and the ruleset is pinned by `manifest.rulesetHash` and shipped inside the bundle, so the classification a bundle used cannot be revised after the fact. | Produces the record |
| 17(3)(c) | Assign roles and responsibilities for different incident types. | No. DEPOSE records a producer key fingerprint, not an organizational role. | No |
| 19(1), 19(4) | Report major incidents to the competent authority, with initial, intermediate and final reports. | A disclosure bundle carries exactly the events the report cites, with an inclusion proof against the sealed root, so an intermediate report and a final report over the same incident are provably about the same evidence (`depose-verify consistency`). | Produces the record |
| 26 | Threat-led penetration testing. | No. | No |
| 28 to 30 | ICT third-party risk management, including contractual arrangements. | No. A bundle records what an agent did, not who supplied it. | No |

---

## SEC Rule 17a-4, electronic records for broker-dealers

The 2022 amendments (effective 3 January 2023, compliance 3 May 2023)
added an audit-trail alternative to the WORM requirement. DEPOSE's
structure lines up with the audit-trail alternative, not with WORM: it
does not make storage immutable, it makes alteration detectable.

| Paragraph | What it requires | What DEPOSE produces | Status |
|---|---|---|---|
| 17a-4(f)(2)(i)(A)(2) | An electronic recordkeeping system that preserves records in a way that permits the recreation of an original record if it is modified or deleted. | DEPOSE does not preserve prior versions and cannot recreate a deleted record. It detects that one changed: the files map pins every file by SHA-256 and length, and the chain and Merkle root pin every event. | Partial: detects, does not recreate |
| 17a-4(f)(2)(i)(A)(2) | A complete time-stamped audit trail of all modifications to and deletions of a record. | The RFC 3161 token dates the seal against a third party's clock, and `timestamp-backdating` fails a bundle whose `producedAt` is after its own token. Modifications after sealing fail `files-map`, `chain-replay`, or `merkle-root`, each by name. | Produces the record |
| 17a-4(f)(2)(i)(A)(2) | The date and time of operator entries and actions that create, modify, or delete the record. | Every event carries `wallTs` and a monotonic `monoNs`, and the capture layer records `capturedAt` with `capturedAtSource` saying whether the time was observed or derived. | Produces the record |
| 17a-4(f)(2)(i)(A)(2) | The individual(s) creating, modifying, or deleting the record. | Partial. The bundle records the Unix user, hostname, TTY, and process ancestry of the capturing process, and a producer key fingerprint. It does not authenticate a natural person. | Partial |
| 17a-4(a), 17a-4(b) | Six-year and three-year retention, the first two years in an easily accessible place. | Retention is the firm's. A bundle is a directory; DEPOSE imposes no expiry and deletes nothing on its own. | The retention floor is the operator's |
| 17a-4(f)(3)(v) | Records must be readily downloadable and reproducible in a human-readable format. | `narrative.md` and `narrative.html` are human-readable and deterministic from the signed events; `verify.txt` states what a recipient should run. Both are excluded from the root hash and say so, because a readable rendering is not the record. | Produces the record |
| 17a-4(i) | Third-party access to records, with an undertaking to furnish them to the Commission. | No. That is a contractual arrangement, not a file format. | No |

---

## HIPAA Security Rule, 45 CFR Part 164 Subpart C

| Section | What it requires | What DEPOSE produces | Status |
|---|---|---|---|
| 164.312(b) | Audit controls: hardware, software, or procedural mechanisms that record and examine activity in information systems containing or using electronic protected health information. | The capture layer is such a mechanism for one class of activity: what an AI coding agent did. It records the command, the files it named, and their hashes before and after. It does not read file contents unless the producer opts in, so it records that ePHI-bearing files changed without becoming a second copy of them. | Produces the record, for agent activity |
| 164.308(a)(1)(ii)(D) | Information system activity review: procedures to regularly review records of information system activity. | The narrative is a deterministic review artifact with a per-event citation for every claim, and the destructive-operations index is where a reviewer starts. The procedure and the cadence are the covered entity's. | Produces the record |
| 164.312(c)(1) | Integrity: protect ePHI from improper alteration or destruction. | DEPOSE detects rather than protects. `file-continuity` fails a bundle where a file's recorded outcome disagrees with the next recorded pre-state and no gap discloses the difference, which is exactly "something altered this and nothing here witnessed it". | Partial: detects, does not prevent |
| 164.312(c)(2) | A mechanism to corroborate that ePHI has not been altered or destroyed in an unauthorized manner. | The pre-state and post-state SHA-256 of every file a tool call named, bound into the signed chain. | Produces the record |
| 164.312(e)(2)(i) | Integrity controls for ePHI transmitted electronically. | No. DEPOSE records what happened on one host. | No |
| 164.316(b)(1), (b)(2)(i) | Retain required documentation for six years from creation or from when it was last in effect, whichever is later. | Retention is the covered entity's. The RFC 3161 token establishes the creation date the six years run from. | The retention floor is the operator's; DEPOSE dates the record |
| 164.502, 164.514 | Minimum necessary; de-identification. | `depose disclose` opens only the fields named on the command line and leaves the rest as salted commitments, so a bundle disclosed to an auditor carries the events the audit is about and proves the others exist without revealing them. Choosing what is minimum necessary is the covered entity's. | Produces the mechanism |

---

## What is common to all four

Every regime above asks for the same three things in different words: a
record of what happened, evidence that the record has not been altered,
and a date that does not depend on the record-keeper's own clock.

| Requirement | DEPOSE mechanism | Verifier check that proves it |
|---|---|---|
| A record of what happened | `events.jsonl`, the capture layer, the intent and effect pair | `payload-hash`, `intent-effect`, `file-continuity` |
| Unaltered since it was made | Per-event hash chain, RFC 6962 Merkle root, signed files map over every file in the tree | `chain-replay`, `merkle-root`, `files-map`, `attestation-files` |
| Dated independently | RFC 3161 token over the signed manifest, from a third-party authority | `timestamp-verify`, `timestamp-backdating`, `anchor-status` |
| What the record does not cover | Gap events, and counts inside the signed manifest | `intent-effect`, `file-continuity` fail a bundle that has a hole and no gap disclosing it |
| Disclosing part without the whole | Salted field commitments, RFC 6962 inclusion proofs | `disclosure-inclusion`, `disclosure-commitments`, `disclosure-files` |

The fourth row is the one auditors ask about last and care about most. A
log that cannot say where it is blind is a log that has to be taken on
faith. DEPOSE's gaps are enforced: removing one fails a named check.

---

## What DEPOSE is not

- **Not a control.** The hook observes and never denies. A destructive
  rule firing records a finding; it did not stop the command, and the
  SCITT export marks every constraint `blocking: false` for that reason.
- **Not an identity system.** A bundle proves which key sealed it. Tying
  that key to a person is `docs/key-management.md`'s subject and it ends
  at a published fingerprint.
- **Not a retention system.** Nothing expires and nothing is deleted
  automatically. Every retention floor above is the operator's to meet.
- **Not a compliance certification.** No table here says a system is
  compliant. Each says which artifact answers which sentence of a
  regulation, so a compliance argument can be made from evidence instead
  of from assertion.
