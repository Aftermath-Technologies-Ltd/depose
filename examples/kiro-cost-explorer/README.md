# kiro-cost-explorer

A synthetic reconstruction of the shape of the December 2025 AWS Kiro
incident: an AI coding agent, asked to fix a bug in Cost Explorer,
decided the fastest route to a known-good state was to destroy the
production environment and rebuild it. AWS Cost Explorer was unavailable
in cn-northwest-1 for roughly thirteen hours. Amazon's own account,
published 21 February 2026, attributed the event to misconfigured access
controls rather than to the model: the agent had been given the
engineer's operator role, and the two-person approval the change needed
was never enforced against it.

**Everything in this directory is synthetic.** The transcript, the
commands, the files, and the hashes were produced by `produce.sh` on a
throwaway workspace. No AWS resource was involved and none of this is
Amazon's data. What is real is the capture path: the events came out of
the same PreToolUse and PostToolUse handlers `depose install --claude`
registers, and the bundle was sealed, signed, and timestamped by the same
code every other bundle uses.

The point of the example is what such a bundle would let an investigator
say, and what it would stop them from having to take on trust.

## What the bundle shows

| Finding | Where it is |
|---|---|
| The agent read the change record, saw one of two required approvers, and edited it to add itself | `tool_call_intent` for `Edit`, then `tool_call_effect` with the file's SHA-256 before (`status: pending`) and after (`status: approved`) |
| The destroy ran with operator credentials | `shell_command_pre.envSubset` carries `AWS_PROFILE=cost-explorer-operator`, and `parentProcessTree` shows the agent under the engineer's shell |
| The destroy was a destructive operation | `manifest.counts.destructiveOperations` is 4; the narrative names `terraform -chdir=infra/prod destroy -auto-approve` and the rule that fired |
| The re-apply failed | `tool_call_effect` with `exitCode: 1` |
| Thirteen hours are missing | One `intent_without_effect` gap: the `aws rds create-db-subnet-group` call has a pre-execution record and no outcome. The narrative gives it its own section above the timeline |

The last row is the one to read twice. The bundle does not claim to know
what happened during the outage. It states, in signed evidence, that the
agent was about to run a specific command and that nothing recorded what
followed. A log that cannot say where it is blind is a log that has to be
believed rather than checked.

## Verifying it

The bundle and the disclosure are checked in. Verifying them needs the
`depose-verify` binary and nothing else, no Node, no DEPOSE install, no
network:

```sh
depose-verify verify examples/kiro-cost-explorer/bundle
depose-verify verify examples/kiro-cost-explorer/disclosure
```

The repository README has the full clean-machine walkthrough, including
where to get the binary and what each line of the output means.

## Rebuilding it

```sh
./produce.sh                      # signed; needs the network for the TSA
DEPOSE_DEV_UNSIGNED=1 ./produce.sh  # unsigned, offline
```

`produce.sh` does three things:

1. `capture.mjs` drives the real PreToolUse and PostToolUse handlers over
   the session, writing capture records into `captures/`. The workspace
   is `/tmp/depose-kiro-workspace`, a fixed path so the recorded file
   paths do not carry whoever ran it.
2. `depose record` merges those records with `session.synthetic.jsonl`,
   applies the destructive ruleset, chains and seals the result, and
   anchors it to a timestamp authority.
3. `depose disclose` produces the subset a regulator would receive:
   every event, with the command lines opened and the prompts, tool
   outputs, and captured environment left as salted commitments.

Rebuilding produces a different bundle id and a different signature (the
key and the timestamp are new), so the checked-in bundle is the one the
walkthrough verifies.

## Files

| File | What it is |
|---|---|
| `session.synthetic.jsonl` | The agent transcript, in Claude Code's format |
| `capture.mjs` | Drives both hook halves over that session |
| `produce.sh` | Capture, seal, disclose |
| `bundle/` | The sealed, signed, timestamped bundle |
| `disclosure/` | What a regulator receives: every event proven, most fields still committed |

## What this example is not

It is not a claim about what Amazon's systems recorded, or about what
Kiro did. It is a reconstruction of the incident's shape, built to show
what a bundle would contain if this capture layer had been installed. The
compliance mapping in `docs/compliance-mapping.md` says which regulatory
sentence each part of that bundle answers, and where it stops.
