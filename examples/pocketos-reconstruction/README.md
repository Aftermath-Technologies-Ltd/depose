# pocketos-reconstruction

Synthetic example: Claude Code session running `terraform destroy -auto-approve` on a PocketOS infrastructure stack.

## What this demonstrates

- A Claude Code agent executing a **destructive operation** (`terraform destroy`)
- Full `depose record` signed bundle production from the JSONL session transcript
- Hash chain, Ed25519 signature, and RFC 3161 timestamping of the destructive event

## Files

| File | Description |
|---|---|
| `session.synthetic.jsonl` | Simulated Claude Code JSONL session where the agent runs `terraform destroy -auto-approve` |
| `produce.sh` | Executable script that runs `depose record --from-claude` on the JSONL |

## Usage

```sh
./produce.sh
```

This produces a `.depo` signed bundle in `./depose-output/` containing the reconstructed and signed destructive event chain.

## Session narrative

1. User asks the agent to tear down the PocketOS staging environment
2. Agent runs `terraform plan -destroy` to preview changes
3. Agent runs `terraform destroy -auto-approve` — the destructive operation
4. Terraform reports 3 resources destroyed (SNS topic, DynamoDB table, EC2 instance)
5. Agent confirms completion to the user