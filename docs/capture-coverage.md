# Capture Coverage Matrix

> Honest accounting of what DEPOSE captures and what it does not.
> Updated for Phase 4 (narrative + full verification pipeline).

## Field coverage: Claude Code sessions

| Field | Claude Code JSONL (passive) | DEPOSE PreToolUse Hook (active) | DEPOSE Shell Shim (active) | Why it matters |
|---|---|---|---|---|
| Command string | Yes | Yes | Yes | What was executed |
| argv (tokenized) | No* | Yes | Yes | Preserves token boundaries for rule matching |
| Current working directory | Partial† | Yes | Yes | Which project/files were affected |
| Full env (hash) | No | Yes | Yes | Tamper-evidence: detect env changes |
| Env subset (allowlisted) | No | Yes | Yes | Prove cloud credentials were present |
| Parent PID tree | No | Yes | Yes | Prove the command came from the agent, not user |
| Pre-exec file SHA-256 | No | Yes | Partial‡ | Prove file state before modification |
| Pre-exec file size | No | Yes | Partial‡ | Prove file existed and had known size |
| TTY identifier | No | Yes | Yes | Prove command ran in a terminal context |
| User/hostname | No | Yes | Yes | Who ran the command and where |
| stdin content (tee) | No | No | Yes§ | Capture GraphQL payloads in `gh api` calls |
| Exit code | Partial¶ | No | No‖ | Whether command succeeded (from JSONL result) |
| Duration | No | No | No‖ | How long the command ran |
| Source attribution | No | Yes | Yes | Prove capture origin (hook vs shim) |

\* Claude Code JSONL includes `command` as a string but does not preserve argv token boundaries (e.g., quoted args may be merged).

† Claude Code JSONL sometimes includes `cwd` in tool result metadata, but not reliably in the pre-execution record.

‡ Shell shim only hashes files that appear as command-line arguments matching existing paths. It does not parse tool-specific file_path fields.

§ Shell shim tees stdin to a temp file (default: <1 MB) for commands like `gh api graphql` where the destructive operation is in the stdin payload. Over-threshold stdin is hash-only.

‖ Exit code and duration are captured in the JSONL `tool_result` event (passive). The shim does not capture these because it `exec`s the real binary transparently.

## Source coverage matrix

| Source | Captures pre-execution? | Captures post-execution? | Gaps visible? |
|---|---|---|---|
| Claude Code PreToolUse hook | Yes (Bash, Edit, Write) | No (from JSONL) | Yes, gap events emitted |
| Shell shim | Yes (PATH-intercepted) | No | Yes, gap events for absolute paths |
| Claude Code JSONL (passive) | Partial (tool_result only) | Yes | Yes, gap events for missing pre-capture |
| Shell history (passive) | Partial | Partial | Yes, gap events for uncorrelated commands |
| Git reflog (passive) | Indirect | Indirect | Yes, gap events for reflog changes w/o command |

## What the hook does NOT catch

The Claude Code PreToolUse hook only fires for tools that Claude Code explicitly invokes. It does NOT fire for:

1. **Direct shell commands**, Commands the user types in their terminal outside Claude Code.
2. **Subprocess calls**, Python `subprocess.run()`, Node `child_process.exec()` called from within the agent's code execution (not via the Bash tool).
3. **Cursor/other agent tools**, The hook is specific to Claude Code's PreToolUse event. Other editors/agents need their own integration.

## What the shim does NOT catch

Per BUILD_PLAN.md §6 (Phase 3), the shell shim is best-effort:

1. **Absolute paths**, `/usr/bin/terraform destroy` bypasses the shim's PATH interception.
2. **Tool aliases**, `tofu destroy` instead of `terraform destroy` (unless user adds `tofu` to the shim allowlist).
3. **Subprocess calls with `shell=False`**, Python/Node calls that use `execve` directly, bypassing PATH.
4. **Statically-linked tools**, Direct `execve` to a binary path.
5. **Commands run on remote hosts**, SSH sessions, Docker containers, etc.

**The gap events make these limitations visible rather than hidden.** When a tool result appears in the JSONL but no matching pre-execution capture exists, a `gap` event is emitted with reason `tool_result_without_pre_capture`. This is by design: a visible gap is more valuable than silently smoothed-over reconstruction.

## Coverage improvement: Phase 1 vs Phase 3

| Capability | Phase 1 (passive only) | Phase 3 (active capture) |
|---|---|---|
| Pre-execution argv tokens | No | Yes |
| Pre-execution env hash | No | Yes |
| Pre-execution env subset | No | Yes |
| Pre-execution file hashes | No | Yes |
| Source attribution (hook/shim) | No | Yes |
| Gap visibility | Yes (basic) | Yes (enhanced: linkedShellCommandPreId) |
| Cross-correlation with captures | No | Yes |

Phase 3's active capture layer is the **unique-value layer** of DEPOSE. It transforms the bundle from "inferred reconstruction" to "captured evidence."

## Tuning capture behavior at runtime

Two environment variables let the producer adjust capture behavior
without rebuilding:

| Variable | What it does | Default |
|---|---|---|
| `DEPOSE_CAPTURE_DIR` | Directory where the hook and shim write capture records. Read by both producer-side TS and the Go shim. | `~/.depose/captures` |
| `DEPOSE_ENV_ALLOWLIST` | Comma-separated extra env-variable prefixes captured into `envSubset` beyond the built-in defaults (`AWS_`, `GH_`, `OPENAI_`, `ANTHROPIC_`, `RAILWAY_`). Example: `DEPOSE_ENV_ALLOWLIST=DD_,DOPPLER_`. | (none) |
| `DEPOSE_CAPTURE_SECRET_VALUES` | Set to `1` to store secret-named env values in plaintext. The default redacts any value whose key matches `SECRET|TOKEN|KEY|PASSWORD|CREDENTIALS` to `sha256:<hex>`. Enable only for debugging in a trusted local environment; the bundle is then unsafe to share. | `0` (redacted) |

The shim's built-in allowlist (the binary names it intercepts via
PATH) is fixed at build time. To intercept additional commands,
add a symlink to `depose-shim` under the desired name (see
`docs/shim-installation.md`).

## What a gap event looks like

When a `tool_result` lands without a matching pre-execution capture,
the merger emits an event of `type: gap` with one of:

- `tool_result_without_pre_capture`, saw an after but no before.
- `pre_capture_without_tool_result`, saw a before but no after.
- `shell_history_without_jsonl_correlation`, shell-history entry
  that doesn't correlate to anything in the Claude Code session.
- `reflog_change_without_command`, git reflog change with no
  observed command.

The verifier replays the chain, including gap events, exactly as the
producer wrote them. A bundle whose `counts.gaps` is zero is a
bundle where every observable action could be cross-correlated. A
bundle with gaps is more honest than a bundle that hides them.