# Capture Coverage Matrix

> Honest accounting of what DEPOSE captures and what it does not.

## Field coverage: Claude Code sessions

| Field | Claude Code JSONL (passive) | DEPOSE hooks (active) | DEPOSE Shell Shim (active) | Why it matters |
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
| Post-exec file SHA-256 | No | Yes (PostToolUse) | No | Prove what the call actually changed, not just what it was told to |
| Exit code | Partial¶ | Yes (PostToolUse) | No‖ | Whether the command succeeded, bound to the intent that started it |
| Duration | No | Yes (PostToolUse) | No‖ | How long the command ran |
| Source attribution | No | Yes | Yes | Prove capture origin (hook vs shim vs kernel) |

\* Claude Code JSONL includes `command` as a string but does not preserve argv token boundaries (e.g., quoted args may be merged).

† Claude Code JSONL sometimes includes `cwd` in tool result metadata, but not reliably in the pre-execution record.

‡ Shell shim only hashes files that appear as command-line arguments matching existing paths. It does not parse tool-specific file_path fields.

§ Shell shim tees stdin to a temp file (default: <1 MB) for commands like `gh api graphql` where the destructive operation is in the stdin payload. Over-threshold stdin is hash-only.

‖ The shim captures neither, because it `exec`s the real binary transparently. The PostToolUse hook records both, and the session log carries the exit code too. See `docs/bundle-format.md#intent-and-effect`.

## Agent sources

| Agent | Session log | Reconstructed by |
|---|---|---|
| Claude Code | the session JSONL | `depose record --from-claude <path>` |
| OpenAI Codex CLI | `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-*.jsonl` | `depose record --from-codex <path>` |

Codex has two rollout grammars in the wild; the normalizer detects which
one it read and records it in `manifest.session.sourceFormat`. See
`docs/bundle-format.md#agent-sources` for the per-item mapping and what
it deliberately leaves out.

Active capture is Claude Code only. The Codex path is passive
reconstruction: it recovers what the rollout recorded, which is the
command and its output, and nothing about the environment it ran in.

## Shell history

| Shell | File | Timestamps |
|---|---|---|
| bash | `~/.bash_history` | only with `HISTTIMEFORMAT`, as a `#<epoch>` line above each command |
| zsh | `~/.zsh_history` | with `EXTENDED_HISTORY`, as `: <epoch>:<elapsed>;<command>` |
| fish | `~/.local/share/fish/fish_history` | always, as a `when:` line |

`parseShellHistory` picks the parser from the file's own shape: a
`- cmd:` line at the start of a line is fish's entry marker and appears
in neither of the others.

An entry with no recorded time keeps a null timestamp. History files
also record no working directory, so `cwd` is null for every entry from
every shell. Filling either from the producer's own process would put an
unobserved value into signed evidence.

## Source coverage matrix

| Source | Captures pre-execution? | Captures post-execution? | Gaps visible? |
|---|---|---|---|
| Claude Code PreToolUse hook | Yes (Bash, Edit, Write) | No | Yes, gap events emitted |
| Claude Code PostToolUse hook | No | Yes (exit status, post-state hashes) | Yes, `intent_without_effect` and `effect_without_intent` |
| eBPF execve collector (Linux) | Yes (every exec in the agent's tree) | No | Yes, `kernel_execve_without_hook` |
| Shell shim | Yes (PATH-intercepted) | No | Yes, gap events for absolute paths |
| Claude Code JSONL (passive) | Partial (tool_result only) | Yes | Yes, gap events for missing pre-capture |
| Shell history (passive) | Partial | Partial | Yes, gap events for uncorrelated commands |
| Git reflog (passive) | Indirect | Indirect | Yes, gap events for reflog changes w/o command |

## Kernel-witnessed execve

`depose-collect-execve` (`apps/collect-execve/`) is an optional Linux
collector that attaches an eBPF program to the
`sched:sched_process_exec` tracepoint and records every exec inside the
agent's process tree. It is the answer to the first, third, and fourth
entries under "What the shim does NOT catch": the kernel sees an execve
however the binary was reached.

```
depose-collect-execve --session <id> --pid <agent pid> [--capture-dir <dir>] [--duration 30m]
```

**Requires `CAP_BPF` and `CAP_PERFMON`, or root.** Without them it
writes a `capture_failed` record with phase `ebpf-attach` and exits 0,
so the bundle says kernel witnessing was requested and did not happen
rather than looking like a session where nothing ran outside the hook.

**macOS: not supported, hook only.** There is no equivalent surface
DEPOSE can use. Apple's Endpoint Security framework needs an
entitlement granted per developer account, and the older openbsm audit
pipeline is deprecated and disabled by default. The collector refuses to
start on macOS rather than shipping something that loads and records
nothing. macOS sessions are captured through the Claude Code hooks and
the shell shim only.

### What it costs

The probe writes 32 bytes per exec (pid, monotonic nanoseconds, comm)
into a ring buffer and reads nothing from the tracepoint context.
Everything else is read from `/proc` in userspace. Measured on an Intel
Core Ultra 7 155H, Linux 7.0, Go 1.24.4 (`go test ./collector/ -bench .`):

| Path | Cost per exec |
|---|---|
| Exec outside the agent's process tree (one ancestry walk, no write) | 8.0 µs |
| Exec recorded (ancestry walk, `/proc` reads, JSON record written) | 31.9 µs |

That is the userspace half. A build that execs 10,000 times with the
collector attached costs about 0.08 s of collector CPU if none of it is
in the agent's tree, 0.32 s if all of it is.

**Not measured here:** the kernel-side cost of the tracepoint and the
ring buffer, because loading a BPF program needs `CAP_BPF` and the
development host has no such privilege. Published figures for a
tracepoint of this shape are in the low hundreds of nanoseconds per
exec; DEPOSE does not repeat them as its own measurement. To measure it
on your own machine, run the collector against a shell loop that execs a
trivial binary and compare wall-clock time with the collector attached
and detached.

### What it still misses

- Syscalls that are not execs. A command that truncates a file without
  spawning a process is invisible to it.
- Work the agent delegates to an already-running daemon, which is not in
  its process tree.
- argv and cwd for a process that exits before `/proc` can be read. The
  record is still written, with an empty `argv`, because an exec that
  was witnessed and not characterized is itself a finding.

## Hook latency

Measured on the same machine over 300 in-process invocations per case,
after the process-tree cache is warm:

| Hook | Median | p95 |
|---|---|---|
| PreToolUse, Bash | 0.23 ms | 0.58 ms |
| PostToolUse, Bash | 0.03 ms | 0.05 ms |
| PreToolUse, Edit (hashes the file) | 0.24 ms | 0.59 ms |
| PostToolUse, Edit (hashes the file) | 0.05 ms | 0.14 ms |

Claude Code runs each hook as its own process, so what a user feels is
dominated by Node startup rather than by the handler: 180 ms median for
`depose-hook pretooluse` and 60 ms for `depose-hook posttooluse` over 30
full invocations. The difference between the two is the pre hook's
process-tree walk, which shells out to `ps`.

## What the hook does NOT catch

The Claude Code PreToolUse hook only fires for tools that Claude Code explicitly invokes. It does NOT fire for:

1. **Direct shell commands**, Commands the user types in their terminal outside Claude Code.
2. **Subprocess calls**, Python `subprocess.run()`, Node `child_process.exec()` called from within the agent's code execution (not via the Bash tool).
3. **Cursor/other agent tools**, The hook is specific to Claude Code's PreToolUse and PostToolUse events. Other editors/agents need their own integration.
4. **Files a command created without naming them**, The PostToolUse hook re-hashes the paths the tool input declared, which are the only ones either half knows about.

## What the shim does NOT catch

The shell shim is best-effort:

1. **Absolute paths**, `/usr/bin/terraform destroy` bypasses the shim's PATH interception.
2. **Tool aliases**, `tofu destroy` instead of `terraform destroy` (unless user adds `tofu` to the shim allowlist).
3. **Subprocess calls with `shell=False`**, Python/Node calls that use `execve` directly, bypassing PATH.
4. **Statically-linked tools**, Direct `execve` to a binary path.
5. **Commands run on remote hosts**, SSH sessions, Docker containers, etc.

**The gap events make these limitations visible rather than hidden.** When a tool result appears in the JSONL but no matching pre-execution capture exists, a `gap` event is emitted with reason `tool_result_without_pre_capture`. This is by design: a visible gap is more valuable than silently smoothed-over reconstruction.

## What each capture layer adds

| Capability | Passive only | Pre-execution hook and shim | Intent and effect pair | Kernel collector |
|---|---|---|---|---|
| argv token boundaries | No | Yes | Yes | Yes |
| Environment hash and allowlisted subset | No | Yes | Yes | No |
| Pre-execution file hashes | No | Yes | Yes | No |
| Post-execution file hashes and exit status | From the session log | No | Yes | No |
| Signed binding between what was intended and what happened | No | No | Yes | No |
| Commands that never went through PATH | No | No | No | Yes |
| Source attribution | No | Yes | Yes | Yes |

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
- `capture_failed`, a collector threw before it could write a record.
  The hook writes a `capture_failed` record (or, if even that fails,
  a line in `capture-failed.log`) naming the phase and error; the
  merger turns it into this gap so a lost capture is disclosed.
- `intent_without_effect`, the PreToolUse hook recorded a call and no
  PostToolUse record closed it. The narrative gives these their own
  section ahead of the timeline.
- `effect_without_intent`, a post-execution record could not be
  matched to any intent in the bundle.
- `unwitnessed_file_change`, a path's hash moved between one call's
  recorded outcome and the next call's recorded pre-state.
- `kernel_execve_without_hook`, the eBPF collector saw an exec in the
  agent's process tree that no hook or shim recorded.

The last four are enforced, not advisory: `depose-verify` fails a bundle
that has the condition and not the gap.

The verifier replays the chain, including gap events, exactly as the
producer wrote them. A bundle whose `counts.gaps` is zero is a
bundle where every observable action could be cross-correlated. A
bundle with gaps is more honest than a bundle that hides them.