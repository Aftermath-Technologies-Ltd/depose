# Hook Installation Guide

## Claude Code capture hooks

DEPOSE registers two hooks, one on each side of every Bash, Edit, and Write tool call. The PreToolUse hook records what the agent was about to do; the PostToolUse hook records what happened. Together they turn a Claude Code session into a forensically verifiable evidence bundle.

Install both or neither. A bundle built with only the pre half reports every tool call as an `intent_without_effect` gap, because from the evidence's point of view that is exactly what it is.

### Installation

```bash
depose install --claude
```

This command:

1. Adds a `PreToolUse` and a `PostToolUse` hook to `~/.claude/settings.json` (or project `.claude/settings.json` with `--project`)
2. Creates a backup of your existing settings at `.claude/settings.json.depose-backup-<timestamp>`
3. Creates the capture directory at `~/.depose/captures` (mode 0700)

### What the hooks capture

PreToolUse, before every Bash, Edit, or Write tool invocation:

- Full argv (tokenized command arguments)
- Current working directory
- SHA-256 hash of the full process environment
- Allowlisted environment variables (AWS_*, GH_*, OPENAI_*, ANTHROPIC_*, RAILWAY_*)
- Parent process tree (proof the command came from the agent)
- SHA-256 of file-path arguments referenced in tool input
- TTY identifier
- User and hostname
- Source attribution (claude-pretooluse)

PostToolUse, after the same call returns:

- Exit status, when the tool reports one
- How long the call took
- SHA-256 of the same file-path arguments, now classified `created`, `modified`, `deleted`, or `unchanged`
- The event id of the intent it closes, inside the signed payload
- Source attribution (claude-posttooluse)

The post half re-hashes the paths the tool input named, which are the only ones either hook knows about. A file a command created without naming it does not appear; on Linux the optional eBPF collector covers the commands that ran, and `docs/capture-coverage.md` states the limit rather than working around it.

### Privacy

Both hooks are **observation-only**; neither denies or modifies a tool call, and both exit 0 whatever happens. A hook that throws writes a `capture_failed` record naming the phase before it exits, so a lost capture shows up as a gap rather than as a clean timeline.

- Capture is **opt-in per project**, never global
- Environment capture uses a strict allowlist (extendable via `$DEPOSE_ENV_ALLOWLIST`)
- Full env is hashed (not stored) for tamper-evidence
- File content capture defaults to hash-only

### Uninstall

```bash
depose uninstall --claude
```

### Custom capture directory

```bash
depose install --claude --capture-dir /path/to/captures
# or
export DEPOSE_CAPTURE_DIR=/path/to/captures
```

### Hook contract

The hook is registered in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write",
        "hooks": [
          { "type": "command", "command": "depose-hook pretooluse" }
        ]
      }
    ]
  }
}
```

The `depose-hook` wrapper reads the hook JSON from stdin, processes it, writes a capture record, and exits 0. It never blocks the tool call.