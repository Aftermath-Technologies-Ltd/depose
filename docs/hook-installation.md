# Hook Installation Guide

## Claude Code PreToolUse Hook

The DEPOSE Claude Code hook captures pre-execution data for every Bash, Edit, and Write tool call. This turns your Claude Code sessions into forensically verifiable evidence bundles.

### Installation

```bash
depose install --claude
```

This command:

1. Adds a `PreToolUse` hook to `~/.claude/settings.json` (or project `.claude/settings.json` with `--project`)
2. Creates a backup of your existing settings at `.claude/settings.json.depose-backup-<timestamp>`
3. Creates the capture directory at `~/.depose/captures` (mode 0700)

### What the hook captures

For every Bash, Edit, or Write tool invocation:

- Full argv (tokenized command arguments)
- Current working directory
- SHA-256 hash of the full process environment
- Allowlisted environment variables (AWS_*, GH_*, OPENAI_*, ANTHROPIC_*, RAILWAY_*)
- Parent process tree (proof the command came from the agent)
- SHA-256 of file-path arguments referenced in tool input
- TTY identifier
- User and hostname
- Source attribution (claude-pretooluse)

### Privacy

The hook is **observation-only**; it never denies or modifies a tool call.

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