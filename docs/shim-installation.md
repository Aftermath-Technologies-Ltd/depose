# Shim Installation Guide

## Shell Shim for Destructive Binaries

The DEPOSE shell shim intercepts destructive commands before they execute, captures pre-execution data, then transparently passes through to the real binary with full stdio/signal passthrough.

### Installation

```bash
depose install --shell
```

This command:

1. Creates `~/.depose/bin` (or custom directory with `--bin-dir`)
2. Copies the `depose-shim` binary
3. Creates symlinks for: terraform, aws, gh, kubectl, psql, gcloud, railway, rm
4. Creates the capture directory at `~/.depose/captures` (mode 0700)
5. Prints the PATH instruction you need to add to your shell profile

### Required PATH setup

After installation, add the shim directory to the **beginning** of your PATH:

```bash
# Add to ~/.bashrc, ~/.zshrc, or equivalent:
export PATH="$HOME/.depose/bin:$PATH"
```

The shim directory must come **before** the real binary locations so that `which terraform` resolves to the shim, not the real binary.

### What the shim captures

For every intercepted command:

- Full argv (tokenized)
- Current working directory
- SHA-256 hash of the full process environment
- Allowlisted environment variables
- Parent process tree
- TTY identifier
- User and hostname
- stdin content (tee'd to temp file if <1 MB, for `gh api graphql` cases)
- Source attribution (shell-shim)

### Transparent passthrough

The shim uses `syscall.Exec` on Unix to replace its own process with the real binary. This means:

- Exit codes are preserved exactly
- Signals (Ctrl-C, SIGTERM, etc.) propagate cleanly
- stdin/stdout/stderr pass through without modification
- No measurable performance overhead (single `exec` syscall)

### Self-loop protection

If the shim detects that the resolved "real binary" is itself (infinite loop), it aborts with exit code 126 and a clear error message. This prevents PATH misconfiguration from causing infinite recursion.

### Uninstall

```bash
depose uninstall --shell
```

### Custom binary list

The default shim allowlist is: terraform, aws, gh, kubectl, psql, gcloud, railway, rm.

To add a binary that isn't on the default list (e.g. `tofu` for
OpenTofu, `nomad`, `helm`, `flyctl`, custom internal tools), add a
symlink to `depose-shim` under the same name:

```bash
ln -s "$HOME/.depose/bin/depose-shim" "$HOME/.depose/bin/tofu"
```

After adding the symlink, confirm that `which tofu` resolves to the
shim path. If it resolves to a real binary instead, your PATH is not
ordered with `~/.depose/bin` first; fix that before relying on the
new shim.

To remove a custom binary, delete the symlink:

```bash
rm "$HOME/.depose/bin/tofu"
```

The shim distinguishes itself from any wrapped binary by name: it
refuses to exec back into anything called `depose-shim`. If you
ever see `FATAL: resolved real binary is the shim itself`, it means
two PATH entries both expose the shim under the same name; clean up
the duplicate.

### What the shim does NOT catch

(See docs/capture-coverage.md for the full matrix.)

1. Absolute paths: `/usr/bin/terraform destroy`
2. Tool aliases not in the allowlist
3. Subprocess calls with `shell=False` from Python/Node
4. Statically-linked tools called via `execve` directly
5. Commands run on remote hosts (SSH, Docker)

These limitations are **visible** — a `gap` event is emitted whenever a tool result has no matching pre-execution capture.