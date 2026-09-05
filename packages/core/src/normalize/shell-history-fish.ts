// packages/core/src/normalize/shell-history-fish.ts
//
// fish keeps its history in ~/.local/share/fish/fish_history, in a format
// that looks like YAML and is not: values are escaped rather than quoted,
// so a YAML reader either mangles a command containing a newline or
// refuses the file. It is parsed line by line instead.

import type { ShellHistoryCommand } from './shell-history.js';
import { tokenize } from './shell-tokenize.js';

/**
 * Parse fish shell history (~/.local/share/fish/fish_history).
 *
 * The format is YAML-ish rather than YAML: an entry is a `- cmd:` line,
 * an optional `  when:` line holding a Unix timestamp, and an optional
 * `  paths:` list. It is parsed line by line rather than with a YAML
 * reader because fish does not quote or fold its values, it escapes them:
 * a newline in a command is written `\n` and a backslash `\\`, which a
 * YAML parser would read as literal characters or reject outright.
 *
 * An entry with no `when:` keeps a null timestamp rather than being
 * given the file's mtime or the current time. A history line that cannot
 * be dated is still evidence of a command; a fabricated time is not.
 *
 * @param content - The fish_history file contents.
 * @returns One entry per command, in file order.
 */
export function parseFishHistory(content: string): ShellHistoryCommand[] {
  const commands: ShellHistoryCommand[] = [];
  let current: { command: string; when: number | null } | null = null;

  const flush = (): void => {
    if (!current) return;
    const command = current.command;
    if (command.length > 0) {
      commands.push({
        timestamp: current.when === null ? null : new Date(current.when * 1000).toISOString(),
        command,
        argv: tokenize(command)[0] ?? [],
        cwd: null,
        exitCode: null,
        durationMs: null,
      });
    }
    current = null;
  };

  for (const raw of content.split('\n')) {
    const entry = raw.match(/^- cmd:\s?(.*)$/);
    if (entry) {
      flush();
      current = { command: unescapeFishValue(entry[1] ?? ''), when: null };
      continue;
    }
    const when = raw.match(/^\s+when:\s*(\d+)\s*$/);
    if (when && current) {
      current.when = Number(when[1]);
      continue;
    }
    // `paths:` and its list entries describe files the command touched.
    // They are not commands and fish does not record them reliably, so
    // they are skipped rather than turned into fileArgs that would look
    // like captured pre-state hashes.
  }
  flush();
  return commands;
}

/**
 * Undo fish's history escaping: `\\n` is a newline and `\\\\` a backslash.
 *
 * @param value - The raw text after `- cmd: `.
 * @returns The command as the user typed it.
 */
export function unescapeFishValue(value: string): string {
  let out = '';
  for (let i = 0; i < value.length; i++) {
    if (value[i] !== '\\' || i === value.length - 1) {
      out += value[i];
      continue;
    }
    const next = value[i + 1];
    if (next === 'n') {
      out += '\n';
      i++;
    } else if (next === '\\') {
      out += '\\';
      i++;
    } else {
      out += value[i];
    }
  }
  return out;
}
