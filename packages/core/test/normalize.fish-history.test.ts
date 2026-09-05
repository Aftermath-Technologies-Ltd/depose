// packages/core/test/normalize.fish-history.test.ts
//
// fish keeps history in a format that looks like YAML and is not: values
// are escaped rather than quoted. These tests pin the two places that
// costs a naive parser a command, the multi-line entry and the literal
// backslash, plus the case where fish recorded no time at all.

import { describe, it, expect } from 'vitest';
import {
  parseFishHistory,
  parseShellHistory,
  looksLikeFishHistory,
  unescapeFishValue,
} from '../src/normalize/shell-history.js';

const SAMPLE = [
  '- cmd: terraform destroy -auto-approve',
  '  when: 1747583400',
  '- cmd: git commit -m "wip"',
  '  when: 1747583460',
  '  paths:',
  '    - src/main.tf',
  '- cmd: echo one\\ntwo',
  '  when: 1747583520',
  '- cmd: grep -r "\\\\d+" .',
  '  when: 1747583580',
  '- cmd: ls',
  '',
].join('\n');

describe('looksLikeFishHistory', () => {
  it('recognizes a fish history file by its entry marker', () => {
    expect(looksLikeFishHistory(SAMPLE)).toBe(true);
  });

  it('does not mistake bash history for it', () => {
    expect(looksLikeFishHistory('#1747583400\nterraform destroy\n')).toBe(false);
    expect(looksLikeFishHistory('ls -la\ncd /tmp\n')).toBe(false);
  });
});

describe('parseFishHistory', () => {
  const parsed = parseFishHistory(SAMPLE);

  it('reads every entry, including the one with no timestamp', () => {
    expect(parsed.map((c) => c.command)).toEqual([
      'terraform destroy -auto-approve',
      'git commit -m "wip"',
      'echo one\ntwo',
      'grep -r "\\d+" .',
      'ls',
    ]);
  });

  it('converts the Unix time in when: to ISO 8601', () => {
    expect(parsed[0]!.timestamp).toBe('2025-05-18T15:50:00.000Z');
    expect(parsed[1]!.timestamp).toBe('2025-05-18T15:51:00.000Z');
  });

  it('leaves an undated entry undated rather than inventing a time', () => {
    expect(parsed[4]!.timestamp).toBeNull();
  });

  it('tokenizes argv so rule matching has token boundaries', () => {
    expect(parsed[0]!.argv).toEqual(['terraform', 'destroy', '-auto-approve']);
    expect(parsed[1]!.argv).toEqual(['git', 'commit', '-m', 'wip']);
  });

  it('skips the paths: list, which is not a command', () => {
    expect(parsed.some((c) => c.command.includes('src/main.tf'))).toBe(false);
  });

  it('records nothing it did not observe', () => {
    for (const command of parsed) {
      expect(command.cwd).toBeNull();
      expect(command.exitCode).toBeNull();
      expect(command.durationMs).toBeNull();
    }
  });

  it('returns nothing for an empty file rather than one empty command', () => {
    expect(parseFishHistory('')).toEqual([]);
    expect(parseFishHistory('\n\n')).toEqual([]);
  });
});

describe('unescapeFishValue', () => {
  it('turns an escaped newline into a newline', () => {
    expect(unescapeFishValue('echo one\\ntwo')).toBe('echo one\ntwo');
  });

  it('turns a doubled backslash into one', () => {
    expect(unescapeFishValue('grep "\\\\d+"')).toBe('grep "\\d+"');
  });

  it('leaves any other backslash alone, because fish does', () => {
    expect(unescapeFishValue('echo \\t')).toBe('echo \\t');
  });

  it('leaves a trailing backslash alone', () => {
    expect(unescapeFishValue('echo \\')).toBe('echo \\');
  });
});

describe('parseShellHistory dispatch', () => {
  it('routes a fish file to the fish parser', () => {
    expect(parseShellHistory(SAMPLE)).toHaveLength(5);
  });

  it('still routes a bash file to the bash parser', () => {
    const parsed = parseShellHistory('#1747583400\nterraform destroy\n');
    expect(parsed).toHaveLength(1);
    expect(parsed[0]!.command).toBe('terraform destroy');
  });
});
