// packages/core/test/reconstruct.shell-split.test.ts
//
// The shell splitter and wrapper stripper feed destructive-rule matching.
// Every evasion shape here was a silent miss on the hook path before
// this module existed: the hook records ['bash', '-c', cmd] and argvHead
// rules matched a strict argv prefix, so no rule could ever fire.

import { describe, it, expect } from 'vitest';
import { splitShellCommand, expandArgv, expandCommandString } from '../src/index.js';

const argvs = (cmd: string) => expandCommandString(cmd).map((c) => c.argv);

describe('splitShellCommand', () => {
  it('splits on &&, ||, ;, |, & and newlines', () => {
    expect(splitShellCommand('a && b || c; d | e & f\ng').map((c) => c.argv)).toEqual([
      ['a'], ['b'], ['c'], ['d'], ['e'], ['f'], ['g'],
    ]);
  });

  it('keeps quoted separators inside a single word', () => {
    expect(splitShellCommand(`psql -c "DROP TABLE users; DROP TABLE orders"`).map((c) => c.argv)).toEqual([
      ['psql', '-c', 'DROP TABLE users; DROP TABLE orders'],
    ]);
  });

  it('honours single quotes, double quotes, and backslash escapes', () => {
    expect(splitShellCommand(`echo 'a b' "c d" e\\ f`).map((c) => c.argv)).toEqual([
      ['echo', 'a b', 'c d', 'e f'],
    ]);
  });

  it('recurses into subshells and command substitutions in source order', () => {
    const commands = splitShellCommand('(cd /prod && rm -rf .) && echo $(terraform destroy -auto-approve) `ls`');
    expect(commands.map((c) => [c.origin, ...c.argv])).toEqual([
      ['subshell', 'cd', '/prod'],
      ['subshell', 'rm', '-rf', '.'],
      ['substitution', 'terraform', 'destroy', '-auto-approve'],
      ['substitution', 'ls'],
      ['top', 'echo', '$(terraform destroy -auto-approve)', '`ls`'],
    ]);
  });

  it('drops redirections and their targets from argv', () => {
    expect(splitShellCommand('rm -rf /data > /dev/null 2>&1').map((c) => c.argv)).toEqual([
      ['rm', '-rf', '/data'],
    ]);
  });

  it('skips heredoc bodies so their text is not parsed as commands', () => {
    const cmd = "cat > notes.txt <<'EOF'\nrm -rf /never-run\nEOF\necho done";
    expect(splitShellCommand(cmd).map((c) => c.argv)).toEqual([
      ['cat'],
      ['echo', 'done'],
    ]);
  });

  it('ignores comments and brace-group punctuation', () => {
    expect(splitShellCommand('{ rm -rf /x; } # rm -rf /y').map((c) => c.argv)).toEqual([
      ['rm', '-rf', '/x'],
    ]);
  });

  it('returns nothing for an empty or whitespace-only command', () => {
    expect(splitShellCommand('')).toEqual([]);
    expect(splitShellCommand('  \n\t')).toEqual([]);
  });
});

describe('expandArgv and expandCommandString', () => {
  it('expands the hook argv shape ["bash", "-c", cmd] into the inner commands', () => {
    const commands = expandArgv(['bash', '-c', 'du -sh /data && rm -rf /data/training']);
    expect(commands.map((c) => c.argv)).toEqual([['du', '-sh', '/data'], ['rm', '-rf', '/data/training']]);
    expect(commands.map((c) => c.index)).toEqual([0, 1]);
    expect(commands[1]!.wrappers).toEqual(['bash']);
  });

  it('strips sudo and its flags', () => {
    expect(argvs('sudo rm -rf /data/training')).toEqual([['rm', '-rf', '/data/training']]);
    expect(argvs('sudo -u postgres -n rm -rf /var/lib/pg')).toEqual([['rm', '-rf', '/var/lib/pg']]);
  });

  it('strips env with its assignments and flags', () => {
    expect(argvs('env X=1 terraform destroy -auto-approve')).toEqual([['terraform', 'destroy', '-auto-approve']]);
    expect(argvs('env -i -u HOME AWS_PROFILE=prod aws s3 rb s3://bucket')).toEqual([['aws', 's3', 'rb', 's3://bucket']]);
  });

  it('exposes every command in a cd && rm chain', () => {
    const commands = expandCommandString('cd /prod && rm -rf .');
    expect(commands.map((c) => c.argv)).toEqual([['cd', '/prod'], ['rm', '-rf', '.']]);
    expect(commands[1]!.index).toBe(1);
  });

  it('strips nice, time, nohup, command, exec, timeout, and xargs', () => {
    expect(argvs('nice -n 10 rm -rf /x')).toEqual([['rm', '-rf', '/x']]);
    expect(argvs('time terraform destroy')).toEqual([['terraform', 'destroy']]);
    expect(argvs('nohup kubectl delete ns prod')).toEqual([['kubectl', 'delete', 'ns', 'prod']]);
    expect(argvs('command rm -rf /x')).toEqual([['rm', '-rf', '/x']]);
    expect(argvs('exec rm -rf /x')).toEqual([['rm', '-rf', '/x']]);
    expect(argvs('timeout -s KILL 30 rm -rf /x')).toEqual([['rm', '-rf', '/x']]);
    expect(argvs('find . -name "*.log" | xargs -0 rm -rf')).toEqual([['find', '.', '-name', '*.log'], ['rm', '-rf']]);
  });

  it('does not strip command -v, which only looks a binary up', () => {
    expect(argvs('command -v rm')).toEqual([['command', '-v', 'rm']]);
  });

  it('strips leading VAR=value assignments and records them as wrappers', () => {
    const commands = expandCommandString('AWS_PROFILE=prod TF_VAR_x=1 terraform destroy');
    expect(commands[0]!.argv).toEqual(['terraform', 'destroy']);
    expect(commands[0]!.wrappers).toEqual(['AWS_PROFILE=', 'TF_VAR_x=']);
  });

  it('recurses through nested wrappers and shell -c strings', () => {
    const commands = expandCommandString(`sudo bash -c "env X=1 terraform destroy -auto-approve"`);
    expect(commands.map((c) => c.argv)).toEqual([['terraform', 'destroy', '-auto-approve']]);
    expect(commands[0]!.wrappers).toEqual(['sudo', 'bash', 'env', 'X=']);
    expect(argvs('/bin/sh -lc "rm -rf /x; echo ok"')).toEqual([['rm', '-rf', '/x'], ['echo', 'ok']]);
  });

  it('leaves a shell invoked on a script file alone', () => {
    expect(argvs('bash deploy.sh --force')).toEqual([['bash', 'deploy.sh', '--force']]);
  });

  it('keeps the raw argv alongside the stripped one', () => {
    const [cmd] = expandArgv(['sudo', 'rm', '-rf', '/x']);
    expect(cmd!.rawArgv).toEqual(['sudo', 'rm', '-rf', '/x']);
    expect(cmd!.argv).toEqual(['rm', '-rf', '/x']);
  });
});
