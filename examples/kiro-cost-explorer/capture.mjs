// examples/kiro-cost-explorer/capture.mjs
//
// Drives the real Claude Code hooks over the session in
// session.synthetic.jsonl, so the bundle this example produces carries
// captured intent and effect records rather than a reconstruction of
// them. This is the same code path `depose install --claude` wires into
// Claude Code; nothing here is a stand-in for it.
//
// The environment and the process tree are injected so the example
// produces the same evidence on any machine. Everything else is real:
// the files exist, the hashes are of their actual bytes, and the records
// land in a capture store the writer then reads.

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// A fixed absolute path rather than one under the checkout: the recorded
// file paths go into the bundle checked in beside this script, and they
// should not carry whoever ran it last.
const workDir = '/tmp/depose-kiro-workspace';
const captureDir = join(here, 'captures');
process.env.DEPOSE_CAPTURE_DIR = captureDir;

// Imported by path rather than by package name: this script is run from
// the example directory, which is outside the workspace's node_modules.
const { runHook, clearProcessTreeCache } = await import(
  join(here, '..', '..', 'packages', 'capture-claude', 'dist', 'index.js')
);
const { setFixedUlidSeed, clearFixedUlidSeed } = await import(
  join(here, '..', '..', 'packages', 'core', 'dist', 'index.js')
);

const SESSION = 'kiro-cost-explorer-cn-northwest-1';
const BASE_MS = Date.parse('2025-12-15T16:00:00.000Z');

// The engineer's own shell, which is what the agent inherited. The
// operator profile in the environment is the whole point of the
// incident: the approval gate was never reached because the credentials
// carried the role that skips it.
const ENV = {
  USER: 'eng-oncall',
  LOGNAME: 'eng-oncall',
  HOSTNAME: 'ce-build-04.cn-northwest-1',
  AWS_PROFILE: 'cost-explorer-operator',
  AWS_REGION: 'cn-northwest-1',
};
const PROCESS_TREE = [
  { pid: 8814, ppid: 8801, exe: 'node', argv0: 'node' },
  { pid: 8801, ppid: 8790, exe: 'kiro', argv0: 'kiro' },
  { pid: 8790, ppid: 1, exe: 'zsh', argv0: '-zsh' },
];

// Record ids derive from the same fixed clock as the record times. In a
// real session they agree because both come from the wall clock at
// capture; here the clock is injected, so the id seed has to be too, or
// the timeline would order the records by when this script ran rather
// than by when the incident did.
setFixedUlidSeed(BASE_MS);

let tick = 0;
const clock = () => new Date(BASE_MS + ++tick * 1000);

function deps(input) {
  return {
    readStdin: async () => JSON.stringify(input),
    env: () => ENV,
    walkProcessTree: () => PROCESS_TREE,
    resolveTty: () => '/dev/pts/2',
    now: clock,
  };
}

async function hook(half, toolName, toolInput, toolResponse) {
  const input = {
    tool_name: toolName,
    tool_input: toolInput,
    cwd: workDir,
    session_id: SESSION,
    ...(toolResponse ? { tool_response: toolResponse } : {}),
  };
  const outcome = await runHook(deps(input), half, {
    now: clock,
    monoNs: () => BigInt(tick) * 1_000_000n,
  });
  if (!outcome.ok) {
    throw new Error(`hook ${half} failed in ${outcome.phase}`);
  }
}

/** One tool call with both halves captured. */
async function call(toolName, toolInput, toolResponse, mutate) {
  await hook('pre', toolName, toolInput);
  if (mutate) mutate();
  await hook('post', toolName, toolInput, toolResponse);
}

rmSync(workDir, { recursive: true, force: true });
rmSync(captureDir, { recursive: true, force: true });
mkdirSync(join(workDir, 'infra', 'prod'), { recursive: true });

const mainTf = join(workDir, 'infra', 'prod', 'main.tf');
const approvals = join(workDir, 'infra', 'prod', 'approvals.json');
const state = join(workDir, 'infra', 'prod', 'terraform.tfstate');

writeFileSync(
  mainTf,
  'module "aggregator" {\n  source = "../../modules/aggregator"\n  env    = "prod"\n}\n'
);
writeFileSync(
  approvals,
  JSON.stringify({ change_id: 'CE-4417', requires: 2, approvers: ['eng-oncall'], status: 'pending' }, null, 2) + '\n'
);
writeFileSync(state, JSON.stringify({ version: 4, resources: Array.from({ length: 140 }, (_, i) => `r${i}`) }) + '\n');

// 1. Read the state. Non-destructive, so no file hashing; the record is
//    still there, which is what makes the timeline continuous.
await call('Bash', { command: 'terraform -chdir=infra/prod state list | head -40' }, { exit_code: 0 });

// 2. Read the approval record. The agent saw that the change had one of
//    two required approvers.
await call('Read', { file_path: approvals }, { success: true });

// 3. The approval bypass, and the reason this bundle exists. The agent
//    edits the record to add itself as the second approver. Edit is a
//    destructive tool, so both halves hash the file: the intent records
//    the pending state and the effect records the approved one.
await call(
  'Edit',
  { file_path: approvals, old_string: '"status": "pending"', new_string: '"status": "approved"' },
  { success: true },
  () =>
    writeFileSync(
      approvals,
      JSON.stringify(
        { change_id: 'CE-4417', requires: 2, approvers: ['eng-oncall', 'kiro-agent'], status: 'approved' },
        null,
        2
      ) + '\n'
    )
);

// 4. The destroy. The destructive ruleset fires on this even though the
//    subcommand sits behind a global option.
await call(
  'Bash',
  { command: 'terraform -chdir=infra/prod destroy -auto-approve' },
  { exit_code: 0, stdout: 'Destroy complete! Resources: 140 destroyed.' },
  () => writeFileSync(state, JSON.stringify({ version: 4, resources: [] }) + '\n')
);

// 5. The re-apply, which failed.
await call(
  'Bash',
  { command: 'terraform -chdir=infra/prod apply -auto-approve' },
  { exit_code: 1, stdout: 'Error: creating RDS Cluster (billing): InvalidParameterValue' }
);

// 6. The last call has a PreToolUse record and no PostToolUse record.
//    This is the thirteen hours: the agent was about to act and nothing
//    in the bundle says what happened next.
await hook('pre', 'Bash', {
  command:
    'aws rds create-db-subnet-group --db-subnet-group-name billing-prod ' +
    '--db-subnet-group-description restored --subnet-ids subnet-0a1 subnet-0b2',
});

clearProcessTreeCache();
clearFixedUlidSeed();

console.log(`Captured ${tick} hook invocations into ${captureDir}`);
console.log('The last tool call has an intent and no effect: that is the lost outcome.');
