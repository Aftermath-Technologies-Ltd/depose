// packages/bundle/test/export.golden.test.ts
//
// Golden outputs for the three IETF export targets, over both example
// incidents. The goldens are byte comparisons: an unintended change to
// any mapping shows up as a diff rather than as a subtly different
// export that still passes a loose structural check.
//
// Regenerate after a deliberate mapping change with:
//   DEPOSE_WRITE_GOLDEN=1 npx vitest run packages/bundle/test/export.golden.test.ts

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdirSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { exportAat, exportAsqavReceipts, exportScittStatement, type LoadedBundle } from '../src/index.js';
import { EXPORT_EXAMPLES, EXPORT_TEST_KEY, GOLDEN_EXPORT_DIR, sealExample } from './export-fixture.js';

const outputRoot = join(__dirname, 'test-output-export');
const bundles = new Map<string, LoadedBundle>();
const writeGolden = process.env.DEPOSE_WRITE_GOLDEN === '1';

beforeAll(async () => {
  rmSync(outputRoot, { recursive: true, force: true });
  mkdirSync(outputRoot, { recursive: true });
  if (writeGolden) mkdirSync(GOLDEN_EXPORT_DIR, { recursive: true });
  for (const example of EXPORT_EXAMPLES) {
    bundles.set(example, await sealExample(example, outputRoot));
  }
});

afterAll(() => {
  rmSync(outputRoot, { recursive: true, force: true });
});

function checkGolden(name: string, actual: Buffer): void {
  const path = join(GOLDEN_EXPORT_DIR, name);
  if (writeGolden) {
    writeFileSync(path, actual);
    return;
  }
  expect(existsSync(path), `golden ${name} is missing; regenerate with DEPOSE_WRITE_GOLDEN=1`).toBe(true);
  expect(actual.equals(readFileSync(path))).toBe(true);
}

describe.each(EXPORT_EXAMPLES)('%s', (example) => {
  it('exports AAT JSON Lines matching the golden', () => {
    checkGolden(`${example}.aat.jsonl`, Buffer.from(exportAat(bundles.get(example)!), 'utf-8'));
  });

  it('exports ASQAV receipts matching the golden', () => {
    checkGolden(
      `${example}.asqav-receipts.jsonl`,
      Buffer.from(exportAsqavReceipts(bundles.get(example)!, EXPORT_TEST_KEY), 'utf-8')
    );
  });

  it('exports a SCITT signed statement matching the golden', () => {
    checkGolden(
      `${example}.scitt-statement.cose`,
      Buffer.from(exportScittStatement(bundles.get(example)!, EXPORT_TEST_KEY))
    );
  });

  it('produces the same bytes twice, so the goldens mean something', () => {
    const bundle = bundles.get(example)!;
    expect(exportAat(bundle)).toBe(exportAat(bundle));
    expect(exportAsqavReceipts(bundle, EXPORT_TEST_KEY)).toBe(exportAsqavReceipts(bundle, EXPORT_TEST_KEY));
    expect(Buffer.from(exportScittStatement(bundle, EXPORT_TEST_KEY))).toEqual(
      Buffer.from(exportScittStatement(bundle, EXPORT_TEST_KEY))
    );
  });
});
