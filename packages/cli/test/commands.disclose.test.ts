// packages/cli/test/commands.disclose.test.ts
//
// Flag parsing for `depose disclose`: event selection by id, index, and
// range, and field selection as JSON pointers.

import { describe, it, expect } from 'vitest';
import { parseEventSelection, parseFieldSelection } from '../src/commands/disclose.js';

const ids = ['01A', '01B', '01C', '01D', '01E'];

describe('parseEventSelection', () => {
  it('selects everything with "all"', () => {
    expect(parseEventSelection('all', ids)).toEqual([0, 1, 2, 3, 4]);
  });

  it('accepts ids, indices, and inclusive ranges in one spec, sorted and deduplicated', () => {
    expect(parseEventSelection('01D, 0, 1-2, 2', ids)).toEqual([0, 1, 2, 3]);
  });

  it('rejects an unknown id, a backwards range, and an index past the end', () => {
    expect(() => parseEventSelection('01Z', ids)).toThrow(/not in this bundle/);
    expect(() => parseEventSelection('3-1', ids)).toThrow(/runs backwards/);
    expect(() => parseEventSelection('9', ids)).toThrow(/out of range/);
  });
});

describe('parseFieldSelection', () => {
  it('returns "all" and an empty list for "none"', () => {
    expect(parseFieldSelection('all')).toBe('all');
    expect(parseFieldSelection('none')).toEqual([]);
  });

  it('accepts top-level JSON pointers and rejects nested ones', () => {
    expect(parseFieldSelection('/toolInput, /output')).toEqual(['/toolInput', '/output']);
    expect(() => parseFieldSelection('toolInput')).toThrow(/JSON pointer/);
    expect(() => parseFieldSelection('/toolInput/command')).toThrow(/one top-level payload field/);
  });
});
