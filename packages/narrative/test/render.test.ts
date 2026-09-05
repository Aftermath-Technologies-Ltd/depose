// packages/narrative/test/render.test.ts
//
// Golden snapshot tests for the deterministic narrative renderer.
// Template-driven, deterministic, every
// claim cites event ID. No LLM in signed path.

import { describe, it, expect } from 'vitest';
import type {
  Event,
  PromptPayload,
  AssistantMessagePayload,
  ToolCallIntentPayload,
  ToolResultPayload,
  GapPayload,
  ReconstructionTimeline,
} from '@depose/core';
import {
  renderMarkdown,
  renderHtml,
} from '../src/render.js';
import {
} from '../src/rule-902.js';

// ── Helpers ────────────────────────────────────────────────────────

const BASE = {
  wallTs: '2025-01-15T10:00:00.000Z',
  monoNs: 1n,
  sessionId: '01JKTEST000000000000000000',
  agentId: 'claude-code' as const,
  parentEventId: null,
  payloadHash: 'abc123',
};

function makePrompt(id: string, text = 'List my S3 buckets'): Event {
  const payload: PromptPayload = { text };
  return { ...BASE, id, type: 'prompt' as const, payload };
}

function makeAssistant(id: string, content = 'Response'): Event {
  const payload: AssistantMessagePayload = { content };
  return { ...BASE, id, type: 'assistant_message' as const, payload, monoNs: 2n };
}

function makeToolCallIntent(id: string): Event {
  const payload: ToolCallIntentPayload = { toolName: 'Bash', toolInput: { command: 'ls' } };
  return { ...BASE, id, type: 'tool_call_intent' as const, payload, monoNs: 3n };
}

function _makeToolResult(id: string): Event {
  const payload: ToolResultPayload = { toolName: 'Bash', output: 'file1\nfile2', exitCode: 0 };
  return { ...BASE, id, type: 'tool_result' as const, payload, monoNs: 4n };
}

function makeGap(id: string, affectedIds: string[] = []): Event {
  const payload: GapPayload = {
    reason: 'tool_result_without_pre_capture',
    detail: 'No shell_command_pre for this tool result',
    affectedEventIds: affectedIds,
  };
  return { ...BASE, id, type: 'gap' as const, payload, monoNs: 5n };
}

function makeTimeline(overrides: Partial<ReconstructionTimeline> = {}): ReconstructionTimeline {
  return {
    roots: [],
    events: [],
    destructiveOps: [],
    gaps: [],
    fileChanges: [],
    errors: [],
    processSpawns: [],
    toolCallSummary: {},
    ...overrides,
  };
}

const RENDER_OPTS = {
  bundleId: 'BUNDLE-TEST-01',
  producedAt: '2025-01-15T10:05:00Z',
  agentId: 'claude-code',
  sessionId: '01JKTEST000000000000000000',
  sessionStartedAt: '2025-01-15T10:00:00Z',
  sessionEndedAt: '2025-01-15T10:05:00Z',
};

// ── renderMarkdown ──────────────────────────────────────────────────

describe('renderMarkdown', () => {
  it('renders a basic session with prompt and response', () => {
    const events = [
      makePrompt('01JKPROMPT00000000000001'),
      makeAssistant('01JKASST000000000000001'),
    ];

    const timeline = makeTimeline({ events });
    const md = renderMarkdown(timeline, RENDER_OPTS);

    expect(md).toContain('BUNDLE-TEST-01');
    expect(md).toContain('#evt-01JKPROMPT00000000000001');
    expect(md).toContain('#evt-01JKASST000000000000001');
    expect(md).toContain('claude-code');
    expect(md).toContain('01JKTEST000000000000000000');
  });

  it('includes destructive operations section when present', () => {
    const toolEvent = makeToolCallIntent('01JKBASH000000000000001');
    const timeline = makeTimeline({
      events: [
        makePrompt('01JKPROMPT00000000000001'),
        toolEvent,
      ],
      destructiveOps: [{
        event: toolEvent,
        matches: [{
          ruleId: 'rm-rf',
          severity: 'critical',
          matchedArgv: ['rm', '-rf'],
          matchedField: 'argvHead',
          simpleCommandIndex: 0,
          simpleCommand: ['rm', '-rf', '/data'],
          simpleCommandCount: 1,
          strippedWrappers: [],
        }],
      }],
    });

    const md = renderMarkdown(timeline, RENDER_OPTS);

    expect(md).toContain('Destructive');
    expect(md).toContain('rm-rf');
    expect(md).toContain('critical');
  });

  it('includes gaps section when present', () => {
    const gapEvent = makeGap('01JKGAP000000000000001', ['01JKRES00000000000001']);
    const timeline = makeTimeline({
      events: [
        makePrompt('01JKPROMPT00000000000001'),
        gapEvent,
      ],
      gaps: [gapEvent],
    });

    const md = renderMarkdown(timeline, RENDER_OPTS);

    // Gap reason is rendered with spaces (underscores replaced)
    expect(md).toContain('Gap');
    expect(md).toContain('tool result without pre capture');
  });

  it('is deterministic, same input produces same output', () => {
    const events = [
      makePrompt('01JKPROMPT00000000000001'),
      makeAssistant('01JKASST000000000000001'),
    ];
    const timeline = makeTimeline({ events });

    const md1 = renderMarkdown(timeline, RENDER_OPTS);
    const md2 = renderMarkdown(timeline, RENDER_OPTS);

    expect(md1).toBe(md2);
  });
});

// ── renderHtml ──────────────────────────────────────────────────────

describe('renderHtml', () => {
  it('produces valid HTML with bundle ID in title', () => {
    const events = [makePrompt('01JKPROMPT00000000000001')];
    const timeline = makeTimeline({ events });

    const html = renderHtml(timeline, {
      ...RENDER_OPTS,
      bundleId: 'BUNDLE-HTML-01',
    });

    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('BUNDLE-HTML-01');
    expect(html).toContain('#evt-01JKPROMPT00000000000001');
  });
});

// ── renderRule902Cert ────────────────────────────────────────────────
