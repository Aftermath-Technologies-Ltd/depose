// packages/narrative/test/render.test.ts
//
// Golden snapshot tests for the deterministic narrative renderer.
// BUILD_PLAN.md §6 Phase 4: template-driven, deterministic, every
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
  buildNarrativeData,
  summarizeEvent,
  groupEventsIntoSections,
} from '../src/render.js';
import {
  renderRule902Cert,
  buildCertDataFromManifest,
  type Rule902CertData,
  type ManifestExtract,
} from '../src/rule-902.js';

// ── Helpers ────────────────────────────────────────────────────────

const BASE = {
  wallTs: '2025-01-15T10:00:00.000Z',
  monoNs: 1,
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
  return { ...BASE, id, type: 'assistant_message' as const, payload, monoNs: 2 };
}

function makeToolCallIntent(id: string): Event {
  const payload: ToolCallIntentPayload = { toolName: 'Bash', toolInput: { command: 'ls' }, linkedShellCommandPreId: null };
  return { ...BASE, id, type: 'tool_call_intent' as const, payload, monoNs: 3 };
}

function _makeToolResult(id: string): Event {
  const payload: ToolResultPayload = { toolName: 'Bash', output: 'file1\nfile2', exitCode: 0, linkedShellCommandPreId: null };
  return { ...BASE, id, type: 'tool_result' as const, payload, monoNs: 4 };
}

function makeGap(id: string, affectedIds: string[] = []): Event {
  const payload: GapPayload = {
    reason: 'tool_result_without_pre_capture',
    detail: 'No shell_command_pre for this tool result',
    affectedEventIds: affectedIds,
  };
  return { ...BASE, id, type: 'gap' as const, payload, monoNs: 5 };
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
        matches: [{ ruleId: 'rm-rf', severity: 'critical', matchedArgv: ['rm', '-rf'], matchedField: 'argv[0]' }],
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

  it('is deterministic — same input produces same output', () => {
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

describe('renderRule902Cert', () => {
  it('renders a complete FRE 902 certification', () => {
    const data: Rule902CertData = {
      bundleId: 'BUNDLE-902-01',
      producedAt: '2025-01-15T10:05:00Z',
      rootHash: 'sha256:abcdef1234567890',
      signatureScheme: 'ed25519',
      timestampAuthority: 'http://timestamp.digicert.com',
      timestampGenTime: '2025-01-15T10:05:01Z',
      eventCount: 42,
      destructiveOpCount: 3,
      gapCount: 1,
      certifierName: 'Jane Doe',
      certifierTitle: 'VP Engineering',
      certificationDate: '2025-01-15',
      jurisdiction: 'Northern District of California',
    };

    const cert = renderRule902Cert(data);

    expect(cert).toContain('FED. R. EVID. 902(13)');
    expect(cert).toContain('902(14)');
    expect(cert).toContain('Jane Doe');
    expect(cert).toContain('VP Engineering');
    expect(cert).toContain('sha256:abcdef1234567890');
    expect(cert).toContain('ed25519');
    expect(cert).toContain('42');
    expect(cert).toContain('3 destructive');
    expect(cert).toContain('1 coverage gap');
    expect(cert).toContain('Northern District of California');
    expect(cert).toContain('NOTICE');
  });

  it('works without jurisdiction', () => {
    const data: Rule902CertData = {
      bundleId: 'BUNDLE-902-02',
      producedAt: '2025-01-15T10:05:00Z',
      rootHash: 'sha256:abc',
      signatureScheme: 'ed25519',
      timestampAuthority: 'N/A',
      timestampGenTime: 'N/A',
      eventCount: 5,
      destructiveOpCount: 0,
      gapCount: 0,
      certifierName: 'John Smith',
      certifierTitle: 'CTO',
      certificationDate: '2025-01-16',
    };

    const cert = renderRule902Cert(data);
    expect(cert).toContain('John Smith');
    expect(cert).not.toContain('Jurisdiction:');
  });

  it('is deterministic', () => {
    const data: Rule902CertData = {
      bundleId: 'BUNDLE-DET-902',
      producedAt: '2025-01-15T10:05:00Z',
      rootHash: 'sha256:abc',
      signatureScheme: 'ed25519',
      timestampAuthority: 'TSA',
      timestampGenTime: '2025-01-15T10:05:01Z',
      eventCount: 10,
      destructiveOpCount: 1,
      gapCount: 0,
      certifierName: 'Test',
      certifierTitle: 'Tester',
      certificationDate: '2025-01-15',
    };

    const cert1 = renderRule902Cert(data);
    const cert2 = renderRule902Cert(data);
    expect(cert1).toBe(cert2);
  });
});

// ── buildCertDataFromManifest ───────────────────────────────────────

describe('buildCertDataFromManifest', () => {
  it('extracts cert data from manifest extract', () => {
    const manifest: ManifestExtract = {
      bundleId: 'BUNDLE-MAN-01',
      producedAt: '2025-01-15T10:05:00Z',
      rootHash: 'sha256:feedbeef',
      signatures: [{ scheme: 'ed25519' }],
      timestamps: [{ tsa: 'http://tsa.example.com', timestamp: '2025-01-15T10:05:01Z' }],
      counts: { events: 20, destructiveOperations: 2, gaps: 1 },
    };

    const certData = buildCertDataFromManifest(manifest, {
      name: 'Alice',
      title: 'Engineering Lead',
      date: '2025-01-15',
    });

    expect(certData.bundleId).toBe('BUNDLE-MAN-01');
    expect(certData.signatureScheme).toBe('ed25519');
    expect(certData.timestampAuthority).toBe('http://tsa.example.com');
    expect(certData.eventCount).toBe(20);
    expect(certData.destructiveOpCount).toBe(2);
    expect(certData.gapCount).toBe(1);
    expect(certData.certifierName).toBe('Alice');
  });

  it('handles manifest with no signatures or timestamps', () => {
    const manifest: ManifestExtract = {
      bundleId: 'BUNDLE-UNSIGNED',
      producedAt: '2025-01-15T10:05:00Z',
      rootHash: '(unsigned)',
      signatures: [],
      timestamps: [],
      counts: { events: 5, destructiveOperations: 0, gaps: 0 },
    };

    const certData = buildCertDataFromManifest(manifest, {
      name: 'Bob',
      title: 'Attorney',
      date: '2025-01-16',
    });

    expect(certData.signatureScheme).toBe('none');
    expect(certData.timestampAuthority).toBe('N/A');
    expect(certData.timestampGenTime).toBe('N/A');
  });
});

// ── summarizeEvent ──────────────────────────────────────────────────

describe('summarizeEvent', () => {
  it('summarizes a prompt event', () => {
    const event = makePrompt('01JKPROMPT00000000000001');
    const result = summarizeEvent(event);
    expect(result.summary).toContain('User prompt');
    expect(result.summary).toContain('List my S3 buckets');
  });

  it('summarizes a tool_call_intent event', () => {
    const event = makeToolCallIntent('01JKTOOL0000000000001');
    const result = summarizeEvent(event);
    expect(result.summary).toContain('Tool call intent');
    expect(result.summary).toContain('Bash');
  });

  it('summarizes a gap event', () => {
    const event = makeGap('01JKGAP00000000000001');
    const result = summarizeEvent(event);
    expect(result.summary).toContain('Gap');
    // Gap reason is rendered with spaces
    expect(result.summary).toContain('tool result without pre capture');
  });
});

// ── groupEventsIntoSections ─────────────────────────────────────────

describe('groupEventsIntoSections', () => {
  it('groups events by hour', () => {
    const events = [
      makePrompt('01JKPROMPT00000000000001'),
      makeAssistant('01JKASST000000000000001'),
    ];

    const sections = groupEventsIntoSections(events);
    // Same hour → should be 1 section
    expect(sections.length).toBe(1);
    expect(sections[0]!.events.length).toBe(2);
  });

  it('creates separate sections for different hours', () => {
    const events: Event[] = [
      { ...BASE, id: '01JKPROMPT00000000000001', type: 'prompt' as const, payload: { text: 'Hello' } as PromptPayload, monoNs: 1, wallTs: '2025-01-15T10:00:00.000Z' },
      { ...BASE, id: '01JKPROMPT00000000000002', type: 'prompt' as const, payload: { text: 'World' } as PromptPayload, monoNs: 2, wallTs: '2025-01-15T11:00:00.000Z' },
    ];

    const sections = groupEventsIntoSections(events);
    expect(sections.length).toBe(2);
  });
});

// ── buildNarrativeData ──────────────────────────────────────────────

describe('buildNarrativeData', () => {
  it('assembles narrative data from timeline and options', () => {
    const events = [makePrompt('01JKPROMPT00000000000001')];
    const timeline = makeTimeline({ events });

    const data = buildNarrativeData(timeline, RENDER_OPTS);

    expect(data.bundleId).toBe('BUNDLE-TEST-01');
    expect(data.totalCount).toBe(1);
  });
});