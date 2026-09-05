// packages/core/src/normalize/merge-intent-effect.ts
//
// Binds the two halves of a tool call. The PreToolUse hook writes the
// intent (a shell_command_pre event: what the agent was about to run and
// what the files it named looked like beforehand); the PostToolUse hook
// writes the effect (a tool_call_effect event: how the call ended and what
// those files look like now).
//
// Three things come out of this pass:
//
//   1. The pair is linked. The effect's payload carries the intent's event
//      id, so the link is hashed and signed. When the pending marker was
//      lost the merge resolves it from inputHash and a time window instead,
//      and says so in intentEventIdSource rather than presenting a matched
//      link as a recorded one.
//   2. An intent with no effect becomes a gap. That is the "the agent ran
//      something and we lost what happened" case, and it is the loudest
//      thing the narrative reports.
//   3. A file whose pre-state in a later intent disagrees with its
//      post-state in an earlier effect becomes a gap: something changed it
//      that nothing in this bundle witnessed.
//
// The verifier requires each of these gaps to be present, so stripping one
// out of events.jsonl turns a disclosed hole into a failed check.
// See docs/bundle-format.md#intent-and-effect.

import type {
  AgentId,
  Event,
  ShellCommandPrePayload,
  ToolCallEffectPayload,
  GapPayload,
} from '../events/schema.js';
import { sha256 } from '../events/canonical-json.js';
import { buildEvent, truncateArgv } from './merge-support.js';

/** Options for the intent and effect pass. */
export interface IntentEffectOptions {
  sessionId: string;
  agentId: AgentId;
  /** Seconds either side of an effect to look for its intent by inputHash. */
  matchWindowSeconds: number;
}

/** What the pass produced. */
export interface IntentEffectResult {
  /** Gap events to append to the timeline. */
  gaps: Event[];
  /** Intent and effect pairs that were linked, by either route. */
  linkedCount: number;
}

/**
 * Link intents to effects, then report every hole the pairing exposes.
 *
 * Mutates the events in place: an effect's payload gains the intent's id
 * when the merge resolves it, and both events gain correlation entries.
 * Payload hashes are recomputed for anything changed, so the chain pass
 * sees the final form.
 *
 * @param sorted - The merged timeline, already ordered by (wallTs, monoNs).
 * @param options - Session, agent, and the correlation window.
 * @returns The gap events to append and the number of pairs linked.
 */
export function bindIntentAndEffect(
  sorted: Event[],
  options: IntentEffectOptions
): IntentEffectResult {
  const intents = sorted.filter((e) => e.type === 'shell_command_pre');
  const effects = sorted.filter((e) => e.type === 'tool_call_effect');
  if (effects.length === 0) {
    return { gaps: [], linkedCount: 0 };
  }

  const byId = new Map(intents.map((e) => [e.id, e]));
  const claimed = new Set<string>();
  const gaps: Event[] = [];
  let linkedCount = 0;

  for (const effect of effects) {
    const payload = effect.payload as ToolCallEffectPayload;
    const recorded = payload.intentEventId ? byId.get(payload.intentEventId) : undefined;
    const intent = recorded ?? resolveByInputHash(effect, payload, intents, claimed, options);

    if (!intent) {
      gaps.push(effectWithoutIntent(effect, payload, options));
      continue;
    }
    if (claimed.has(intent.id)) {
      // A second effect naming the same intent is not a coverage hole, it
      // is a contradiction. Leave it unlinked; the verifier fails on it.
      continue;
    }
    if (!recorded) {
      payload.intentEventId = intent.id;
      payload.intentEventIdSource = 'correlated';
      effect.payloadHash = sha256(payload);
    }
    claimed.add(intent.id);
    intent.correlation = { ...intent.correlation, linkedEffectId: effect.id };
    effect.correlation = { ...effect.correlation, linkedIntentId: intent.id };
    linkedCount++;
  }

  for (const intent of intents) {
    const payload = intent.payload as ShellCommandPrePayload;
    if (payload.source !== 'claude-pretooluse' || claimed.has(intent.id)) continue;
    gaps.push(intentWithoutEffect(intent, payload, options));
  }

  gaps.push(...fileContinuityGaps(sorted, options));
  return { gaps, linkedCount };
}

/**
 * Last resort when the pending marker did not survive: the same tool input
 * hashed the same way, in the same session, inside the match window.
 */
function resolveByInputHash(
  effect: Event,
  payload: ToolCallEffectPayload,
  intents: Event[],
  claimed: Set<string>,
  options: IntentEffectOptions
): Event | undefined {
  const effectMs = Date.parse(effect.wallTs);
  const windowMs = options.matchWindowSeconds * 1000;
  let best: Event | undefined;
  let bestDelta = Number.POSITIVE_INFINITY;
  for (const intent of intents) {
    if (claimed.has(intent.id)) continue;
    const intentPayload = intent.payload as ShellCommandPrePayload;
    if (intentPayload.inputHash !== payload.inputHash) continue;
    const delta = Math.abs(Date.parse(intent.wallTs) - effectMs);
    if (delta > windowMs || delta >= bestDelta) continue;
    best = intent;
    bestDelta = delta;
  }
  return best;
}

function intentWithoutEffect(
  intent: Event,
  payload: ShellCommandPrePayload,
  options: IntentEffectOptions
): Event {
  const gap: GapPayload = {
    reason: 'intent_without_effect',
    affectedEventIds: [intent.id],
    detail:
      `The agent was about to run ${truncateArgv(payload.argv)} at ${payload.capturedAt} ` +
      `and no post-execution record closed it. The command may have run and its outcome ` +
      `was lost, or the session ended before the tool returned. What happened next is not ` +
      `in this bundle.`,
  };
  return buildEvent({
    sessionId: options.sessionId,
    agentId: options.agentId,
    type: 'gap',
    parentEventId: intent.id,
    monoNs: intent.monoNs + 1n,
    wallTs: intent.wallTs,
    payload: gap,
  });
}

function effectWithoutIntent(
  effect: Event,
  payload: ToolCallEffectPayload,
  options: IntentEffectOptions
): Event {
  const named = payload.intentEventId ? ` names intent ${payload.intentEventId}, which is not in this bundle, and` : '';
  const gap: GapPayload = {
    reason: 'effect_without_intent',
    affectedEventIds: [effect.id],
    detail:
      `The post-execution record for ${payload.toolName} at ${payload.capturedAt}${named} ` +
      `could not be matched to a pre-execution capture. What the agent intended to run is ` +
      `not recorded; only the outcome is.`,
  };
  return buildEvent({
    sessionId: options.sessionId,
    agentId: options.agentId,
    type: 'gap',
    parentEventId: effect.id,
    monoNs: effect.monoNs + 1n,
    wallTs: effect.wallTs,
    payload: gap,
  });
}

/**
 * A file the bundle claims continuous custody of, whose hash moved between
 * one call's post-state and the next call's pre-state, was changed by
 * something nothing here witnessed.
 */
function fileContinuityGaps(sorted: Event[], options: IntentEffectOptions): Event[] {
  const lastPost = new Map<string, { sha256: string | null; eventId: string }>();
  const gaps: Event[] = [];

  for (const event of sorted) {
    if (event.type === 'shell_command_pre') {
      const payload = event.payload as ShellCommandPrePayload;
      for (const arg of payload.fileArgs ?? []) {
        const previous = lastPost.get(arg.path);
        if (!previous || previous.sha256 === arg.preSha256) continue;
        gaps.push(unwitnessedChange(event, arg.path, previous, arg.preSha256, options));
      }
      continue;
    }
    if (event.type === 'tool_call_effect') {
      const payload = event.payload as ToolCallEffectPayload;
      for (const file of payload.files) {
        lastPost.set(file.path, { sha256: file.postSha256, eventId: event.id });
      }
    }
  }
  return gaps;
}

function unwitnessedChange(
  intent: Event,
  path: string,
  previous: { sha256: string | null; eventId: string },
  observed: string | null,
  options: IntentEffectOptions
): Event {
  const gap: GapPayload = {
    reason: 'unwitnessed_file_change',
    affectedEventIds: [previous.eventId, intent.id],
    detail:
      `${path} was ${describeHash(previous.sha256)} when event ${previous.eventId} finished ` +
      `and ${describeHash(observed)} when event ${intent.id} started. Something changed it in ` +
      `between and this bundle did not witness it.`,
  };
  return buildEvent({
    sessionId: options.sessionId,
    agentId: options.agentId,
    type: 'gap',
    parentEventId: intent.id,
    monoNs: intent.monoNs + 2n,
    wallTs: intent.wallTs,
    payload: gap,
  });
}

function describeHash(hash: string | null): string {
  return hash === null ? 'absent' : `sha256:${hash.slice(0, 12)}`;
}
