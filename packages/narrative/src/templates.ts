// packages/narrative/src/templates.ts
//
// The two narrative templates. They live apart from the renderer so the
// prose can be read and edited on its own, and so render.ts stays about
// building the view model rather than about markup.

/** Markdown narrative template. */
export const MD_TEMPLATE = `# DEPOSE Reconstruction Narrative

**Bundle ID:** {{bundleId}}
**Produced:** {{producedAt}}
**Agent:** {{agentId}}
**Session:** {{sessionId}}

---

## Summary

This bundle reconstructs {{totalCount}} events from an AI coding agent session
({{agentId}}). The session ran from {{sessionStartedAt}} to {{sessionEndedAt}} UTC.

{{#if destructiveCount}}
**⚠ {{destructiveCount}} destructive operation(s) detected.** See Destructive Operations below.
{{/if}}

{{#if lostOutcomeCount}}
**⚠ {{lostOutcomeCount}} tool call(s) ran with no recorded outcome.** The agent was
about to act, and nothing in this bundle records what happened next. See Lost
Outcomes below; this is the most serious kind of coverage hole DEPOSE reports.
{{/if}}

{{#if unwitnessedExecveCount}}
**⚠ {{unwitnessedExecveCount}} command(s) ran in the agent's process tree with no hook record.**
The kernel witnessed them; the capture surface did not. See Unwitnessed Commands below.
{{/if}}

{{#if gapCount}}
**◉ {{gapCount}} coverage gap(s) identified.** Gaps indicate events where pre-execution
capture was not available. These are disclosed, not hidden. See Coverage Gaps below.
{{/if}}

---

## Lost Outcomes

{{#if lostOutcomes}}
Each entry is a tool call whose pre-execution record exists and whose outcome does not.
{{#each lostOutcomes}}
- {{wallTs}}: {{detail}} \`[#evt-{{id}}]\`
{{/each}}
{{else}}
Every recorded intent has a recorded outcome.
{{/if}}

{{#if unwitnessedExecves}}
---

## Unwitnessed Commands

The kernel execve collector saw these in the agent's process tree and no hook or shim recorded them.
{{#each unwitnessedExecves}}
- {{wallTs}}: {{detail}} \`[#evt-{{id}}]\`
{{/each}}
{{/if}}

---

## Timeline

{{#each sections}}
### {{header}}

{{#each events}}
- **[{{type}}]** {{wallTs}} UTC, {{summary}} \`[#evt-{{id}}]\`
{{#if detail}}
  - {{detail}}
{{/if}}
{{/each}}

{{/each}}

---

## Destructive Operations

{{#if destructiveOps}}
{{#each destructiveOps}}
- **[{{severity}}]** {{wallTs}}: \`{{command}}\`{{position}}, Rule: {{ruleId}} \`[#evt-{{eventId}}]\`
{{/each}}
{{else}}
No destructive operations detected.
{{/if}}

---

## Coverage Gaps

{{#if gaps}}
{{#each gaps}}
- **[{{reason}}]** {{wallTs}}: {{detail}} \`[#evt-{{id}}]\`
{{/each}}
{{else}}
No coverage gaps. All tool results have matching pre-execution captures.
{{/if}}

{{#if capturesExcluded}}
**Capture records excluded:** {{capturesExcluded}} record(s) in the producer's
capture store could not be attributed to this session and were left out of this
bundle; {{capturesAttributed}} were included. The store is machine-wide, so it
holds activity from unrelated work. Excluded records are counted in the signed
manifest (\`counts.capturesExcluded\`) so this disclosure is covered by the
signature rather than asserted only here.
{{/if}}

---

## Verification

This narrative is **deterministically generated** from the event timeline.
Every claim above cites a specific event ID (\`#evt-<ulid>\`) that maps to a
row in \`events.jsonl\`. The events are hash-chained and signed; altering any
event invalidates the bundle.

To verify: \`depose-verify <bundle-path>\`

**Note:** This narrative is excluded from the signed content. It is derived
from signed events. Modifying this file does not affect bundle validity.`;

/** HTML narrative template. */
export const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DEPOSE Reconstruction: {{bundleId}}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 800px; margin: 2em auto; padding: 0 1em; color: #1a1a1a; line-height: 1.6; }
  h1 { border-bottom: 2px solid #333; padding-bottom: 0.3em; }
  h2 { color: #444; margin-top: 2em; }
  h3 { color: #555; }
  .meta { background: #f5f5f5; padding: 1em; border-radius: 4px; margin-bottom: 1.5em; font-size: 0.9em; }
  .destructive { background: #fff3f3; border-left: 4px solid #c00; padding: 0.5em 1em; margin: 0.5em 0; }
  .gap { background: #fff8e1; border-left: 4px solid #f90; padding: 0.5em 1em; margin: 0.5em 0; }
  .event-ref { font-family: monospace; font-size: 0.85em; color: #666; }
  code { background: #f0f0f0; padding: 0.15em 0.3em; border-radius: 3px; font-size: 0.9em; }
  .warning { color: #c00; font-weight: bold; }
  .note { font-style: italic; color: #666; font-size: 0.9em; }
  table { border-collapse: collapse; width: 100%; margin: 1em 0; }
  th, td { border: 1px solid #ddd; padding: 0.5em; text-align: left; }
  th { background: #f5f5f5; }
</style>
</head>
<body>
<h1>DEPOSE Reconstruction Narrative</h1>
<div class="meta">
<p><strong>Bundle ID:</strong> {{bundleId}}<br>
<strong>Produced:</strong> {{producedAt}}<br>
<strong>Agent:</strong> {{agentId}}<br>
<strong>Session:</strong> {{sessionId}}</p>
</div>
<h2>Summary</h2>
<p>This bundle reconstructs {{totalCount}} events from an AI coding agent session
({{agentId}}). The session ran from {{sessionStartedAt}} to {{sessionEndedAt}} UTC.</p>
{{#if destructiveCount}}
<div class="destructive"><strong>WARNING: {{destructiveCount}} destructive operation(s) detected.</strong> See Destructive Operations below.</div>
{{/if}}
{{#if lostOutcomeCount}}
<div class="destructive"><strong>WARNING: {{lostOutcomeCount}} tool call(s) ran with no recorded outcome.</strong> The agent was about to act and nothing in this bundle records what happened next. See Lost Outcomes below.</div>
{{/if}}
{{#if unwitnessedExecveCount}}
<div class="destructive"><strong>WARNING: {{unwitnessedExecveCount}} command(s) ran in the agent's process tree with no hook record.</strong> The kernel witnessed them; the capture surface did not.</div>
{{/if}}
{{#if gapCount}}
<div class="gap"><strong>NOTE: {{gapCount}} coverage gap(s) identified.</strong> Gaps indicate events where pre-execution capture was not available. These are disclosed, not hidden.</div>
{{/if}}
<h2>Lost Outcomes</h2>
{{#if lostOutcomes}}
<table>
<tr><th>Time</th><th>Detail</th><th>Event ID</th></tr>
{{#each lostOutcomes}}
<tr class="destructive"><td>{{wallTs}}</td><td>{{detail}}</td><td class="event-ref"><code>#evt-{{id}}</code></td></tr>
{{/each}}
</table>
{{else}}
<p>Every recorded intent has a recorded outcome.</p>
{{/if}}
{{#if unwitnessedExecves}}
<h2>Unwitnessed Commands</h2>
<table>
<tr><th>Time</th><th>Detail</th><th>Event ID</th></tr>
{{#each unwitnessedExecves}}
<tr class="destructive"><td>{{wallTs}}</td><td>{{detail}}</td><td class="event-ref"><code>#evt-{{id}}</code></td></tr>
{{/each}}
</table>
{{/if}}
<h2>Timeline</h2>
{{#each sections}}
<h3>{{header}}</h3>
<table>
<tr><th>Type</th><th>Time (UTC)</th><th>Summary</th><th>Event ID</th></tr>
{{#each events}}
<tr><td>{{type}}</td><td>{{wallTs}}</td><td>{{summary}}</td><td class="event-ref"><code>#evt-{{id}}</code></td></tr>
{{/each}}
</table>
{{/each}}
<h2>Destructive Operations</h2>
{{#if destructiveOps}}
<table>
<tr><th>Severity</th><th>Time</th><th>Command</th><th>Rule</th><th>Event ID</th></tr>
{{#each destructiveOps}}
<tr class="destructive"><td>{{severity}}</td><td>{{wallTs}}</td><td><code>{{command}}</code>{{position}}</td><td>{{ruleId}}</td><td class="event-ref"><code>#evt-{{eventId}}</code></td></tr>
{{/each}}
</table>
{{else}}
<p>No destructive operations detected.</p>
{{/if}}
<h2>Coverage Gaps</h2>
{{#if gaps}}
<table>
<tr><th>Reason</th><th>Time</th><th>Detail</th><th>Event ID</th></tr>
{{#each gaps}}
<tr class="gap"><td>{{reason}}</td><td>{{wallTs}}</td><td>{{detail}}</td><td class="event-ref"><code>#evt-{{id}}</code></td></tr>
{{/each}}
</table>
{{else}}
<p>No coverage gaps. All tool results have matching pre-execution captures.</p>
{{/if}}
<h2>Verification</h2>
<p>This narrative is <strong>deterministically generated</strong> from the event timeline.
Every claim above cites a specific event ID that maps to a row in <code>events.jsonl</code>.
The events are hash-chained and signed; altering any event invalidates the bundle.</p>
<p>To verify: <code>depose-verify &lt;bundle-path&gt;</code></p>
<p class="note">This narrative is excluded from the signed content. It is derived from signed events. Modifying this file does not affect bundle validity.</p>
</body>
</html>`;