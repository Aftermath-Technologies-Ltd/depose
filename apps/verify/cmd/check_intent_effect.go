// Package cmd, the intent and effect checks.
//
// A tool call is recorded twice: an intent (shell_command_pre, what the
// agent was about to run and what the files it named looked like) and an
// effect (tool_call_effect, how it ended and what those files look like
// now). The effect carries the intent's event id inside its payload, so
// the binding is hashed into payloadHash and signed. The intent carries
// the effect's id in `correlation`, which is not in the chain hash, so it
// is a claim to be checked against the signed side rather than trusted.
//
// Two checks run here:
//
//	intent-effect     every effect names a real intent, no intent is
//	                  closed twice, the unsigned correlation agrees with
//	                  the signed payload, and every unclosed intent has a
//	                  gap event disclosing it
//	file-continuity   a path whose post-state in one effect disagrees with
//	                  its pre-state in a later intent was changed by
//	                  something the bundle did not witness, and that must
//	                  be disclosed as a gap
//
// Both fail closed on a missing disclosure: the producer's own merge emits
// these gaps, so a bundle that lacks one has had it removed.
// See docs/bundle-format.md#intent-and-effect.
package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/chain"
)

// effectPayload is the signed half of the binding.
type effectPayload struct {
	Kind                string       `json:"kind"`
	ToolName            string       `json:"toolName"`
	IntentEventID       *string      `json:"intentEventId"`
	IntentEventIDSource string       `json:"intentEventIdSource"`
	InputHash           string       `json:"inputHash"`
	Files               []fileEffect `json:"files"`
}

type fileEffect struct {
	Path       string  `json:"path"`
	PreSha256  *string `json:"preSha256"`
	PostSha256 *string `json:"postSha256"`
	Change     string  `json:"change"`
}

// intentPayload is the part of shell_command_pre these checks read.
type intentPayload struct {
	Source   string `json:"source"`
	FileArgs []struct {
		Path      string  `json:"path"`
		PreSha256 *string `json:"preSha256"`
	} `json:"fileArgs"`
}

// gapPayload is read to confirm a hole was disclosed rather than hidden.
type gapPayload struct {
	Reason           string   `json:"reason"`
	AffectedEventIDs []string `json:"affectedEventIds"`
}

// checkIntentEffect proves the two halves of every tool call agree.
func checkIntentEffect(ctx *checkContext) []CheckResult {
	const name = "intent-effect"
	if ctx.replay == nil {
		return one(CheckResult{Name: name, Status: StatusSkipped, Detail: "chain replay did not complete"})
	}
	events := ctx.replay.Events
	effects := indicesOfType(events, "tool_call_effect")
	if len(effects) == 0 {
		return one(CheckResult{Name: name, Status: StatusSkipped, Detail: "no post-execution records in this bundle; intents are unpaired by design"})
	}

	byID := make(map[string]int, len(events))
	for i, evt := range events {
		byID[evt.ID] = i
	}
	gaps := gapsByReason(events)

	var problems []string
	closedBy := make(map[string]string, len(effects))
	for _, i := range effects {
		evt := events[i]
		var payload effectPayload
		if err := json.Unmarshal(evt.Payload, &payload); err != nil {
			problems = append(problems, fmt.Sprintf("%s: effect payload is unreadable: %v", evt.ID, err))
			continue
		}
		if payload.IntentEventID == nil || *payload.IntentEventID == "" {
			if !gapCovers(gaps, "effect_without_intent", evt.ID) {
				problems = append(problems, fmt.Sprintf("%s: effect names no intent and no effect_without_intent gap discloses it", evt.ID))
			}
			continue
		}
		intentID := *payload.IntentEventID
		j, ok := byID[intentID]
		if !ok || events[j].Type != "shell_command_pre" {
			if !gapCovers(gaps, "effect_without_intent", evt.ID) {
				problems = append(problems, fmt.Sprintf("%s: effect names intent %s, which is not a shell_command_pre event in this bundle, and no gap discloses it", evt.ID, intentID))
			}
			continue
		}
		if prior, taken := closedBy[intentID]; taken {
			problems = append(problems, fmt.Sprintf("intent %s is closed by two effects, %s and %s; a tool call has one outcome", intentID, prior, evt.ID))
			continue
		}
		closedBy[intentID] = evt.ID
		problems = append(problems, crossReferenceProblems(events[j], evt, intentID)...)
	}

	for _, i := range indicesOfType(events, "shell_command_pre") {
		evt := events[i]
		var payload intentPayload
		if err := json.Unmarshal(evt.Payload, &payload); err != nil {
			continue
		}
		if payload.Source != "claude-pretooluse" {
			continue
		}
		if _, closed := closedBy[evt.ID]; closed {
			continue
		}
		if !gapCovers(gaps, "intent_without_effect", evt.ID) {
			problems = append(problems, fmt.Sprintf("intent %s has no effect and no intent_without_effect gap discloses it", evt.ID))
		}
	}

	if len(problems) > 0 {
		return one(CheckResult{Name: name, Status: StatusFail, Detail: fmt.Sprintf("%d problem(s): %s", len(problems), joinProblems(problems))})
	}
	return one(CheckResult{
		Name:   name,
		Status: StatusPass,
		Detail: fmt.Sprintf("%d tool call(s) have a matching pre and post record; every unpaired intent is disclosed as a gap", len(closedBy)),
	})
}

// crossReferenceProblems compares the signed binding in the effect's
// payload with the unsigned one the merge wrote alongside the events.
func crossReferenceProblems(intent, effect chain.Event, intentID string) []string {
	var problems []string
	if intent.Correlation != nil && intent.Correlation.LinkedEffectID != "" &&
		intent.Correlation.LinkedEffectID != effect.ID {
		problems = append(problems, fmt.Sprintf(
			"intent %s points at effect %s but effect %s claims the intent; the unsigned correlation disagrees with the signed payload",
			intentID, intent.Correlation.LinkedEffectID, effect.ID))
	}
	if effect.Correlation != nil && effect.Correlation.LinkedIntentID != "" &&
		effect.Correlation.LinkedIntentID != intentID {
		problems = append(problems, fmt.Sprintf(
			"effect %s carries correlation to intent %s but its signed payload names %s",
			effect.ID, effect.Correlation.LinkedIntentID, intentID))
	}
	return problems
}

// checkFileContinuity walks each path through the timeline and requires
// that nothing moved it between a recorded outcome and the next recorded
// pre-state without a gap saying so.
func checkFileContinuity(ctx *checkContext) []CheckResult {
	const name = "file-continuity"
	if ctx.replay == nil {
		return one(CheckResult{Name: name, Status: StatusSkipped, Detail: "chain replay did not complete"})
	}
	events := ctx.replay.Events
	if len(indicesOfType(events, "tool_call_effect")) == 0 {
		return one(CheckResult{Name: name, Status: StatusSkipped, Detail: "no post-execution records, so no path has a recorded outcome to carry forward"})
	}
	gaps := gapsByReason(events)

	type observation struct {
		hash    *string
		eventID string
	}
	lastPost := map[string]observation{}
	var problems []string
	tracked := 0

	for _, evt := range events {
		switch evt.Type {
		case "shell_command_pre":
			var payload intentPayload
			if err := json.Unmarshal(evt.Payload, &payload); err != nil {
				continue
			}
			for _, arg := range payload.FileArgs {
				previous, seen := lastPost[arg.Path]
				if !seen || sameHash(previous.hash, arg.PreSha256) {
					continue
				}
				if gapCovers(gaps, "unwitnessed_file_change", evt.ID) {
					continue
				}
				problems = append(problems, fmt.Sprintf(
					"%s was %s after event %s and %s before event %s, with no unwitnessed_file_change gap disclosing the difference",
					arg.Path, describeHash(previous.hash), previous.eventID, describeHash(arg.PreSha256), evt.ID))
			}
		case "tool_call_effect":
			var payload effectPayload
			if err := json.Unmarshal(evt.Payload, &payload); err != nil {
				continue
			}
			for _, file := range payload.Files {
				lastPost[file.Path] = observation{hash: file.PostSha256, eventID: evt.ID}
				tracked++
			}
		}
	}

	if len(problems) > 0 {
		return one(CheckResult{Name: name, Status: StatusFail, Detail: fmt.Sprintf("%d problem(s): %s", len(problems), joinProblems(problems))})
	}
	return one(CheckResult{
		Name:   name,
		Status: StatusPass,
		Detail: fmt.Sprintf("%d file outcome(s) carry forward to the next recorded pre-state, or the difference is disclosed as a gap", tracked),
	})
}

// gapsByReason indexes disclosed holes so a check can ask whether one
// covers a given event.
func gapsByReason(events []chain.Event) map[string]map[string]bool {
	index := map[string]map[string]bool{}
	for _, evt := range events {
		if evt.Type != "gap" {
			continue
		}
		var payload gapPayload
		if err := json.Unmarshal(evt.Payload, &payload); err != nil {
			continue
		}
		byEvent, ok := index[payload.Reason]
		if !ok {
			byEvent = map[string]bool{}
			index[payload.Reason] = byEvent
		}
		for _, id := range payload.AffectedEventIDs {
			byEvent[id] = true
		}
	}
	return index
}

func gapCovers(gaps map[string]map[string]bool, reason, eventID string) bool {
	return gaps[reason][eventID]
}

func indicesOfType(events []chain.Event, eventType string) []int {
	var out []int
	for i, evt := range events {
		if evt.Type == eventType {
			out = append(out, i)
		}
	}
	return out
}

func sameHash(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return strings.EqualFold(*a, *b)
}

func describeHash(hash *string) string {
	if hash == nil {
		return "absent"
	}
	return "sha256:" + truncHex(*hash, 12)
}
