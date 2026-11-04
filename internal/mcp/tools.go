package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func obj(props map[string]any, req ...string) map[string]any {
	o := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(req) > 0 {
		o["required"] = req
	}
	return o
}

func str(desc string) map[string]any  { return map[string]any{"type": "string", "description": desc} }
func intg(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }
func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func enum(desc string, vals ...string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": vals}
}

const sessionDesc = "session name from term_sessions; optional when only one session is shared"

// refusals is the shared sentence about when input is refused.
const refusals = "Refused, with an error that says what to do, while the person is typing, while they hold the keyboard, " +
	"during a secret prompt and in private mode."

func toolList() []tool {
	readOnly := map[string]any{"readOnlyHint": true, "openWorldHint": false}
	writes := map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false}
	return []tool{
		{Name: "term_sessions", Title: "Shared terminal sessions", Annotations: readOnly,
			Description: "List the terminal sessions the person shared with agents: name, size, input policy, people and agents attached. " +
				"Sessions the person did not share are never listed; if none is, ask the person to start one with `cotty new --ai` " +
				"or to run `cotty share NAME`.",
			InputSchema: obj(map[string]any{})},
		{Name: "term_read", Title: "Read the terminal", Annotations: readOnly,
			Description: "Read the shared terminal as you are allowed to see it: the current screen (mode=screen, default) " +
				"or the lines that scrolled off the top since a cursor (mode=since; pass the cursor from the previous result). " +
				"Always includes the session state: who has the keyboard, whether a secret prompt is active (program and lock colour), " +
				"private mode, a line waiting for the person's approval, the foreground program and, when the shell reports it, " +
				"the last command and its exit code. Known secrets read [masked:NAME]; rows written during private mode read [private].",
			InputSchema: obj(map[string]any{
				"session": str(sessionDesc),
				"mode":    enum("screen (default) or since", "screen", "since"),
				"cursor":  intg("since: the line cursor to read from (next_cursor of the last result; 0 = oldest kept)"),
				"limit":   intg("since: at most this many lines (default 500, max 5000)"),
				"context": intg("screen: also return this many lines above the screen (default 0, max 200)"),
			})},
		{Name: "term_run", Title: "Run a command", Annotations: writes,
			Description: "Run one shell command in the shared terminal: types it, presses Enter, waits until the shell is back at its prompt " +
				"or the timeout passes, and returns the output (masked) and the exit code when the shell reports one. Use it at a shell prompt, " +
				"one command at a time; the person sees everything. The result's status says what happened: " +
				"done; secret_prompt (a password or other secret prompt is waiting: only the person types it, never you; tell the person what it is for, " +
				"then call term_wait with for=secret_ended, then term_wait for=prompt or term_read for the result); " +
				"confirmation_pending (the session asks the person to approve each line; call term_wait with for=confirmation); " +
				"running (still running or waiting for input when the timeout passed; read the screen and decide: term_wait, term_type to answer, term_keys C-c to stop); " +
				"interactive (a full-screen program took over; use term_read and term_keys); private_mode (the person turned private mode on; wait). " +
				refusals,
			InputSchema: obj(map[string]any{
				"command":   str("the command line, without a trailing newline"),
				"session":   str(sessionDesc),
				"timeout_s": intg("how long to wait for the prompt (default 30, max 300)"),
				"idle_ms":   intg("quiet time that counts as finished when the shell does not report its prompt (default 500)"),
				"max_lines": intg("return at most the last this many output lines (default 200, max 2000)"),
			}, "command")},
		{Name: "term_type", Title: "Type text", Annotations: writes,
			Description: "Type text into the shared terminal as if typed on its keyboard; enter=true presses Enter after it. " +
				"Use it to answer programs that ask questions; for ordinary commands use term_run. The person sees every character. " +
				refusals + " Under the confirm policy the Enter waits until the person approves the line (held_enter true: call term_wait with for=confirmation). " +
				"Never type passwords, tokens or other secrets, and never ask the person to tell you one.",
			InputSchema: obj(map[string]any{
				"text":    str("text to type (at most 4096 bytes); a newline inside counts as Enter"),
				"enter":   boolean("press Enter after the text"),
				"session": str(sessionDesc),
			}, "text")},
		{Name: "term_keys", Title: "Press keys", Annotations: writes,
			Description: "Press named keys in the shared terminal, in order: Enter, Tab, BTab, Esc, Backspace, Delete, Insert, Home, End, PgUp, PgDn, " +
				"Up, Down, Left, Right, F1 to F12, Space, C-a to C-z (C-c interrupts, C-d ends input), C-@, C-[, C-\\, C-], C-^, C-_, M-<char>. " +
				"Use it for menus, editors, pagers and to interrupt a command. " + refusals +
				" Under the confirm policy only Enter, Tab, Backspace and C-c are allowed.",
			InputSchema: obj(map[string]any{
				"keys":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "key names, 1 to 64"},
				"session": str(sessionDesc),
			}, "keys")},
		{Name: "term_wait", Title: "Wait for the terminal", Annotations: readOnly,
			Description: "Wait for something in the shared terminal. for: idle (no output for idle_ms), prompt (the shell shows its prompt again; " +
				"the same as idle when the shell does not report prompts), regex (pattern, RE2, matched on the masked screen and on new lines), " +
				"change (any output), secret_ended (the person finished typing at a secret prompt), confirmation (the person answered the line " +
				"waiting for approval). When time runs out the result has matched=false and reason timeout (not an error). While waiting for idle, prompt " +
				"or regex, a secret prompt that appears ends the wait with reason secret_prompt: tell the person, then wait for secret_ended. " +
				"The result includes the state and the bottom of the screen.",
			InputSchema: obj(map[string]any{
				"for":       enum("what to wait for", "idle", "prompt", "regex", "change", "secret_ended", "confirmation"),
				"session":   str(sessionDesc),
				"timeout_s": intg("default 30, max 300"),
				"idle_ms":   intg("idle and prompt: quiet time (default 500)"),
				"pattern":   str("regex: RE2 pattern"),
			}, "for")},
		{Name: "term_mask", Title: "Mask a secret by name", Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
			Description: "Ask cotty to hide a known secret, by the name the person gave it in cotty's secret sources (for example GITHUB_TOKEN), " +
				"in everything you read from now on; it then reads [masked:NAME]. You never receive the value. Use it before a command " +
				"that may print that secret. Errors: unknown_secret (no such name), unsupported (no secret sources configured).",
			InputSchema: obj(map[string]any{
				"name":    str("the secret's name"),
				"session": str(sessionDesc),
			}, "name")},
		{Name: "term_request_keyboard", Title: "Ask for the keyboard", Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
			Description: "Ask the person to give you the keyboard when they hold it (error keyboard_held). Their status line shows the request until " +
				"they give the keyboard or you type. Then wait (term_wait for=change, or term_read) until the keyboard is free. Ask once, not in a loop.",
			InputSchema: obj(map[string]any{"session": str(sessionDesc)})},
	}
}

// result is what a tool hands back before it becomes MCP content.
type result struct {
	text    string
	session string
	status  string // for the log: done, secret_prompt, matched, ...
	err     *toolError
}

func errResult(err error) result { return result{err: asToolError(err)} }

func (s *Server) call(ctx context.Context, name string, raw json.RawMessage) map[string]any {
	start := time.Now()
	if len(raw) == 0 || string(raw) == "null" {
		raw = json.RawMessage("{}")
	}
	var r result
	switch name {
	case "term_sessions":
		r = s.termSessions(ctx)
	case "term_read":
		r = withArgs(raw, func(a readArgs) result { return s.termRead(ctx, a) })
	case "term_run":
		r = withArgs(raw, func(a runArgs) result { return s.termRun(ctx, a) })
	case "term_type":
		r = withArgs(raw, func(a typeArgs) result { return s.termType(ctx, a) })
	case "term_keys":
		r = withArgs(raw, func(a keysArgs) result { return s.termKeys(ctx, a) })
	case "term_wait":
		r = withArgs(raw, func(a waitArgs) result { return s.termWait(ctx, a) })
	case "term_mask":
		r = withArgs(raw, func(a maskArgs) result { return s.termMask(ctx, a) })
	case "term_request_keyboard":
		r = withArgs(raw, func(a sessionArg) result { return s.termRequestKeyboard(ctx, a) })
	default:
		r = result{err: &toolError{Code: errUnknownTool, Message: "unknown tool " + name}}
	}
	if r.err != nil {
		r.text = s.formatError(ctx, r.session, r.err)
		r.status = "error=" + r.err.Code
	}
	// The log carries no terminal content and no typed text.
	s.logf("tool=%s session=%s dur=%s %s result_bytes=%d", name, r.session,
		time.Since(start).Round(time.Millisecond), r.status, len(r.text))
	out := map[string]any{"content": []map[string]any{{"type": "text", "text": r.text}}}
	if r.err != nil {
		out["isError"] = true
	}
	return out
}

func withArgs[T any](raw json.RawMessage, f func(T) result) result {
	var a T
	if err := json.Unmarshal(raw, &a); err != nil {
		return result{err: &toolError{Code: errBadArguments, Message: fmt.Sprintf("arguments: %v", err)}}
	}
	return f(a)
}
