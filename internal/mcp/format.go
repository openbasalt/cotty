package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbasalt/cotty/internal/proto"
)

// hints say what the model should do after an error, by code.
var hints = map[string]string{
	proto.ErrPrivateMode: "The person turned on private mode: your view is frozen and your input is refused until they turn it off. " +
		"Do not try to work around it; wait (term_wait with for=change) or ask the person.",
	proto.ErrSecretInputActive: "A password or other secret prompt is active. Only the person types secrets; you cannot and must not. " +
		"Tell the person what the prompt is for, then call term_wait with for=secret_ended.",
	proto.ErrKeyboardHeld: "The person holds the keyboard. Call term_request_keyboard once to ask for it, then wait until the state shows keyboard free.",
	proto.ErrPersonTyping: "The person is typing right now. Wait until retry_after_ms passes and try again; never type over them.",
	proto.ErrConfirmationPending: "Your previous line waits for the person's approval (confirm policy). " +
		"Call term_wait with for=confirmation, then read the screen.",
	proto.ErrPolicyDenied: "This session uses the confirm policy: send plain text without tabs, ! or ^ (they expand shell history; use -ne, test -z or a script file instead of !), " +
		"and only the keys Enter, Backspace, Delete, Space, Left, Right, Home, End and C-c. Type whole commands; do not complete them with Tab.",
	proto.ErrNotShared: "The person has not shared this session with agents. Ask them to run `cotty share SESSION`, " +
		"or to start a shared session with `cotty new --ai`.",
	proto.ErrSessionEnded: "The session ended or closed this connection. Call term_sessions to see what is shared now.",
	proto.ErrUnknownSecret: "No secret with that name is configured. Ask the person for the name they used (`cotty secrets`), " +
		"never for the value.",
	proto.ErrUnsupported: "Masking by name is not available in this session (no secret sources are configured).",
	proto.ErrBadRequest:  "The request was not valid; check the arguments against the tool's description.",
	proto.ErrForbidden:   "Agents may not do this.",
	errBadArguments:      "Check the arguments against the tool's description.",
	errNoSession: "Ask the person to start a shared session with `cotty new --ai`, or to share an existing one with " +
		"`cotty share SESSION`, then call term_sessions.",
	errAmbiguousSession: "Pass session with one of the names from term_sessions.",
	errUnknownSession:   "Call term_sessions for the names you may use.",
	errUnreachable:      "cotty could not reach the session broker. Call term_sessions; if it persists, tell the person.",
	errUnknownTool:      "Call tools/list for the tools of this server.",
}

// arbitration codes come with the state, so the model sees why.
var arbitration = map[string]bool{
	proto.ErrPrivateMode: true, proto.ErrSecretInputActive: true, proto.ErrKeyboardHeld: true,
	proto.ErrPersonTyping: true, proto.ErrConfirmationPending: true, proto.ErrPolicyDenied: true,
}

func (s *Server) formatError(ctx context.Context, sess string, e *toolError) string {
	var b strings.Builder
	fmt.Fprintf(&b, "error: %s\n", e.Code)
	if e.Message != "" {
		fmt.Fprintf(&b, "message: %s\n", e.Message)
	}
	if e.RetryAfterMS > 0 {
		fmt.Fprintf(&b, "retry_after_ms: %d\n", e.RetryAfterMS)
	}
	if h := hints[e.Code]; h != "" {
		fmt.Fprintf(&b, "what to do: %s\n", h)
	}
	if arbitration[e.Code] && sess != "" {
		if ac := s.cached(sess); ac != nil {
			var st proto.State
			if ac.cl.Call(ctx, "state", nil, &st) == nil {
				b.WriteString(stateText(st))
			}
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// cached returns the open connection to a session by name, if any.
func (s *Server) cached(name string) *agentConn {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	for _, ac := range s.conns {
		if ac.name == name {
			return ac
		}
	}
	return nil
}

func lockColour(p *proto.Program) string {
	if p != nil && p.Trust == proto.TrustSystem {
		return "green lock (a trusted system program)"
	}
	return "amber lock (not a trusted system program)"
}

func programText(p *proto.Program) string {
	if p == nil {
		return "unknown program"
	}
	s := p.Name
	if p.Exe != "" && p.Exe != p.Name {
		s += " (" + p.Exe + ")"
	}
	if p.AgentStarted {
		s += ", started by a line you typed"
	}
	return s
}

// stateText describes the state for a model, one fact per line.
func stateText(st proto.State) string {
	var b strings.Builder
	b.WriteString("state:\n")
	line := func(format string, a ...any) { fmt.Fprintf(&b, "  "+format+"\n", a...) }
	switch {
	case st.Keyboard == proto.KeyboardHeld:
		line("keyboard: held by the person (term_request_keyboard asks for it)")
	case st.PersonTyping:
		line("keyboard: free, the person is typing right now")
	default:
		line("keyboard: free")
	}
	if st.AgentMayType {
		line("you may type: yes")
	} else {
		line("you may type: no")
	}
	if st.SecretInput == proto.SecretActive {
		line("secret prompt: ACTIVE, %s, %s; only the person types it; call term_wait with for=secret_ended",
			programText(st.SecretProgram), lockColour(st.SecretProgram))
	} else {
		line("secret prompt: none")
	}
	if st.Private {
		line("private mode: ON (your view is frozen; rows written meanwhile read [private])")
	} else {
		line("private mode: off")
	}
	if st.Policy == proto.PolicyConfirm {
		line("policy: confirm (the person approves every line you send before it runs)")
	} else {
		line("policy: auto")
	}
	if st.PendingConfirmation != nil {
		line("line waiting for the person's approval: %q", st.PendingConfirmation.Line)
	}
	if st.AgentRequestsKeyboard {
		line("your keyboard request is shown to the person")
	}
	if st.Foreground != nil {
		line("foreground program: %s (pid %d)", st.Foreground.Name, st.Foreground.PID)
	}
	if st.AltScreen {
		line("full-screen program: yes")
	}
	if st.Shell.Integration {
		code := "unknown"
		if st.Shell.ExitCode != nil {
			code = fmt.Sprint(*st.Shell.ExitCode)
		}
		at := "no"
		if st.Shell.AtPrompt {
			at = "yes"
		}
		line("shell: at prompt %s, last command %q, exit code %s (reported by the shell; a hint)", at, st.Shell.LastCommand, code)
	} else {
		line("shell integration: none (exit codes are not reported; run `echo $?` when you need one)")
	}
	line("size: %dx%d, people attached: %d, agents: %d", st.Cols, st.Rows, st.Persons, st.Agents)
	return b.String()
}

// trimBlank drops blank rows at the end.
func trimBlank(rows []string) []string {
	n := len(rows)
	for n > 0 && strings.TrimSpace(rows[n-1]) == "" {
		n--
	}
	return rows[:n]
}

// tail keeps the last n rows and says how many were left out.
func tail(rows []string, n int) ([]string, int) {
	if n <= 0 || len(rows) <= n {
		return rows, 0
	}
	return rows[len(rows)-n:], len(rows) - n
}
