package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

type sessionArg struct {
	Session string `json:"session"`
}

type readArgs struct {
	Session string `json:"session"`
	Mode    string `json:"mode"`
	Cursor  int64  `json:"cursor"`
	Limit   int    `json:"limit"`
	Context int    `json:"context"`
}

type typeArgs struct {
	Session string `json:"session"`
	Text    string `json:"text"`
	Enter   bool   `json:"enter"`
}

type keysArgs struct {
	Session string   `json:"session"`
	Keys    []string `json:"keys"`
}

type runArgs struct {
	Session  string `json:"session"`
	Command  string `json:"command"`
	TimeoutS int    `json:"timeout_s"`
	IdleMS   int    `json:"idle_ms"`
	MaxLines int    `json:"max_lines"`
}

type waitArgs struct {
	Session  string `json:"session"`
	For      string `json:"for"`
	TimeoutS int    `json:"timeout_s"`
	IdleMS   int    `json:"idle_ms"`
	Pattern  string `json:"pattern"`
}

type maskArgs struct {
	Session string `json:"session"`
	Name    string `json:"name"`
}

// Reasons and statuses that the server adds to the broker's.
const (
	reasonSecretPrompt = "secret_prompt"

	statusDone         = "done"
	statusSecretPrompt = "secret_prompt"
	statusConfirmation = "confirmation_pending"
	statusRejected     = "rejected"
	statusRunning      = "running"
	statusInteractive  = "interactive"
	statusPrivate      = "private_mode"
)

const (
	defaultTimeout = 30 * time.Second
	maxTimeout     = 300 * time.Second
	statePoll      = 250 * time.Millisecond
)

func timeoutOf(sec int) time.Duration {
	if sec <= 0 {
		return defaultTimeout
	}
	return min(time.Duration(sec)*time.Second, maxTimeout)
}

func bad(format string, a ...any) result {
	return result{err: &toolError{Code: errBadArguments, Message: fmt.Sprintf(format, a...)}}
}

func (s *Server) termSessions(ctx context.Context) result {
	list, err := s.sessions(ctx)
	if err != nil {
		return errResult(err)
	}
	if len(list) == 0 {
		return result{status: "sessions=0", text: "No terminal session is shared with agents. " + hints[errNoSession]}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d shared session(s):\n", len(list))
	for _, e := range list {
		i := e.info
		def := ""
		if i.Session == s.Session || len(list) == 1 {
			def = ", default"
		}
		fmt.Fprintf(&b, "- %s: %dx%d, policy %s, people attached %d, agents %d, created %s%s\n",
			i.Session, i.Cols, i.Rows, i.Policy, i.Persons, i.Agents, i.Created, def)
	}
	if len(list) > 1 && s.Session == "" {
		b.WriteString("Pass session to the other tools.\n")
	}
	return result{status: fmt.Sprintf("sessions=%d", len(list)), text: strings.TrimRight(b.String(), "\n")}
}

func (s *Server) termRead(ctx context.Context, a readArgs) result {
	ac, err := s.conn(ctx, a.Session)
	if err != nil {
		return errResult(err)
	}
	r := result{session: ac.name}
	var b strings.Builder
	fmt.Fprintf(&b, "session: %s\n", ac.name)
	switch a.Mode {
	case "", "screen":
		var sc proto.Screen
		if err := ac.cl.Call(ctx, "screen", map[string]int{"context": min(max(a.Context, 0), 200)}, &sc); err != nil {
			return result{session: ac.name, err: asToolError(err)}
		}
		b.WriteString(stateText(sc.State))
		fmt.Fprintf(&b, "cursor: row %d, col %d (rows count from 0); next_cursor for mode=since: %d\n",
			sc.Cursor.Row, sc.Cursor.Col, sc.CursorSince)
		if len(sc.Context) > 0 {
			fmt.Fprintf(&b, "--- %d lines above the screen ---\n%s\n", len(sc.Context), strings.Join(sc.Context, "\n"))
		}
		rows := trimBlank(sc.Rows)
		fmt.Fprintf(&b, "--- screen, %d of %d rows (blank rows at the bottom left out) ---\n", len(rows), len(sc.Rows))
		b.WriteString(strings.Join(rows, "\n"))
		r.status = "mode=screen"
	case "since":
		var sn proto.Since
		limit := a.Limit
		if limit <= 0 {
			limit = 500
		}
		if err := ac.cl.Call(ctx, "since", map[string]any{"cursor": max(a.Cursor, 0), "limit": min(limit, 5000)}, &sn); err != nil {
			return result{session: ac.name, err: asToolError(err)}
		}
		var st proto.State
		if err := ac.cl.Call(ctx, "state", nil, &st); err != nil {
			return result{session: ac.name, err: asToolError(err)}
		}
		b.WriteString(stateText(st))
		if sn.Truncated {
			fmt.Fprintf(&b, "note: lines before %d were already dropped\n", sn.First)
		}
		fmt.Fprintf(&b, "--- %d lines committed from cursor %d ---\n", len(sn.Lines), sn.First)
		if len(sn.Lines) > 0 {
			b.WriteString(strings.Join(sn.Lines, "\n") + "\n")
		}
		fmt.Fprintf(&b, "next_cursor: %d", sn.Cursor)
		r.status = "mode=since"
	default:
		return bad("mode must be screen or since")
	}
	r.text = b.String()
	return r
}

// typeRetry sends type or keys, retrying once when the person was typing
// a moment ago (the broker says how long to wait).
func typeRetry(ctx context.Context, ac *agentConn, op string, args any) (proto.Sent, error) {
	var sent proto.Sent
	err := ac.cl.Call(ctx, op, args, &sent)
	var pe *proto.Error
	if proto.ErrorCode(err) == proto.ErrPersonTyping {
		pe, _ = err.(*proto.Error)
	}
	if pe != nil && pe.RetryAfterMS > 0 && pe.RetryAfterMS <= 2000 {
		select {
		case <-time.After(time.Duration(pe.RetryAfterMS) * time.Millisecond):
		case <-ctx.Done():
			return sent, ctx.Err()
		}
		sent = proto.Sent{}
		err = ac.cl.Call(ctx, op, args, &sent)
	}
	return sent, err
}

func sentText(sent proto.Sent) string {
	t := fmt.Sprintf("sent: %d bytes", sent.Sent)
	if sent.HeldEnter {
		t += "\nheld_enter: true: the Enter waits for the person's approval (confirm policy); call term_wait with for=confirmation"
	} else {
		t += "\nSee the effect with term_wait (for=idle) or term_read."
	}
	return t
}

func (s *Server) termType(ctx context.Context, a typeArgs) result {
	if a.Text == "" && !a.Enter {
		return bad("text is empty")
	}
	ac, err := s.conn(ctx, a.Session)
	if err != nil {
		return errResult(err)
	}
	unlock, err := s.lockSession(ctx, ac.name)
	if err != nil {
		return result{session: ac.name, err: asToolError(err)}
	}
	defer unlock()
	sent, err := typeRetry(ctx, ac, "type", map[string]any{"text": a.Text, "enter": a.Enter})
	if err != nil {
		return result{session: ac.name, err: asToolError(err)}
	}
	return result{session: ac.name, status: fmt.Sprintf("sent=%d held=%v", sent.Sent, sent.HeldEnter), text: sentText(sent)}
}

func (s *Server) termKeys(ctx context.Context, a keysArgs) result {
	if len(a.Keys) == 0 || len(a.Keys) > 64 {
		return bad("keys: 1 to 64 key names")
	}
	ac, err := s.conn(ctx, a.Session)
	if err != nil {
		return errResult(err)
	}
	unlock, err := s.lockSession(ctx, ac.name)
	if err != nil {
		return result{session: ac.name, err: asToolError(err)}
	}
	defer unlock()
	sent, err := typeRetry(ctx, ac, "keys", map[string]any{"keys": a.Keys})
	if err != nil {
		return result{session: ac.name, err: asToolError(err)}
	}
	return result{session: ac.name, status: fmt.Sprintf("keys=%d held=%v", len(a.Keys), sent.HeldEnter), text: sentText(sent)}
}

func (s *Server) termMask(ctx context.Context, a maskArgs) result {
	if strings.TrimSpace(a.Name) == "" {
		return bad("name is empty")
	}
	ac, err := s.conn(ctx, a.Session)
	if err != nil {
		return errResult(err)
	}
	if err := ac.cl.Call(ctx, "mask", map[string]string{"name": a.Name}, nil); err != nil {
		return result{session: ac.name, err: asToolError(err)}
	}
	return result{session: ac.name, status: "masked",
		text: fmt.Sprintf("masked: from now on the secret %s reads [masked:%s] in everything you read from this session", a.Name, a.Name)}
}

func (s *Server) termRequestKeyboard(ctx context.Context, a sessionArg) result {
	ac, err := s.conn(ctx, a.Session)
	if err != nil {
		return errResult(err)
	}
	if err := ac.cl.Call(ctx, "request_keyboard", nil, nil); err != nil {
		return result{session: ac.name, err: asToolError(err)}
	}
	return result{session: ac.name, status: "requested",
		text: "requested: the person's status line shows that you ask for the keyboard. " +
			"Wait (term_wait with for=change, or term_read) until the state shows keyboard free; do not ask again in a loop."}
}

func (s *Server) state(ctx context.Context, ac *agentConn) (proto.State, error) {
	var st proto.State
	err := ac.cl.Call(ctx, "state", nil, &st)
	return st, err
}

// waitWatch runs a broker wait. With watchSecret, a secret prompt that is
// active or appears meanwhile ends the wait with reason secret_prompt
// (the broker's idle, prompt and regex waits would otherwise sit on it).
func (s *Server) waitWatch(ctx context.Context, ac *agentConn, wa proto.WaitArgs, watchSecret bool) (proto.WaitResult, error) {
	if watchSecret {
		st, err := s.state(ctx, ac)
		if err != nil {
			return proto.WaitResult{}, err
		}
		if st.SecretInput == proto.SecretActive {
			return proto.WaitResult{Reason: reasonSecretPrompt, State: st}, nil
		}
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(wa.TimeoutMS)*time.Millisecond+15*time.Second)
	defer cancel()
	type answer struct {
		r   proto.WaitResult
		err error
	}
	done := make(chan answer, 1)
	go func() {
		var r proto.WaitResult
		err := ac.cl.Call(cctx, "wait", wa, &r)
		done <- answer{r, err}
	}()
	if !watchSecret {
		a := <-done
		return a.r, a.err
	}
	tick := time.NewTicker(statePoll)
	defer tick.Stop()
	for {
		select {
		case a := <-done:
			return a.r, a.err
		case <-tick.C:
			st, err := s.state(ctx, ac)
			if err == nil && st.SecretInput == proto.SecretActive {
				return proto.WaitResult{Reason: reasonSecretPrompt, State: st}, nil
			}
		case <-ctx.Done():
			return proto.WaitResult{}, ctx.Err()
		}
	}
}

// screenTail returns the bottom of the agent's screen.
func screenTail(ctx context.Context, ac *agentConn, n int) string {
	var sc proto.Screen
	if ac.cl.Call(ctx, "screen", nil, &sc) != nil {
		return ""
	}
	rows, left := tail(trimBlank(sc.Rows), n)
	head := fmt.Sprintf("--- bottom of the screen (%d rows) ---\n", len(rows))
	if left > 0 {
		head = fmt.Sprintf("--- bottom of the screen (last %d rows; term_read shows all) ---\n", len(rows))
	}
	return head + strings.Join(rows, "\n")
}

func (s *Server) termWait(ctx context.Context, a waitArgs) result {
	switch a.For {
	case proto.WaitIdle, proto.WaitPrompt, proto.WaitChange, proto.WaitSecretEnded, proto.WaitConfirmation:
	case proto.WaitRegex:
		if a.Pattern == "" {
			return bad("for=regex needs pattern")
		}
	default:
		return bad("for must be idle, prompt, regex, change, secret_ended or confirmation")
	}
	ac, err := s.conn(ctx, a.Session)
	if err != nil {
		return errResult(err)
	}
	wa := proto.WaitArgs{For: a.For, TimeoutMS: timeoutOf(a.TimeoutS).Milliseconds(), IdleMS: int64(max(a.IdleMS, 0)), Pattern: a.Pattern}
	watch := a.For == proto.WaitIdle || a.For == proto.WaitPrompt || a.For == proto.WaitRegex
	wr, err := s.waitWatch(ctx, ac, wa, watch)
	if err != nil {
		return result{session: ac.name, err: asToolError(err)}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "matched: %v\nreason: %s\n", wr.Matched, wr.Reason)
	if wr.Match != "" {
		fmt.Fprintf(&b, "match: %q\n", wr.Match)
	}
	switch {
	case wr.Reason == reasonSecretPrompt:
		fmt.Fprintf(&b, "A secret prompt is waiting: %s, %s. Only the person types it. Tell the person what it is for, "+
			"then call term_wait with for=secret_ended.\n", programText(wr.State.SecretProgram), lockColour(wr.State.SecretProgram))
	case !wr.Matched && a.For == proto.WaitSecretEnded:
		b.WriteString("The person has not finished the secret prompt yet. Wait again, or ask them whether they want to go on.\n")
	case !wr.Matched && a.For == proto.WaitConfirmation:
		b.WriteString("The person has not answered your line yet. Wait again or ask them.\n")
	}
	b.WriteString(stateText(wr.State))
	b.WriteString(screenTail(ctx, ac, 20))
	return result{session: ac.name, status: fmt.Sprintf("for=%s matched=%v reason=%s", a.For, wr.Matched, wr.Reason), text: b.String()}
}

// termRun types a command with Enter and waits until the shell is back.
//
// "Back" means: no output for idle_ms, the foreground process group is
// the one that was in front when the command was typed (the shell), and,
// when the shell reports prompts (OSC 133), it is at its prompt. A secret
// prompt, private mode or a full-screen program end the wait early with
// their own status.
func (s *Server) termRun(ctx context.Context, a runArgs) result {
	cmd := strings.TrimRight(a.Command, "\r\n")
	if strings.TrimSpace(cmd) == "" {
		return bad("command is empty")
	}
	if strings.ContainsAny(cmd, "\r\n") {
		return bad("command must be one line; use term_type for multi-line input")
	}
	ac, err := s.conn(ctx, a.Session)
	if err != nil {
		return errResult(err)
	}
	fail := func(err error) result { return result{session: ac.name, err: asToolError(err)} }
	// The whole run holds the session's input lock: a parallel term_run or
	// term_type waits instead of typing into this command's output.
	unlock, err := s.lockSession(ctx, ac.name)
	if err != nil {
		return fail(err)
	}
	defer unlock()
	timeout := timeoutOf(a.TimeoutS)
	idle := 500 * time.Millisecond
	if a.IdleMS > 0 {
		idle = min(time.Duration(a.IdleMS)*time.Millisecond, 30*time.Second)
	}
	maxLines := 200
	if a.MaxLines > 0 {
		maxLines = min(a.MaxLines, 2000)
	}
	deadline := time.Now().Add(timeout)

	var sc0 proto.Screen
	if err := ac.cl.Call(ctx, "screen", nil, &sc0); err != nil {
		return fail(err)
	}
	start := runStart{cursor: sc0.CursorSince, row: sc0.Cursor.Row}
	if start.row >= 0 && start.row < len(sc0.Rows) {
		start.prompt = strings.TrimRight(sc0.Rows[start.row], " ")
	}
	shellPID := 0
	if sc0.State.Foreground != nil {
		shellPID = sc0.State.Foreground.PID
	}

	sent, err := typeRetry(ctx, ac, "type", map[string]any{"text": cmd, "enter": true})
	if err != nil {
		return fail(err)
	}
	typedAt := time.Now()

	status := ""
	waitingInput := false
	var st proto.State
	if sent.HeldEnter {
		var before proto.Screen
		_ = ac.cl.Call(ctx, "screen", nil, &before)
		wr, err := s.waitWatch(ctx, ac, proto.WaitArgs{For: proto.WaitConfirmation, TimeoutMS: time.Until(deadline).Milliseconds()}, false)
		if err != nil {
			return fail(err)
		}
		st = wr.State
		if !wr.Matched {
			status = statusConfirmation
		} else {
			// Accepted, the Enter moves the cursor on; rejected, the line
			// stays where it was.
			time.Sleep(300 * time.Millisecond)
			var after proto.Screen
			if err := ac.cl.Call(ctx, "screen", nil, &after); err != nil {
				return fail(err)
			}
			st = after.State
			switch wr.Match {
			case "denied":
				status = statusRejected
			case "accepted":
			default:
				// An older broker does not say: the Enter moves the cursor on.
				if after.Cursor.Row == before.Cursor.Row && after.CursorSince == before.CursorSince {
					status = statusRejected
				}
			}
			typedAt = time.Now()
		}
	}
	for status == "" {
		rem := time.Until(deadline)
		if rem <= 0 {
			status = statusRunning
			break
		}
		wr, err := s.waitWatch(ctx, ac, proto.WaitArgs{For: proto.WaitIdle, IdleMS: idle.Milliseconds(),
			TimeoutMS: min(rem, 5*time.Second).Milliseconds()}, true)
		if err != nil {
			return fail(err)
		}
		st = wr.State
		switch {
		case st.SecretInput == proto.SecretActive:
			status = statusSecretPrompt
		case st.Private:
			status = statusPrivate
		case st.PendingConfirmation != nil:
			status = statusConfirmation
		case wr.Matched && time.Since(typedAt) >= idle:
			back := shellPID == 0 || st.Foreground == nil || st.Foreground.PID == shellPID
			switch {
			case back && st.Shell.Integration && st.Shell.AtPrompt:
				status = statusDone
			case back && !st.Shell.Integration:
				// Without prompt marks a quiet shell in front may still be
				// running a builtin that waits for input (read x): done
				// only when the cursor sits at a fresh prompt.
				// With no foreground to go by, only the prompt seen before
				// the command counts (a progress line ending in % is not one).
				strict := shellPID == 0 || st.Foreground == nil
				fresh, err := freshPrompt(ctx, ac, start, strict)
				if err != nil {
					return fail(err)
				}
				if fresh {
					status = statusDone
				} else {
					status, waitingInput = statusRunning, true
				}
			case st.AltScreen:
				status = statusInteractive
			}
		}
		if status == "" && wr.Matched {
			// Quiet, but a program is still in front: wait for output (or a
			// short while) instead of spinning on idle.
			if _, err := s.waitWatch(ctx, ac, proto.WaitArgs{For: proto.WaitChange,
				TimeoutMS: max(min(time.Until(deadline), idle), time.Millisecond).Milliseconds()}, false); err != nil {
				return fail(err)
			}
		}
	}

	var out string
	var next int64
	if status == statusInteractive {
		// The full-screen program's screen is the useful part.
		out, next = screenTail(ctx, ac, maxLines)+"\n", st.CursorSince
	} else if out, next, err = s.collect(ctx, ac, start, maxLines, status == statusDone); err != nil {
		return fail(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "status: %s\n", status)
	switch status {
	case statusDone:
		if st.Shell.Integration && st.Shell.ExitCode != nil {
			fmt.Fprintf(&b, "exit_code: %d (reported by the shell)\n", *st.Shell.ExitCode)
		} else {
			b.WriteString("exit_code: unknown (the shell does not report it; run `echo $?` if you need it)\n")
		}
	case statusSecretPrompt:
		fmt.Fprintf(&b, "A secret prompt is waiting: %s, %s. Only the person types secrets; you cannot and must not. "+
			"Tell the person what the prompt is for, then call term_wait with for=secret_ended (timeout_s up to 300). "+
			"After it ends, call term_wait with for=prompt, or term_read, to see the result.\n",
			programText(st.SecretProgram), lockColour(st.SecretProgram))
	case statusConfirmation:
		b.WriteString("The line waits for the person's approval. Call term_wait with for=confirmation, then term_read.\n")
	case statusRejected:
		b.WriteString("The person rejected the line: it did not run and is still typed at the prompt. " +
			"Clear it with term_keys [\"C-c\"] if needed, and ask the person before trying again.\n")
	case statusRunning:
		if waitingInput {
			b.WriteString("The shell is in front and quiet, but the cursor is not at a fresh prompt: the command (for example a " +
				"shell builtin such as `read`) may be waiting for input. Read the output below and decide: term_type to answer, " +
				"term_wait to keep waiting, term_keys [\"C-c\"] to stop it.\n")
		} else {
			fmt.Fprintf(&b, "Still running, or waiting for input, after %s. Read the output below and decide: "+
				"term_wait to keep waiting, term_type to answer a question, term_keys [\"C-c\"] to stop it.\n", timeout)
		}
	case statusInteractive:
		b.WriteString("A full-screen program took over the terminal. Use term_read to see it and term_keys to drive it.\n")
	case statusPrivate:
		b.WriteString("The person turned on private mode: your view is frozen and input is refused. Wait until it is off (term_wait with for=change).\n")
	}
	b.WriteString(out)
	fmt.Fprintf(&b, "next_cursor for term_read mode=since: %d\n", next)
	b.WriteString(stateText(st))
	return result{session: ac.name, status: "status=" + status, text: strings.TrimRight(b.String(), "\n")}
}

// promptEnds are the characters a shell prompt usually ends with.
const promptEnds = "$#%>❯➜»λ"

// freshPrompt reports whether the cursor sits at what looks like a new
// shell prompt (used without shell integration): it left the command line
// and the text before it is the prompt seen before the command, or ends
// like a prompt, with nothing after it. Conservative: a question such as
// "Name: " or "[y/N] ", or an empty line (read x), is not a prompt. strict
// accepts only the prompt seen before the command.
func freshPrompt(ctx context.Context, ac *agentConn, start runStart, strict bool) (bool, error) {
	var sc proto.Screen
	if err := ac.cl.Call(ctx, "screen", nil, &sc); err != nil {
		return false, err
	}
	if sc.Cursor.Row < 0 || sc.Cursor.Row >= len(sc.Rows) {
		return false, nil
	}
	if sc.CursorSince == start.cursor && sc.Cursor.Row == start.row {
		return false, nil // still on the command line
	}
	row := strings.TrimRight(sc.Rows[sc.Cursor.Row], " ")
	if row == "" || sc.Cursor.Col < len([]rune(row)) {
		return false, nil // nothing before the cursor, or text after it
	}
	if start.prompt != "" && row == strings.TrimRight(start.prompt, " ") {
		return true, nil
	}
	if strict {
		return false, nil
	}
	r := []rune(row)
	return strings.ContainsRune(promptEnds, r[len(r)-1]), nil
}

// runStart is where the agent's view was when a command was typed.
type runStart struct {
	cursor int64  // since cursor
	row    int    // cursor row (the prompt line)
	prompt string // the prompt line's text before typing
}

// collect returns the output of a command typed at start: the lines
// committed since then followed by the screen, from the row after the
// command line. Committed lines are the top rows of the earlier screen in
// order, so the prompt row keeps its index in that sequence unless the
// screen was cleared or resized; then everything since start is returned.
func (s *Server) collect(ctx context.Context, ac *agentConn, start runStart, maxLines int, dropPrompt bool) (string, int64, error) {
	var sn proto.Since
	if err := ac.cl.Call(ctx, "since", map[string]any{"cursor": start.cursor, "limit": 5000}, &sn); err != nil {
		return "", 0, err
	}
	var sc proto.Screen
	if err := ac.cl.Call(ctx, "screen", nil, &sc); err != nil {
		return "", 0, err
	}
	// Lines committed between the two reads: fetch them, so the screen
	// follows the committed lines without a hole.
	if gap := sc.CursorSince - sn.Cursor; gap > 0 && gap <= 5000 {
		var more proto.Since
		if err := ac.cl.Call(ctx, "since", map[string]any{"cursor": sn.Cursor, "limit": gap}, &more); err != nil {
			return "", 0, err
		}
		sn.Lines = append(sn.Lines, more.Lines...)
		sn.Wrapped = append(sn.Wrapped, more.Wrapped...)
	}
	all := append(append([]string(nil), sn.Lines...), sc.Rows...)
	wrapped := append(append([]bool(nil), sn.Wrapped...), sc.Wrapped...)
	from := 0
	aligned := !sn.Truncated && sn.First == start.cursor && start.row < len(all) &&
		start.prompt != "" && strings.HasPrefix(strings.TrimRight(all[start.row], " "), start.prompt)
	if aligned {
		from = start.row
		for from < len(wrapped) && from < len(all)-1 && wrapped[from] {
			from++
		}
		from++
	}
	out := trimBlank(all[min(from, len(all)):])
	if dropPrompt && len(out) > 0 && start.prompt != "" && strings.TrimRight(out[len(out)-1], " ") == start.prompt {
		out = out[:len(out)-1]
	}
	out, left := tail(out, maxLines)
	var b strings.Builder
	switch {
	case left > 0:
		fmt.Fprintf(&b, "--- output, last %d lines (%d earlier lines left out; term_read mode=since cursor=%d has them) ---\n", len(out), left, start.cursor)
	case !aligned:
		b.WriteString("--- output (the screen moved; this includes lines from before the command) ---\n")
	default:
		fmt.Fprintf(&b, "--- output (%d lines) ---\n", len(out))
	}
	if len(out) > 0 {
		b.WriteString(strings.Join(out, "\n") + "\n")
	}
	return b.String(), sc.CursorSince, nil
}
