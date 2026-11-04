package attach

import (
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/x/ansi"

	"github.com/openbasalt/cotty/internal/proto"
)

// Status line colours (SGR).
const (
	sgrBar     = "\x1b[0;38;5;252;48;5;236m"
	sgrGreen   = "\x1b[0;1;30;42m"
	sgrAmber   = "\x1b[0;1;30;48;5;214m"
	sgrPrivate = "\x1b[0;1;97;45m"
	sgrHeld    = "\x1b[0;1;30;46m"
	sgrAlert   = "\x1b[0;1;97;41m"
	sgrAsk     = "\x1b[0;1;30;43m"
	sgrDim     = "\x1b[0;38;5;245;48;5;236m"
)

// segment is one piece of the status line.
type segment struct {
	sgr  string
	text string
}

// uiState is what the attach client adds to the broker's status.
type uiState struct {
	session  string
	prefix   bool      // the hotkey prefix was typed
	message  string    // transient note (help, code, errors)
	msgUntil time.Time // when the note disappears
	now      time.Time
}

// statusSegments builds the status line from the broker's status. It is
// drawn by cotty in the last row, which the session cannot write to (see
// filter), so a program cannot fake the lock.
func statusSegments(st proto.Status, ui uiState) []segment {
	var segs []segment
	add := func(sgr, text string) { segs = append(segs, segment{sgr, text}) }
	// The oldest attach request comes first, as one bounded segment, so
	// many requests (or long names) cannot push it, or the lock, out of
	// the line; it is the one ^] a and ^] x act on.
	if r, ok := oldestRequest(st.PendingAttach); ok {
		more := ""
		if n := len(st.PendingAttach) - 1; n > 0 {
			more = " +" + itoa(n) + " more"
		}
		add(sgrAlert, " attach request: pid "+itoa(r.PID)+" "+clip(baseName(r.Exe), 24)+" "+clip(r.TTY, 16)+
			parents(r.Chain)+" (^] a allow, ^] x deny)"+more+" ")
	}
	add(sgrBar, " cotty:"+clip(ui.session, 24)+" ")
	if st.SecretInput == proto.SecretActive && st.SecretProgram != nil {
		p := st.SecretProgram
		name := clip(p.Name, 24)
		if name == "" {
			name = "?"
		}
		note := ""
		forParent := ""
		if p.Parent != "" {
			forParent = ", for " + clip(p.Parent, 24)
		}
		switch {
		case p.Exception:
			note = " (exception" + forParent + ")"
		case p.Outside:
			note = " (outside the session" + forParent + ")"
		}
		if p.AgentStarted {
			note += " (started by agent)"
		}
		if p.Trust == proto.TrustSystem {
			add(sgrGreen, " LOCK "+name+note+" ")
		} else {
			add(sgrAmber, " LOCK "+name+" (not a system program)"+note+" ")
		}
	}
	if st.Private {
		add(sgrPrivate, " PRIVATE ")
	}
	if st.PendingConfirmation != nil {
		pc := st.PendingConfirmation
		if pc.Mismatch {
			// The line on screen does not end with what the agent sent:
			// show the agent's own text and advise to deny.
			add(sgrAlert, " agent typed: "+printable(pc.Typed)+" but the line shows: "+printable(pc.Line)+" (^] n) ")
		} else {
			add(sgrAsk, " agent wants to run: "+printable(pc.Line)+" (^] y / ^] n) ")
		}
	}
	if st.Keyboard == proto.KeyboardHeld {
		add(sgrHeld, " KEYBOARD: you ")
	}
	if st.AgentRequestsKeyboard {
		// Shown while the person holds the keyboard too: that is exactly
		// when the agent needs it.
		add(sgrAsk, " agent asks for the keyboard (^] k gives it) ")
	}
	if st.WeakAgents > 0 {
		add(sgrAlert, " "+plural(st.WeakAgents, "unconfined agent")+" (not started with cotty agent) ")
	}
	if st.RefusedAgents > 0 {
		add(sgrAsk, " refused "+plural(st.RefusedAgents, "unconfined agent")+" ")
	}
	if st.AgentText != "" && st.AgentActiveAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, st.AgentActiveAt); err == nil && ui.now.Sub(t) < 4*time.Second {
			add(sgrBar, " agent> "+printable(st.AgentText)+" ")
		}
	}
	if ui.prefix {
		add(sgrAsk, " ^] ... k p y n a x s c d ? ")
	}
	if ui.message != "" && ui.now.Before(ui.msgUntil) {
		add(sgrAsk, " "+ui.message+" ")
	}
	right := " agents:" + itoa(st.Agents)
	if !st.Shared {
		right = " not shared"
	} else if st.RequireConfined {
		right += " confined-only"
	}
	add(sgrDim, right+" "+st.Assurance+" ")
	return segs
}

// oldestRequest returns the pending attach request with the lowest ID
// (the broker numbers requests in order); the list's order is not
// meaningful.
func oldestRequest(reqs []proto.AttachRequest) (proto.AttachRequest, bool) {
	if len(reqs) == 0 {
		return proto.AttachRequest{}, false
	}
	o := reqs[0]
	for _, r := range reqs[1:] {
		if r.ID < o.ID {
			o = r
		}
	}
	return o, true
}

// renderStatus lays the segments out in width terminal cells: the leading
// segments are kept, the last one (agents and assurance) is right
// aligned when there is room. Widths are display cells (wide characters
// take two).
func renderStatus(segs []segment, width int) string {
	if width <= 0 {
		return ""
	}
	var b strings.Builder
	used := 0
	last := segs[len(segs)-1]
	last.text = printable(last.text)
	lastW := cells(last.text)
	for _, s := range segs[:len(segs)-1] {
		room := width - used
		if room <= 0 {
			break
		}
		t := truncate(printable(s.text), room)
		b.WriteString(s.sgr)
		b.WriteString(t)
		used += cells(t)
	}
	if used+lastW <= width {
		b.WriteString(sgrBar)
		b.WriteString(strings.Repeat(" ", width-used-lastW))
		b.WriteString(last.sgr)
		b.WriteString(last.text)
	} else if used < width {
		b.WriteString(sgrBar)
		b.WriteString(strings.Repeat(" ", width-used))
	}
	b.WriteString("\x1b[0m")
	return b.String()
}

// cells is the display width of plain text (no escape sequences).
func cells(s string) int { return ansi.StringWidthWc(s) }

// truncate cuts s to at most n cells, marking the cut with '>'. A wide
// character that does not fit whole is dropped and the line padded, so
// the result is never wider than n.
func truncate(s string, n int) string {
	if cells(s) <= n {
		return s
	}
	if n <= 1 {
		t := ansi.TruncateWc(s, n, "")
		return t + strings.Repeat(" ", n-cells(t))
	}
	t := ansi.TruncateWc(s, n-1, "")
	return t + strings.Repeat(" ", n-1-cells(t)) + ">"
}

// clip bounds an untrusted name to n cells.
func clip(s string, n int) string { return truncate(printable(s), n) }

// printable drops control characters from text shown in the status line,
// so agent text cannot inject escape sequences into the person's terminal,
// and the characters that take no cell or reorder text (format characters
// such as bidi overrides and zero-width joiners, combining marks, line
// and paragraph separators, private use and invalid code points), so an
// untrusted name cannot make the line wider or narrower than measured.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0xfffd ||
			unicode.In(r, unicode.Cc, unicode.Cf, unicode.Mn, unicode.Me, unicode.Zl, unicode.Zp,
				unicode.Co, unicode.Cs) {
			return -1
		}
		return r
	}, s)
}

// plural renders "1 thing" or "N things".
func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return itoa(n) + " " + what + "s"
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// parents names the first two processes above an attach requester
// ("via script < bash"): every attach runs cotty, so the parent tells an
// agent's `script -c 'cotty attach S'` from the person's own terminal
// (review A3). Chain entries are "pid name".
func parents(chain []string) string {
	var names []string
	for _, c := range chain {
		if len(names) == 2 {
			break
		}
		_, name, _ := strings.Cut(c, " ")
		if name == "" {
			name = "?"
		}
		names = append(names, clip(name, 16))
	}
	if len(names) == 0 {
		return ""
	}
	return " via " + strings.Join(names, " < ")
}
