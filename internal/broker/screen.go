package broker

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
)

// maxCommitted is how many committed (scrolled off) lines the broker
// keeps for since reads.
const maxCommitted = 20000

// privateText replaces text written during private mode in agent reads.
const privateText = "[private]"

// line is one committed line.
type line struct {
	text    string
	full    bool // the last column was written (candidate for a soft wrap)
	private bool // committed while private mode was on
}

// Model is the session's screen: a charmbracelet/x/vt emulator (see
// docs/vt.md) plus what cotty adds on top: an absolute counter of
// committed lines, private mode taint, OSC 133 marks and mode tracking for
// the person's attach snapshot. All methods are safe for concurrent use.
type Model struct {
	mu   sync.Mutex
	emu  *vt.Emulator
	rows int
	cols int

	committed []line
	first     int64 // absolute number of committed[0]
	next      int64 // absolute number of the next committed line

	decModes map[int]bool
	alt      bool

	// private mode: on while the person's private mode (privPerson) or
	// secret input (privSecret) is on
	private    bool
	privPerson bool
	privSecret bool
	frozen     *frozenView
	// Private mode taint lives in the emulator's cells (taintMark, see
	// markCell): every cell of a row that shows text written during
	// private mode carries the mark. The emulator moves cells with their
	// marks whatever moves them (scrolling into the scrollback, insert
	// and delete line, reverse index, scroll regions, insert and delete
	// character), and a cell loses its mark only when something is
	// written over it or it is erased. A row reads [private] while any of
	// its cells is marked, so it is shown again only once every column
	// was rewritten or erased: what it held cannot be learnt column by
	// column. Rows are never compared by text (review N4, N5).
	marked bool // a taint mark was ever set (lets reads skip the scan)
	// mainUnseen: the alternate screen was entered during private mode,
	// so the main screen may hold private text not marked yet; it is
	// marked when the main screen is shown again.
	mainUnseen bool

	// OSC 133 shell integration
	shell       shellMarks
	marksSeen   int64 // counter of A and D marks, for wait prompt
	promptMarks int64 // counter of A marks (live, for the broker)

	// replies holds what the emulator answers to queries (DA, DSR);
	// the broker forwards it to the PTY when no person is attached.
	replies func([]byte)

	resets int // emulator panics recovered
}

type frozenView struct {
	rows    []string
	wrapped []bool
	cursor  [3]int // row, col, visible
	since   int64
	alt     bool
	cols    int
	// shell and marks are the OSC 133 state when private mode began:
	// agents see these until it ends (review B1).
	shell shellMarks
	marks int64
}

type shellMarks struct {
	integration bool
	atPrompt    bool
	cmdStart    [2]int // cursor at mark B (row, col)
	haveStart   bool
	lastCommand string
	exitCode    *int
}

// NewModel returns a model of the given size.
func NewModel(rows, cols int, replies func([]byte)) *Model {
	m := &Model{rows: rows, cols: cols, decModes: map[int]bool{}, replies: replies}
	m.reset()
	return m
}

// reset builds a fresh emulator (start, and after a recovered panic).
func (m *Model) reset() {
	if m.emu != nil {
		stopEmu(m.emu)
	}
	e := vt.NewEmulator(m.cols, m.rows)
	// Committed lines are drained after every write, so the emulator's own
	// scrollback only has to hold what one write scrolls.
	e.SetScrollbackSize(100000)
	e.SetCallbacks(vt.Callbacks{
		AltScreen: func(on bool) { m.onAltScreen(on) },
		EnableMode: func(mode ansi.Mode) {
			if d, ok := mode.(ansi.DECMode); ok {
				m.decModes[int(d)] = true
			}
		},
		DisableMode: func(mode ansi.Mode) {
			if d, ok := mode.(ansi.DECMode); ok {
				delete(m.decModes, int(d))
			}
		},
	})
	e.RegisterOscHandler(133, func(data []byte) bool {
		m.handleOSC133(data)
		return true
	})
	m.emu = e
	m.alt = false
	m.mainUnseen = false
	go func(e *vt.Emulator) {
		buf := make([]byte, 4096)
		for {
			n, err := e.Read(buf)
			if n > 0 && m.replies != nil {
				m.replies(bytes.Clone(buf[:n]))
			}
			if err != nil {
				return
			}
		}
	}(e)
}

// Write feeds program output to the model. A panic inside the emulator
// (a crafted escape sequence can trigger one, see docs/vt.md) is
// recovered: the emulator is rebuilt empty and the error returned.
func (m *Model) Write(p []byte) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			m.resets++
			m.reset()
			err = fmt.Errorf("vt emulator panic recovered (screen reset): %v", r)
		}
	}()
	pieces := [][]byte{p}
	if m.private {
		pieces = splitBeforeModes(p)
	}
	for _, piece := range pieces {
		_, _ = m.emu.Write(piece)
		m.drain()
		if m.private {
			m.markPrivateLocked()
		}
	}
	return nil
}

// splitBeforeModes cuts p before each private mode sequence (CSI ? Pm h
// or l, in 7-bit and 8-bit form), so during private mode the model looks
// at the main screen right before the alternate screen can replace it:
// text written to the main screen and the switch in one chunk is marked.
// The emulator parses a stream, so any cut is safe; a cut in the wrong
// place (inside a string) only adds a look.
func splitBeforeModes(p []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 1; i < len(p); i++ {
		cut := p[i] == 0x9b || p[i] == 0x1b && i+2 < len(p) && p[i+1] == '[' && p[i+2] == '?'
		if cut && i > start {
			out = append(out, p[start:i])
			start = i
		}
	}
	return append(out, p[start:])
}

// Marks set on cells (see Model). They live in the cell's hyperlink
// parameters, which the emulator copies with the cell. They start with a
// C0 control: the emulator's OSC parser drops C0 bytes inside a string,
// so a program cannot set (forge) them with OSC 8. Snapshot removes them.
const (
	taintMark = "\x01cotty-private"
	preMark   = "\x01cotty-pre" // the cell was on screen when private mode began
)

func hasMark(c *uv.Cell, mark string) bool {
	return c != nil && strings.Contains(c.Link.Params, mark)
}

func addMark(c *uv.Cell, mark string) {
	if c != nil && !strings.Contains(c.Link.Params, mark) {
		c.Link.Params += mark
	}
}

func blankCell(c *uv.Cell) bool {
	return c == nil || c.Content == "" || c.Content == " "
}

// lineMarked reports whether a line holds a cell with the taint mark.
func lineMarked(l uv.Line) bool {
	for i := range l {
		if hasMark(&l[i], taintMark) {
			return true
		}
	}
	return false
}

// onAltScreen is the emulator's alternate screen callback (called inside
// Write, with m.mu held).
func (m *Model) onAltScreen(on bool) {
	if on == m.alt {
		return
	}
	m.alt = on
	switch {
	case on && m.private:
		// Write cuts the chunk before the switch, so the main screen was
		// marked right before it; this covers a switch the cut missed.
		m.mainUnseen = true
	case !on && m.mainUnseen:
		// The main screen is shown again (the callback runs after the
		// switch): mark what was written to it during private mode.
		m.mainUnseen = false
		m.markPrivateLocked()
	}
}

// drain moves lines from the emulator's scrollback to the committed
// buffer, with absolute numbers. A line is private when it leaves the
// screen during private mode or holds a marked cell.
func (m *Model) drain() {
	sb := m.emu.Scrollback()
	if sb == nil || sb.Len() == 0 {
		return
	}
	for _, l := range sb.Lines() {
		text, full := lineText(l, m.cols)
		priv := m.private || m.marked && lineMarked(l)
		m.committed = append(m.committed, line{text: text, full: full, private: priv})
		m.next++
	}
	sb.Clear()
	if over := len(m.committed) - maxCommitted; over > 0 {
		m.committed = append(m.committed[:0:0], m.committed[over:]...)
		m.first += int64(over)
	}
}

// lineText renders cells as text: wide characters once, never-written
// cells as spaces, trailing spaces trimmed. full reports whether the last
// column holds a character.
func lineText(l uv.Line, cols int) (string, bool) {
	var b strings.Builder
	col := 0
	for i := 0; i < len(l); {
		c := &l[i]
		if c.Content == "" {
			b.WriteByte(' ')
			i++
			col++
			continue
		}
		b.WriteString(c.Content)
		w := max(c.Width, 1)
		i += w
		col += w
	}
	s := strings.TrimRight(b.String(), " ")
	return s, len(l) >= cols && cols > 0 && l[cols-1].Content != "" && l[cols-1].Content != " " ||
		(len(l) >= cols && cols > 1 && l[cols-2].Width == 2)
}

func (m *Model) rowText(y int) (string, bool) {
	l := make(uv.Line, m.cols)
	for x := 0; x < m.cols; x++ {
		if c := m.emu.CellAt(x, y); c != nil {
			l[x] = *c
		}
	}
	return lineText(l, m.cols)
}

// screenRows returns the rendered rows and their wrap flags. A row is
// marked wrapped when its last column is written and the next row is not
// empty: x/vt does not record soft wraps, see docs/vt.md.
func (m *Model) screenRows() ([]string, []bool) {
	rows := make([]string, m.rows)
	full := make([]bool, m.rows)
	for y := 0; y < m.rows; y++ {
		rows[y], full[y] = m.rowText(y)
	}
	wrapped := make([]bool, m.rows)
	for y := 0; y+1 < m.rows; y++ {
		wrapped[y] = full[y] && rows[y+1] != ""
	}
	return rows, wrapped
}

// SetPrivate turns the person's private mode on or off.
func (m *Model) SetPrivate(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.privPerson = on
	m.setHiddenLocked(m.privPerson || m.privSecret)
}

// SetSecretInput hides the screen from agents while a secret prompt is
// active, as private mode does: their view is frozen, and rows written
// meanwhile (the marks a prompt prints per key, such as sudo-rs's
// asterisks, which tell the password's length and timing) read
// [private] afterwards.
func (m *Model) SetSecretInput(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.privSecret = on
	m.setHiddenLocked(m.privPerson || m.privSecret)
}

// setHiddenLocked freezes the agent's view and starts marking rows, or
// stops.
func (m *Model) setHiddenLocked(on bool) {
	if on == m.private {
		return
	}
	if on {
		// The snapshot is the agent's live view, never the raw rows: rows
		// hidden by an earlier private mode stay hidden while frozen, and
		// the cursor column on such a row is not kept (review T1).
		rows, wrapped, onPrivate := m.agentLiveRowsLocked()
		m.frozen = &frozenView{rows: rows, wrapped: wrapped, since: m.next, alt: m.alt, cols: m.cols}
		p := m.emu.CursorPosition()
		col := p.X
		if onPrivate {
			col = 0
		}
		m.frozen.cursor = [3]int{p.Y, col, boolInt(!m.emu.CursorHidden())}
		m.frozen.shell, m.frozen.marks = m.shell, m.marksSeen
		// A command line started before private mode is finished during it:
		// never record it.
		m.shell.haveStart = false
		// What is on screen now was readable before: mark it, so only
		// cells written from now on taint their row.
		for y := 0; y < m.rows; y++ {
			for x := 0; x < m.cols; x++ {
				addMark(m.emu.CellAt(x, y), preMark)
			}
		}
		m.private = true
		return
	}
	m.markPrivateLocked()
	m.private = false
	m.frozen = nil
}

// markPrivateLocked marks, on the screen shown now, every row that shows
// text written during private mode: a visible cell without the pre mark.
// All the row's cells get the taint mark, the blank ones too, so the row
// reads [private] until every column of it was rewritten or erased.
func (m *Model) markPrivateLocked() {
	for y := 0; y < m.rows; y++ {
		written := false
		for x := 0; x < m.cols && !written; x++ {
			c := m.emu.CellAt(x, y)
			written = !blankCell(c) && !hasMark(c, preMark)
		}
		if !written {
			continue
		}
		for x := 0; x < m.cols; x++ {
			addMark(m.emu.CellAt(x, y), taintMark)
		}
		m.marked = true
	}
}

// rowMarkedLocked reports whether row y of the screen shown now holds a
// cell with the taint mark.
func (m *Model) rowMarkedLocked(y int) bool {
	if !m.marked {
		return false
	}
	for x := 0; x < m.cols; x++ {
		if hasMark(m.emu.CellAt(x, y), taintMark) {
			return true
		}
	}
	return false
}

// agentLiveRowsLocked returns the live rows and wrap flags with the
// rows that hold private mode text replaced, and whether the cursor row
// is one of them.
func (m *Model) agentLiveRowsLocked() ([]string, []bool, bool) {
	rows, wrapped := m.screenRows()
	cy := m.emu.CursorPosition().Y
	cursorHidden := false
	for i := range rows {
		if !m.rowMarkedLocked(i) {
			continue
		}
		rows[i] = privateText
		wrapped[i] = false
		if i > 0 {
			wrapped[i-1] = false
		}
		if i == cy {
			cursorHidden = true
		}
	}
	return rows, wrapped, cursorHidden
}

// AgentScreen is the agent's view of the screen (before masking).
type AgentScreen struct {
	Rows        []string
	Wrapped     []bool
	Row, Col    int
	Visible     bool
	AltScreen   bool
	Cols        int
	Context     []string // committed lines right above the screen (the context a reader asked for)
	ContextWrap []bool
	Above       []string // committed lines above Context: matching context for the masker only
	AboveWrap   []bool
	CursorSince int64
	Private     bool
}

// AgentView returns the rows an agent may see: the frozen snapshot while
// private mode is on, rows written during private mode replaced.
func (m *Model) AgentView(context int) AgentScreen {
	return m.ReadScreen(context, Depth{})
}

// Depth is how much masking context a read takes: at least Lines lines,
// and more lines until they hold at least Bytes bytes (a long value
// printed on many short lines, review N24).
type Depth struct {
	Lines int
	Bytes int
}

// ReadScreen is AgentView plus the committed lines before the context
// that above asks for, all taken under one lock so they fit together.
// While private mode is on the context ends where the frozen view begins.
func (m *Model) ReadScreen(context int, above Depth) AgentScreen {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.agentRowsLocked()
	if context > 0 {
		v.Context, v.ContextWrap = m.rangeLocked(v.CursorSince-int64(context), v.CursorSince)
	}
	top := v.CursorSince - int64(len(v.Context))
	if from := m.backLocked(top, above); from < top {
		v.Above, v.AboveWrap = m.rangeLocked(from, top)
	}
	return v
}

// agentRowsLocked returns the screen part of the agent's view.
func (m *Model) agentRowsLocked() AgentScreen {
	if f := m.frozen; f != nil {
		return AgentScreen{Rows: append([]string(nil), f.rows...), Wrapped: append([]bool(nil), f.wrapped...),
			Row: f.cursor[0], Col: f.cursor[1], Visible: f.cursor[2] == 1, AltScreen: f.alt, Cols: f.cols,
			CursorSince: f.since, Private: true}
	}
	rows, wrapped, onPrivate := m.agentLiveRowsLocked()
	p := m.emu.CursorPosition()
	v := AgentScreen{Row: p.Y, Col: p.X, Visible: !m.emu.CursorHidden(), AltScreen: m.alt, Cols: m.cols, CursorSince: m.next}
	if onPrivate {
		v.Col = 0 // the column would tell the length of the hidden text
	}
	v.Rows, v.Wrapped = rows, wrapped
	return v
}

// backLocked returns where context of depth d ending before line top
// starts.
func (m *Model) backLocked(top int64, d Depth) int64 {
	top = min(top, m.endLocked())
	from := top - int64(d.Lines)
	n := 0
	i := top
	for i > m.first && (i > from || n < d.Bytes) {
		i--
		n += len(m.committed[i-m.first].text) + 1
	}
	return min(i, top)
}

// forwardLocked returns where context of depth d starting at line from
// ends (the end may be past the committed lines: the screen follows).
func (m *Model) forwardLocked(from int64, d Depth) int64 {
	from = max(from, m.first)
	to := from + int64(d.Lines)
	end := m.endLocked()
	n := 0
	i := from
	for i < end && (i < to || n < d.Bytes) {
		n += len(m.committed[i-m.first].text) + 1
		i++
	}
	if i == end {
		return max(to, end)
	}
	return i
}

// Since returns committed lines from cursor on (before masking): lines,
// wrap flags, next cursor, first returned number, truncated.
func (m *Model) Since(cursor int64, limit int) ([]string, []bool, int64, int64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sinceLocked(cursor, limit)
}

// SinceRead is a since read with its matching context.
type SinceRead struct {
	Lines     []string
	Wrapped   []bool
	Next      int64
	First     int64
	Truncated bool
	// Before: the committed lines before First (masker context only).
	Before     []string
	BeforeWrap []bool
	// After: what follows the read in the terminal now, the next committed
	// lines and, when they reach it, the agent's screen (masker context
	// only).
	After     []string
	AfterWrap []bool
}

// ReadSince returns a since read with the committed lines before it and
// behind it that the depths ask for, followed by the agent's screen when
// those reach the end, all under one lock: a value cut by either edge of
// a paged read is masked on both sides.
func (m *Model) ReadSince(cursor int64, limit int, before, after Depth) SinceRead {
	m.mu.Lock()
	defer m.mu.Unlock()
	var r SinceRead
	r.Lines, r.Wrapped, r.Next, r.First, r.Truncated = m.sinceLocked(cursor, limit)
	r.Before, r.BeforeWrap = m.rangeLocked(m.backLocked(r.First, before), r.First)
	to := m.forwardLocked(r.Next, after)
	r.After, r.AfterWrap = m.rangeLocked(r.Next, to)
	if to >= m.endLocked() {
		v := m.agentRowsLocked()
		r.After = append(r.After, v.Rows...)
		r.AfterWrap = append(r.AfterWrap, v.Wrapped...)
	}
	return r
}

// endLocked is the end of the committed lines an agent may read: where
// the frozen view begins while private mode is on.
func (m *Model) endLocked() int64 {
	if m.frozen != nil {
		return m.frozen.since
	}
	return m.next
}

func (m *Model) sinceLocked(cursor int64, limit int) ([]string, []bool, int64, int64, bool) {
	end := m.endLocked()
	truncated := false
	if cursor < m.first {
		truncated = m.first > 0
		cursor = m.first
	}
	if cursor > end {
		cursor = end
	}
	stop := end
	if limit > 0 && stop-cursor > int64(limit) {
		stop = cursor + int64(limit)
	}
	lines, wrapped := m.rangeLocked(cursor, stop)
	return lines, wrapped, stop, cursor, truncated
}

// rangeLocked returns the agent's view of committed lines [from, to),
// clipped to what is kept and to the end an agent may read.
func (m *Model) rangeLocked(from, to int64) ([]string, []bool) {
	from = max(from, m.first)
	to = min(to, m.endLocked())
	var lines []string
	var wrapped []bool
	for n := from; n < to; n++ {
		l := m.committed[n-m.first]
		if l.private {
			lines = append(lines, privateText)
			wrapped = append(wrapped, false)
			continue
		}
		lines = append(lines, l.text)
		wrapped = append(wrapped, l.full && m.nextNonEmptyLocked(n))
	}
	return lines, wrapped
}

// nextNonEmptyLocked reports whether what follows committed line n in the
// agent's view is not empty (the wrap rule, docs/vt.md). During private
// mode that is the frozen view's top row, never the live screen.
func (m *Model) nextNonEmptyLocked(n int64) bool {
	end := m.endLocked()
	if n+1 < end {
		nl := m.committed[n+1-m.first]
		return nl.text != "" && !nl.private
	}
	if m.frozen != nil {
		return len(m.frozen.rows) > 0 && m.frozen.rows[0] != ""
	}
	if m.rowMarkedLocked(0) {
		return true // reads [private]: never tell whether the hidden row is empty
	}
	r, _ := m.rowText(0)
	return r != ""
}

// CursorLine returns the text of the cursor's row, joined with the rows
// above it that wrap into it (the logical line being edited), as agents
// may read it: from the live screen (never the frozen view, so a line
// changed during private mode does not look unchanged), rows that hold
// private mode text replaced (review N13).
func (m *Model) CursorLine() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows, wrapped, _ := m.agentLiveRowsLocked()
	y := m.emu.CursorPosition().Y
	if y < 0 || y >= len(rows) {
		return ""
	}
	start := y
	for start > 0 && wrapped[start-1] {
		start--
	}
	return strings.TrimSpace(strings.Join(rows[start:y+1], ""))
}

// CursorSince is the committed line counter agents see (frozen while
// private mode is on).
func (m *Model) CursorSince() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.frozen != nil {
		return m.frozen.since
	}
	return m.next
}

// Resize changes the screen size.
func (m *Model) Resize(rows, cols int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rows == m.rows && cols == m.cols {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			m.resets++
			m.reset()
		}
	}()
	// x/vt cuts or pads rows on a resize, it does not re-wrap them: the
	// cells keep their marks, so a row cut by the resize stays private.
	m.rows, m.cols = rows, cols
	m.emu.Resize(cols, rows)
	m.drain()
	if m.private {
		m.markPrivateLocked()
	}
}

// Size returns rows and columns.
func (m *Model) Size() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rows, m.cols
}

// AltScreen reports whether the alternate screen is active, as agents
// see it (frozen while private mode is on).
func (m *Model) AltScreen() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.frozen != nil {
		return m.frozen.alt
	}
	return m.alt
}

// AppCursor reports DECCKM (application cursor keys).
func (m *Model) AppCursor() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.decModes[1]
}

// Snapshot renders the screen for a person who attaches: modes, the
// rows with their styles, the cursor. It is raw, unmasked output and
// goes only to person connections.
func (m *Model) Snapshot() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b bytes.Buffer
	b.WriteString("\x1b[0m\x1b[H\x1b[2J")
	modes := make([]int, 0, len(m.decModes))
	for k := range m.decModes {
		switch k {
		case 1, 7, 25, 1000, 1002, 1003, 1004, 1005, 1006, 1015, 2004:
			modes = append(modes, k)
		}
	}
	sort.Ints(modes)
	// Reset the modes the snapshot may set, then set the session's.
	b.WriteString("\x1b[?1l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l")
	if m.alt {
		b.WriteString("\x1b[?1049h\x1b[H\x1b[2J")
	} else {
		b.WriteString("\x1b[?1049l")
	}
	for _, k := range modes {
		if k == 25 {
			continue
		}
		b.WriteString("\x1b[?" + strconv.Itoa(k) + "h")
	}
	// The renderer writes the cells' hyperlink parameters, where the taint
	// marks live; they are cotty's, not the program's.
	render := strings.NewReplacer(taintMark, "", preMark, "").Replace(m.emu.Render())
	for i, l := range strings.Split(render, "\n") {
		if i >= m.rows {
			break
		}
		fmt.Fprintf(&b, "\x1b[%d;1H%s\x1b[0m", i+1, l)
	}
	p := m.emu.CursorPosition()
	fmt.Fprintf(&b, "\x1b[%d;%dH", p.Y+1, p.X+1)
	if m.emu.CursorHidden() {
		b.WriteString("\x1b[?25l")
	} else {
		b.WriteString("\x1b[?25h")
	}
	return b.Bytes()
}

// handleOSC133 records FinalTerm / OSC 133 shell integration marks:
// A prompt start, B command start, C command executed, D;N finished.
// During private mode no command line and no exit code is recorded, and
// the last command recorded before is cleared: what the person runs in
// private never shows up in last_command, also after private mode ends.
func (m *Model) handleOSC133(data []byte) {
	s := string(data)
	_, rest, _ := strings.Cut(s, ";")
	kind, params, _ := strings.Cut(rest, ";")
	m.shell.integration = true
	p := m.emu.CursorPosition()
	switch kind {
	case "A":
		m.shell.atPrompt = true
		m.marksSeen++
		m.promptMarks++
	case "B":
		m.shell.cmdStart = [2]int{p.Y, p.X}
		m.shell.haveStart = !m.private
	case "C":
		m.shell.atPrompt = false
		switch {
		case m.private:
			m.shell.lastCommand = ""
		case m.shell.haveStart:
			m.shell.lastCommand = m.textBetween(m.shell.cmdStart, [2]int{p.Y, p.X})
		}
		m.shell.haveStart = false
	case "D":
		m.shell.atPrompt = false
		m.marksSeen++
		code, _, _ := strings.Cut(params, ";")
		if n, err := strconv.Atoi(code); err == nil && !m.private {
			m.shell.exitCode = &n
		} else {
			m.shell.exitCode = nil
		}
	}
}

// textBetween returns the screen text from one cursor position to
// another (the command line between marks B and C). Any program may print
// the marks, so the range can cover rows that hold private mode text:
// then the command is not recorded (review T2).
func (m *Model) textBetween(from, to [2]int) string {
	if from[0] < 0 || from[0] >= m.rows {
		return ""
	}
	end := min(to[0], m.rows-1)
	for y := from[0]; y <= end; y++ {
		if m.rowMarkedLocked(y) {
			return privateText
		}
	}
	var parts []string
	for y := from[0]; y <= end; y++ {
		t, _ := m.rowText(y)
		r := []rune(t)
		if y == from[0] {
			// Columns map to runes only for single-width text; good enough
			// for a hint.
			if from[1] < len(r) {
				r = r[from[1]:]
			} else {
				r = nil
			}
		}
		parts = append(parts, string(r))
	}
	return strings.TrimSpace(strings.Join(parts, ""))
}

// ShellState returns the OSC 133 state (before masking) and the mark
// counter as agents may see them: frozen while private mode is on.
func (m *Model) ShellState() (integration, atPrompt bool, lastCommand string, exit *int, marks int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.frozen != nil {
		f := m.frozen
		return f.shell.integration, f.shell.atPrompt, f.shell.lastCommand, f.shell.exitCode, f.marks
	}
	return m.shell.integration, m.shell.atPrompt, m.shell.lastCommand, m.shell.exitCode, m.marksSeen
}

// PromptMarks returns the live count of OSC 133 A marks (prompts drawn).
func (m *Model) PromptMarks() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.promptMarks
}

// Resets returns how many emulator panics were recovered.
func (m *Model) Resets() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resets
}

// Close stops the emulator.
func (m *Model) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	stopEmu(m.emu)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// stopEmu ends the emulator's reply reader. It closes the reply pipe
// directly: vt.Emulator.Close writes a field that Read reads without a
// lock (a data race in x/vt v0.1.0).
func stopEmu(e *vt.Emulator) {
	if c, ok := e.InputPipe().(io.Closer); ok {
		_ = c.Close()
	}
}
