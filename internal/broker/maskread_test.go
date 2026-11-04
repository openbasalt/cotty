package broker

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/peer"
	"github.com/openbasalt/cotty/internal/proto"
)

// Regression tests for the masking review (B8, S28, S30, S32): the agent's
// reads must not return a listed value, or text written during private
// mode, at page edges, after a taint overflow, a resize or an alternate
// screen switch, and must fail closed when the masker misbehaves. Pure unit
// tests on the model and the broker's read functions: no PTY.

const markValue = "Zq7VALUExK29pLm4TOKENab8Rw" // 26 bytes, fake

// readBroker is a Broker with only what the read paths use.
func readBroker(t *testing.T, m *Model, mk Masker) *Broker {
	t.Helper()
	return &Broker{model: m, masker: mk, logf: t.Logf, cfg: Config{Name: "t", Guard: peer.NoGuard{}},
		classifier: &peer.Classifier{}, hitLogged: map[string]time.Time{},
		hitLocations: map[string]map[int64]time.Time{}, probeFlagged: map[string]time.Time{}}
}

// markEngine masks markValue as TOK.
func markEngine(t *testing.T) *Engine {
	t.Helper()
	e := NewEngine(EngineConfig{ConfigPath: t.TempDir() + "/none.conf"})
	t.Cleanup(e.Close)
	if err := e.eng.AddSecret("TOK", []byte(markValue)); err != nil {
		t.Fatal(err)
	}
	return e
}

// leaks reports whether text holds 8 or more consecutive bytes of v.
func leaks(text, v string) bool {
	for i := 0; i+8 <= len(v); i++ {
		if strings.Contains(text, v[i:i+8]) {
			return true
		}
	}
	return false
}

// B8 bullet 1: a paged since read (limit=1) ending inside a wrapped value
// whose tail is committed too (not on the screen) masks the head.
func TestSincePagedReadMasksWrappedHead(t *testing.T) {
	m := NewModel(4, 20, nil)
	defer m.Close()
	b := readBroker(t, m, markEngine(t))
	write(t, m, "first\r\n")
	write(t, m, "tok="+markValue+"\r\n") // wraps: 20 + 10 columns
	for i := range 10 {
		write(t, m, fmt.Sprintf("after %d\r\n", i))
	}
	for cursor := int64(0); cursor < 3; cursor++ {
		sn, e := b.since(cursor, 1)
		if e != nil {
			t.Fatal(e)
		}
		if leaks(strings.Join(sn.Lines, "\n"), markValue) {
			t.Fatalf("since cursor %d limit 1 leaks: %q", cursor, sn.Lines)
		}
	}
	// One line per line: indexes stay aligned (S32 collect()).
	sn, _ := b.since(0, 100)
	plain, _, _, _, _ := m.Since(0, 100)
	if len(sn.Lines) != len(plain) {
		t.Fatalf("since changed the line count: %d -> %d", len(plain), len(sn.Lines))
	}
}

// rawHas reports the row where the live screen (not the agent's view)
// shows text, or -1: the test's proof that a move really happened.
func rawHas(m *Model, text string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows, _ := m.screenRows()
	for i, r := range rows {
		if strings.Contains(r, text) {
			return i
		}
	}
	return -1
}

// agentSees reports whether the agent's screen or since read shows text.
func agentSees(m *Model, text string) bool {
	v := m.AgentView(0)
	lines, _, _, _, _ := m.Since(0, 10000)
	return strings.Contains(strings.Join(v.Rows, "|")+"|"+strings.Join(lines, "|"), text)
}

// N4 (B8 residual): rows written during private mode stay private when the
// agent moves them without scrolling them into the scrollback: insert and
// delete line, reverse index, scroll up and down, a scroll region with a
// line feed, insert character. Each case checks on the raw screen that
// the row did move, so the test fails if the move stops happening.
func TestTaintFollowsRowMoves(t *testing.T) {
	cases := []struct {
		name, move string
		from, to   int // raw row of the private text before and after (-1: gone from screen)
	}{
		{"insert line", "\x1b[2;1H\x1b[2L", 2, 4},
		{"delete line", "\x1b[1;1H\x1b[1M", 2, 1},
		{"reverse index", "\x1b[1;1H\x1bM", 2, 3},
		{"scroll down", "\x1b[2T", 2, 4},
		{"scroll up", "\x1b[1S", 2, 1},
		{"scroll region line feed", "\x1b[2;5r\x1b[5;1H\n\x1b[r", 2, 1},
		{"insert character", "\x1b[3;1H\x1b[5@", 2, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(6, 40, nil)
			defer m.Close()
			write(t, m, "row0\r\nrow1\r\n")
			m.SetPrivate(true)
			write(t, m, "code SECRETMARK 482913")
			m.SetPrivate(false)
			if got := rawHas(m, "SECRETMARK"); got != tc.from {
				t.Fatalf("setup: private text on row %d, want %d", got, tc.from)
			}
			write(t, m, tc.move)
			if got := rawHas(m, "SECRETMARK"); got != tc.to {
				t.Fatalf("the move did not happen: private text on row %d, want %d", got, tc.to)
			}
			if agentSees(m, "SECRETMARK") || agentSees(m, "482913") {
				t.Fatalf("moved private row visible: %q", m.AgentView(0).Rows)
			}
			// Plain text the agent prints afterwards still shows.
			write(t, m, "\x1b[6;1Hvisible-after")
			if !agentSees(m, "visible-after") {
				t.Fatalf("new text hidden: %q", m.AgentView(0).Rows)
			}
		})
	}
}

// N5: there is no text oracle. A row the agent prints after private mode
// shows even when it equals a row written during private mode, and rows
// on the screen when private mode began stay readable.
func TestTaintNoTextOracle(t *testing.T) {
	m := NewModel(8, 40, nil)
	defer m.Close()
	write(t, m, "before private\r\n")
	m.SetPrivate(true)
	write(t, m, "code 482913\r\n")
	m.SetPrivate(false)
	write(t, m, "code 482913\r\ncode 000000\r\n")
	v := m.AgentView(0)
	if v.Rows[0] != "before private" || v.Rows[1] != privateText || v.Rows[2] != "code 482913" || v.Rows[3] != "code 000000" {
		t.Fatalf("rows %q", v.Rows)
	}
	// The same once the private row scrolled into the committed lines.
	for range 8 {
		write(t, m, "code 482913\r\n")
	}
	lines, _, _, _, _ := m.Since(0, 100)
	priv := 0
	for _, l := range lines {
		if l == privateText {
			priv++
		}
	}
	if priv != 1 {
		t.Fatalf("committed lines: %q (want exactly one private line)", lines)
	}
}

// N4/N5: a private row is shown again only when every column was
// rewritten or erased, so overwriting it column by column tells nothing
// about the length of what it held.
func TestTaintNoLengthOracle(t *testing.T) {
	m := NewModel(4, 30, nil)
	defer m.Close()
	m.SetPrivate(true)
	write(t, m, "pw hunter22")
	m.SetPrivate(false)
	write(t, m, "\r"+strings.Repeat("x", 11)) // exactly the private text's length
	if v := m.AgentView(0); v.Rows[0] != privateText {
		t.Fatalf("row shown after overwriting the private text's length: %q", v.Rows[0])
	}
	write(t, m, "\r"+strings.Repeat("y", 30))
	if v := m.AgentView(0); v.Rows[0] != strings.Repeat("y", 30) {
		t.Fatalf("row fully rewritten: %q", v.Rows[0])
	}
}

// The marks cannot be forged by a program (OSC 8 parameters cannot hold
// C0 bytes), and they never reach the person's snapshot.
func TestTaintMarksNotForgeable(t *testing.T) {
	m := NewModel(4, 40, nil)
	defer m.Close()
	m.SetPrivate(true)
	// A program in the session tries to give the next cells the pre mark.
	write(t, m, "\x1b]8;"+preMark+";\x07SECRETMARK\x1b]8;;\x07")
	m.SetPrivate(false)
	if agentSees(m, "SECRETMARK") {
		t.Fatalf("forged pre mark unmasked a private row: %q", m.AgentView(0).Rows)
	}
	if s := m.Snapshot(); strings.Contains(string(s), "\x01") || !strings.Contains(string(s), "SECRETMARK") {
		t.Fatalf("snapshot: %q", s)
	}
}

// B8 bullet 2: a resize after private mode, and a \r overwrite, keep the
// rows written during private mode hidden.
func TestTaintSurvivesResizeAndOverwrite(t *testing.T) {
	m := NewModel(4, 40, nil)
	defer m.Close()
	write(t, m, "$ ")
	m.SetPrivate(true)
	write(t, m, "pw SECRETMARK-0123456789-ABCDEFGHIJ")
	m.SetPrivate(false)
	m.Resize(4, 20)
	v := m.AgentView(0)
	if strings.Contains(strings.Join(v.Rows, "|"), "SECRETMARK") || strings.Contains(strings.Join(v.Rows, "|"), "ABCDEF") {
		t.Fatalf("resize unmasked: %q", v.Rows)
	}
	lines, _, _, _, _ := m.Since(0, 100)
	if strings.Contains(strings.Join(lines, "|"), "0123456789") {
		t.Fatalf("resize committed: %q", lines)
	}

	m2 := NewModel(4, 40, nil)
	defer m2.Close()
	m2.SetPrivate(true)
	write(t, m2, "password: SECRETMARK")
	m2.SetPrivate(false)
	write(t, m2, "\rxx") // overwrites two columns only
	if v := m2.AgentView(0); strings.Contains(v.Rows[0], "SECRETMARK") {
		t.Fatalf("\\r overwrite unmasked: %q", v.Rows)
	}
}

// B8 bullet 2: the alternate screen entered in the same chunk as the
// secret; the main screen is tainted.
func TestAltScreenInSecretChunk(t *testing.T) {
	m := NewModel(4, 30, nil)
	defer m.Close()
	m.SetPrivate(true)
	write(t, m, "SECRETMARK\x1b[?1049h")
	write(t, m, "editor")
	m.SetPrivate(false)
	if v := m.AgentView(0); strings.Contains(strings.Join(v.Rows, "|"), "editor") {
		t.Fatalf("alternate screen written during private mode visible: %q", v.Rows)
	}
	write(t, m, "\x1b[?1049l")
	if v := m.AgentView(0); strings.Contains(strings.Join(v.Rows, "|"), "SECRETMARK") {
		t.Fatalf("main screen after the alternate one: %q", v.Rows)
	}
}

// A row erased and rewritten in one chunk after private mode is seen blank
// in between, so the new text shows.
func TestEraseInChunkUntaints(t *testing.T) {
	m := NewModel(4, 30, nil)
	defer m.Close()
	m.SetPrivate(true)
	write(t, m, "SECRETMARK")
	m.SetPrivate(false)
	write(t, m, "\r\x1b[2Kclean")
	if v := m.AgentView(0); v.Rows[0] != "clean" {
		t.Fatalf("erased row: %q", v.Rows)
	}
}

// shortMasker returns one row fewer than it gets.
type shortMasker struct{ NoMask }

func (shortMasker) MaskScreen(_ string, rows []string, _ int) MaskedRows {
	return MaskedRows{Rows: rows[:max(len(rows)-1, 0)]}
}

func (shortMasker) MaskLines(_ string, lines []string, _ []bool, _ string) MaskedRows {
	return MaskedRows{Rows: lines[:max(len(lines)-1, 0)]}
}

// B8 bullet 3: a masker row-count mismatch withholds the text.
func TestMaskerRowMismatchFailsClosed(t *testing.T) {
	m := NewModel(4, 30, nil)
	defer m.Close()
	b := readBroker(t, m, shortMasker{})
	for i := range 6 {
		write(t, m, fmt.Sprintf("line %d\r\n", i))
	}
	if sc, e := b.screen(0); e == nil || e.Code != proto.ErrInternal || len(sc.Rows) != 0 {
		t.Fatalf("screen served: %v %q", e, sc.Rows)
	}
	if sn, e := b.since(0, 10); e == nil || len(sn.Lines) != 0 {
		t.Fatalf("since served: %v %q", e, sn.Lines)
	}
}

// B8 bullet 4 and S30: the committed lines above the frozen view are
// masking context, so the tail of a value on the frozen top row is masked;
// and a value whose head is far above the screen (up to 200 lines) is
// masked too.
func TestFrozenViewKeepsContext(t *testing.T) {
	m := NewModel(4, 20, nil)
	defer m.Close()
	b := readBroker(t, m, markEngine(t))
	write(t, m, "a\r\nb\r\nc\r\n")
	write(t, m, "tok="+markValue[:16]) // row 3 is full (20 columns)
	write(t, m, markValue[16:]+"\r\n\r\n\r\n")
	// The head is now committed, the tail is on the top row.
	m.SetPrivate(true)
	write(t, m, "private stuff\r\n")
	sc, e := b.screen(0)
	if e != nil {
		t.Fatal(e)
	}
	if leaks(strings.Join(sc.Rows, "|"), markValue[16:]) || strings.Contains(strings.Join(sc.Rows, "|"), markValue[16:]) {
		t.Fatalf("frozen view tail: %q", sc.Rows)
	}
}

// Nit: during private mode the wrap flag of the last committed line comes
// from the frozen view, not the live screen.
func TestSinceWrapFlagUsesFrozenView(t *testing.T) {
	m := NewModel(3, 10, nil)
	defer m.Close()
	write(t, m, "0123456789\r\n\r\n\r\n") // a full row followed by empty rows
	m.SetPrivate(true)
	write(t, m, "\x1b[Hlivetext")
	_, wrapped, _, _, _ := m.Since(0, 10)
	if len(wrapped) > 0 && wrapped[len(wrapped)-1] {
		t.Fatalf("wrap flag taken from the live screen: %v", wrapped)
	}
}

// S28: the cursor column on a masked row moves with the replacement, so it
// does not tell the value's length.
func TestCursorColumnOnMaskedRow(t *testing.T) {
	m := NewModel(4, 60, nil)
	defer m.Close()
	b := readBroker(t, m, markEngine(t))
	write(t, m, "$ export X="+markValue)
	sc, e := b.screen(0)
	if e != nil {
		t.Fatal(e)
	}
	want := len("$ export X=[masked:TOK]")
	if sc.Rows[0] != "$ export X=[masked:TOK]" || sc.Cursor.Col != want {
		t.Fatalf("row %q cursor %d, want %d", sc.Rows[0], sc.Cursor.Col, want)
	}
	// Cursor inside the span: reported at its start.
	write(t, m, "\x1b[15G")
	if sc, _ := b.screen(0); sc.Cursor.Col != len("$ export X=") {
		t.Fatalf("cursor inside the span: %d", sc.Cursor.Col)
	}
}

func TestMaskedColumn(t *testing.T) {
	in := "ab SECRETVALUE cd"
	out := "ab [masked:S] cd"
	edits := []MaskEdit{{Row: 0, InStart: 3, InEnd: 14, OutStart: 3, OutEnd: 13}}
	for col, want := range map[int]int{0: 0, 2: 2, 3: 3, 10: 3, 14: 13, 16: 15, 30: 29} {
		if got := maskedColumn(in, out, col, edits, 0); got != want {
			t.Errorf("col %d: %d, want %d", col, got, want)
		}
	}
}

// N24: the masking context is sized in bytes as well as lines. A value
// whose base64 (wrapped at 76 columns, as base64(1) prints it) runs over
// more than maskContextLines lines is masked in a since read of one line
// at the top of it.
func TestLongValueContextInBytes(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigPath: t.TempDir() + "/none.conf"})
	t.Cleanup(e.Close)
	value := make([]byte, 12000)
	for i := range value {
		value[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[(i*7919+i/3)%62]
	}
	if err := e.eng.AddSecret("BIG", value); err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString(value)
	m := NewModel(4, 100, nil)
	defer m.Close()
	b := readBroker(t, m, e)
	var lines []string
	for i := 0; i < len(enc); i += 76 {
		lines = append(lines, enc[i:min(i+76, len(enc))])
	}
	if len(lines) <= maskContextLines {
		t.Fatalf("setup: %d lines, need more than %d", len(lines), maskContextLines)
	}
	write(t, m, "start\r\n"+strings.Join(lines, "\r\n")+"\r\nend\r\n\r\n\r\n\r\n")
	for cursor := int64(1); cursor < 4; cursor++ {
		sn, perr := b.since(cursor, 1)
		if perr != nil {
			t.Fatal(perr)
		}
		if len(sn.Lines) != 1 || leaks(sn.Lines[0], enc[(cursor-1)*76:cursor*76]) || !strings.Contains(sn.Lines[0], "[masked") {
			t.Fatalf("since %d limit 1: %q", cursor, sn.Lines)
		}
	}
}

// T1 (round 3): a freeze that starts after private mode keeps the rows
// that private mode hid hidden. Both freeze paths: the person's private
// mode again, and a secret prompt (which the agent can start itself with
// sudo). The frozen cursor column on such a row is not kept either: it
// would tell the hidden text's length.
func TestFrozenViewKeepsEarlierTaint(t *testing.T) {
	freezes := []struct {
		name    string
		on, off func(m *Model)
	}{
		{"private again", func(m *Model) { m.SetPrivate(true) }, func(m *Model) { m.SetPrivate(false) }},
		{"secret prompt", func(m *Model) { m.SetSecretInput(true) }, func(m *Model) { m.SetSecretInput(false) }},
	}
	for _, fz := range freezes {
		t.Run(fz.name, func(t *testing.T) {
			m := NewModel(6, 60, nil)
			defer m.Close()
			write(t, m, "$ ")
			m.SetPrivate(true)
			write(t, m, "export TOKEN=SECRETMARK")
			m.SetPrivate(false)
			if v := m.AgentView(0); v.Rows[0] != privateText || v.Col != 0 {
				t.Fatalf("setup: rows %q col %d", v.Rows, v.Col)
			}
			fz.on(m)
			v := m.AgentView(0)
			if !v.Private {
				t.Fatal("view not frozen")
			}
			if strings.Contains(strings.Join(v.Rows, "|"), "SECRETMARK") || v.Rows[0] != privateText {
				t.Fatalf("frozen view shows the private row: %q", v.Rows)
			}
			if v.Col != 0 {
				t.Fatalf("frozen cursor column %d tells the hidden length", v.Col)
			}
			r := m.ReadSince(0, 100, Depth{Lines: 8}, Depth{Lines: 8})
			if strings.Contains(strings.Join(r.After, "|"), "SECRETMARK") {
				t.Fatalf("masker context shows the private row: %q", r.After)
			}
			fz.off(m)
			if v := m.AgentView(0); strings.Contains(strings.Join(v.Rows, "|"), "SECRETMARK") {
				t.Fatalf("after the freeze: %q", v.Rows)
			}
		})
	}
}

// T1: the frozen cursor column is zeroed for the length oracle case of
// TestTaintNoLengthOracle.
func TestFrozenCursorColumnHidden(t *testing.T) {
	m := NewModel(4, 30, nil)
	defer m.Close()
	m.SetPrivate(true)
	write(t, m, "pw hunter22")
	m.SetPrivate(false)
	m.SetSecretInput(true)
	defer m.SetSecretInput(false)
	if v := m.AgentView(0); v.Col != 0 || v.Rows[0] != privateText {
		t.Fatalf("frozen view: rows %q col %d", v.Rows, v.Col)
	}
}

// T2 (round 3): last_command never carries text from a row private mode
// hid, also when a program prints forged OSC 133 marks around that row,
// or a genuine command line spans it.
func TestLastCommandSkipsTaintedRows(t *testing.T) {
	cases := []struct{ name, after string }{
		// Save cursor, go to the private row, B, move right, C, restore.
		{"forged marks", "\r\n$ \x1b7\x1b[1;1H\x1b]133;B\a\x1b[1;60H\x1b]133;C\a\x1b8"},
		// B on a clean row, C on the private row below it.
		{"line over private row", "\x1b[1;1H\x1b[2L\x1b[1;1H$ \x1b]133;B\aecho a\x1b[3;40H\x1b]133;C\a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(6, 80, nil)
			defer m.Close()
			write(t, m, "$ ")
			m.SetPrivate(true)
			write(t, m, "export TOKEN=SECRETMARK")
			m.SetPrivate(false)
			if rawHas(m, "SECRETMARK") < 0 {
				t.Fatal("setup: private text not on screen")
			}
			write(t, m, tc.after)
			_, _, last, _, _ := m.ShellState()
			if strings.Contains(last, "SECRETMARK") {
				t.Fatalf("last_command %q carries private text", last)
			}
			if last != privateText {
				t.Fatalf("last_command %q, want %q", last, privateText)
			}
		})
	}
	// A clean command line is still recorded.
	m := NewModel(6, 80, nil)
	defer m.Close()
	write(t, m, "$ \x1b]133;B\aecho hi\x1b]133;C\a")
	if _, _, last, _, _ := m.ShellState(); last != "echo hi" {
		t.Fatalf("clean last_command %q", last)
	}
}
