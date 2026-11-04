package broker

import (
	"fmt"
	"strings"
	"testing"
)

func write(t *testing.T, m *Model, s string) {
	t.Helper()
	if err := m.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
}

func TestModelRowsAndSince(t *testing.T) {
	m := NewModel(5, 20, nil)
	defer m.Close()
	for i := 1; i <= 8; i++ {
		write(t, m, fmt.Sprintf("line %d\r\n", i))
	}
	v := m.AgentView(0)
	if v.Rows[0] != "line 5" || v.Rows[3] != "line 8" || v.Row != 4 {
		t.Fatalf("rows %q cursor %d", v.Rows, v.Row)
	}
	lines, _, next, first, trunc := m.Since(0, 100)
	if strings.Join(lines, ",") != "line 1,line 2,line 3,line 4" || next != 4 || first != 0 || trunc {
		t.Fatalf("since: %q next %d first %d trunc %v", lines, next, first, trunc)
	}
	lines, _, next, _, _ = m.Since(3, 100)
	if len(lines) != 1 || lines[0] != "line 4" || next != 4 {
		t.Fatalf("since 3: %q %d", lines, next)
	}
	// Context lines above the screen.
	if v := m.AgentView(2); strings.Join(v.Context, ",") != "line 3,line 4" {
		t.Fatalf("context: %q", v.Context)
	}
}

func TestModelWrapAndWide(t *testing.T) {
	m := NewModel(4, 10, nil)
	defer m.Close()
	write(t, m, "0123456789abc\r\n你好|x")
	v := m.AgentView(0)
	if v.Rows[0] != "0123456789" || v.Rows[1] != "abc" || !v.Wrapped[0] || v.Wrapped[1] {
		t.Fatalf("wrap: %q %v", v.Rows, v.Wrapped)
	}
	if v.Rows[2] != "你好|x" {
		t.Fatalf("wide: %q", v.Rows[2])
	}
}

func TestModelPrivate(t *testing.T) {
	m := NewModel(4, 30, nil)
	defer m.Close()
	write(t, m, "before\r\n")
	m.SetPrivate(true)
	write(t, m, "SECRETMARK typed\r\n")
	v := m.AgentView(0)
	if !v.Private || strings.Contains(strings.Join(v.Rows, "\n"), "SECRETMARK") {
		t.Fatalf("private view leaks: %q", v.Rows)
	}
	for i := 0; i < 6; i++ {
		write(t, m, fmt.Sprintf("more %d\r\n", i))
	}
	if lines, _, _, _, _ := m.Since(0, 100); len(lines) != 0 {
		t.Fatalf("since advanced during private mode: %q", lines)
	}
	m.SetPrivate(false)
	lines, _, _, _, _ := m.Since(0, 100)
	all := strings.Join(lines, "\n")
	if strings.Contains(all, "SECRETMARK") || !strings.Contains(all, privateText) {
		t.Fatalf("committed private lines: %q", lines)
	}
	// A row written during private mode and still visible stays masked.
	m2 := NewModel(4, 30, nil)
	defer m2.Close()
	m2.SetPrivate(true)
	write(t, m2, "token=SECRETMARK")
	m2.SetPrivate(false)
	if v := m2.AgentView(0); v.Rows[0] != privateText {
		t.Fatalf("tainted row visible: %q", v.Rows)
	}
	write(t, m2, "\r\x1b[2Kclean")
	if v := m2.AgentView(0); v.Rows[0] != "clean" {
		t.Fatalf("overwritten row still masked: %q", v.Rows)
	}
}

func TestModelOSC133(t *testing.T) {
	m := NewModel(5, 40, nil)
	defer m.Close()
	write(t, m, "\x1b]133;A\x07$ \x1b]133;B\x07ls -la\r\n\x1b]133;C\x07out\r\n\x1b]133;D;2\x07")
	integ, at, last, code, marks := m.ShellState()
	if !integ || at || last != "ls -la" || code == nil || *code != 2 || marks != 2 {
		t.Fatalf("osc133: %v %v %q %v %d", integ, at, last, code, marks)
	}
}

func TestModelRecoversFromPanic(t *testing.T) {
	m := NewModel(30, 100, nil)
	defer m.Close()
	// Found by tools/vteval -fuzz and minimized: a scroll region whose
	// bottom is below the screen, then scroll up, panics in x/vt v0.1.0.
	if err := m.Write([]byte("\x1b[;99r\x1b[S")); err == nil || m.Resets() != 1 {
		t.Fatalf("panic not recovered: %v resets %d", err, m.Resets())
	}
	for _, s := range fuzzStreams() {
		_ = m.Write([]byte(s))
	}
	write(t, m, "\x1bc\x1b[H\x1b[2Jalive")
	if v := m.AgentView(0); !strings.HasPrefix(v.Rows[0], "alive") {
		t.Fatalf("model unusable after panics: %q", v.Rows[0])
	}
}

func TestSnapshotHasModes(t *testing.T) {
	m := NewModel(4, 20, nil)
	defer m.Close()
	write(t, m, "\x1b[?1h\x1b[?2004h\x1b[?1049hvim")
	s := string(m.Snapshot())
	for _, want := range []string{"\x1b[?1h", "\x1b[?2004h", "\x1b[?1049h", "vim"} {
		if !strings.Contains(s, want) {
			t.Errorf("snapshot lacks %q", want)
		}
	}
	if !m.AppCursor() || !m.AltScreen() {
		t.Error("modes not tracked")
	}
}

func TestCursorLine(t *testing.T) {
	m := NewModel(4, 10, nil)
	defer m.Close()
	write(t, m, "$ echo abcdefghij")
	if got := m.CursorLine(); got != "$ echo abcdefghij" {
		t.Fatalf("cursor line %q", got)
	}
}

// TestCursorLineTainted (review N13): the line shown for a held agent
// line (pending_confirmation.line, which agents read) keeps text the
// person typed in private mode hidden, also when the agent finishes the
// line after private mode.
func TestCursorLineTainted(t *testing.T) {
	m := NewModel(4, 60, nil)
	defer m.Close()
	write(t, m, "$ ")
	m.SetPrivate(true)
	write(t, m, "export TOKEN=SECRETMARK")
	m.SetPrivate(false)
	write(t, m, "; echo done")
	if got := m.CursorLine(); strings.Contains(got, "SECRETMARK") || got != privateText {
		t.Fatalf("cursor line %q", got)
	}
}

// TestSecretInputHidesMarks: what a prompt prints per key (sudo-rs's
// asterisks) is hidden from agents during the prompt and afterwards,
// while the prompt text drawn before it stays readable.
func TestSecretInputHidesMarks(t *testing.T) {
	m := NewModel(4, 60, nil)
	defer m.Close()
	write(t, m, "$ sudo true\r\n[sudo: authenticate] Password: ")
	m.SetSecretInput(true)
	write(t, m, "*******")
	if v := m.AgentView(0); strings.Contains(strings.Join(v.Rows, "|"), "*") || !v.Private {
		t.Fatalf("during the prompt: %q", v.Rows)
	}
	write(t, m, "\r\n")
	m.SetSecretInput(false)
	v := m.AgentView(0)
	if strings.Contains(strings.Join(v.Rows, "|"), "*") || v.Rows[0] != "$ sudo true" || v.Rows[1] != privateText {
		t.Fatalf("after the prompt: %q", v.Rows)
	}
	// Person private mode and secret input combine.
	m.SetPrivate(true)
	m.SetSecretInput(true)
	m.SetSecretInput(false)
	if v := m.AgentView(0); !v.Private {
		t.Fatal("secret end turned the person's private mode off")
	}
	m.SetPrivate(false)
	if v := m.AgentView(0); v.Private {
		t.Fatal("still private")
	}
}
