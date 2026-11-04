package attach

import (
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

func TestFilterClampsToSessionRows(t *testing.T) {
	f := newFilter(23)
	cases := map[string]string{
		"\x1b[r":           "\x1b[1;23r",
		"\x1b[;r":          "\x1b[1;23r",
		"\x1b[5;40r":       "\x1b[5;23r",
		"\x1b[24;1H":       "\x1b[23;1H",
		"\x1b[99;5f":       "\x1b[23;5f",
		"\x1b[10;5H":       "\x1b[10;5H",
		"\x1b[30d":         "\x1b[23d",
		"\x1b[?25l":        "\x1b[?25l",
		"plain text":       "plain text",
		"\x1b]0;title\x07": "\x1b]0;title\x07",
	}
	for in, want := range cases {
		if got := string(f.Write([]byte(in))); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	// Sequences split across writes.
	got := string(f.Write([]byte("ab\x1b[2"))) + string(f.Write([]byte("4;1Hc")))
	if got != "ab\x1b[23;1Hc" {
		t.Errorf("split: %q", got)
	}
	// Margins come back after a full reset and a buffer switch.
	if got := string(f.Write([]byte("\x1bc"))); !strings.HasSuffix(got, "\x1b[1;23r") {
		t.Errorf("RIS: %q", got)
	}
	if got := string(f.Write([]byte("\x1b[?1049h"))); !strings.HasSuffix(got, "\x1b[1;23r") {
		t.Errorf("alt screen: %q", got)
	}
	// ESC inside an OSC string ends it (as in the terminal's parser): the
	// CUP that follows is a real sequence and is clamped.
	if got := string(f.Write([]byte("\x1b]2;\x1b[99;1H\x07"))); got != "\x1b]2;\x1b\\\x1b[23;1H\x07" {
		t.Errorf("osc: %q", got)
	}
}

func TestFilterIdleAndPen(t *testing.T) {
	f := newFilter(10)
	f.Write([]byte("\x1b[1;31mred"))
	if !f.idle() || string(f.pen()) != "\x1b[0m\x1b[1;31m" {
		t.Fatalf("pen %q idle %v", f.pen(), f.idle())
	}
	f.Write([]byte("\x1b[0m"))
	if string(f.pen()) != "\x1b[0m" {
		t.Fatalf("pen after reset %q", f.pen())
	}
	f.Write([]byte("\xe4\xbd")) // first two bytes of a three-byte rune
	if f.idle() {
		t.Fatal("idle in the middle of a UTF-8 character")
	}
	f.Write([]byte("\xa0\x1b]0;t"))
	if f.idle() {
		t.Fatal("idle inside an OSC string")
	}
	f.Write([]byte("\x07"))
	if !f.idle() {
		t.Fatal("not idle after the OSC string")
	}
}

func TestStatusLine(t *testing.T) {
	st := proto.Status{State: proto.State{Keyboard: proto.KeyboardHeld, SecretInput: proto.SecretActive,
		SecretProgram: &proto.Program{Name: "sudo", Trust: proto.TrustSystem}, Private: true,
		PendingConfirmation: &proto.Confirmation{Line: "rm -rf build"}, Shared: true, Agents: 1, Assurance: "weak"}}
	line := renderStatus(statusSegments(st, uiState{session: "w", now: time.Now()}), 200)
	for _, want := range []string{"LOCK sudo", sgrGreen, "PRIVATE", "agent wants to run: rm -rf build", "KEYBOARD: you", "agents:1 weak"} {
		if !strings.Contains(line, want) {
			t.Errorf("status lacks %q: %q", want, line)
		}
	}
	st.SecretProgram = &proto.Program{Name: "bash", Trust: proto.TrustOther}
	if line := renderStatus(statusSegments(st, uiState{session: "w"}), 200); !strings.Contains(line, sgrAmber) {
		t.Error("amber lock missing")
	}
	// A program outside the session that opened the pts through the
	// guard's exception list (a pinentry-curses started by gpg-agent).
	st.SecretProgram = &proto.Program{Name: "pinentry-curses", Trust: proto.TrustSystem, Exception: true}
	if line := renderStatus(statusSegments(st, uiState{session: "w"}), 200); !strings.Contains(line, "LOCK pinentry-curses (exception)") {
		t.Errorf("exception lock not named: %q", line)
	}
	// With its parent: who receives what the program reads.
	st.SecretProgram.Parent = "gpg-agent"
	if line := renderStatus(statusSegments(st, uiState{session: "w"}), 200); !strings.Contains(line, "LOCK pinentry-curses (exception, for gpg-agent)") {
		t.Errorf("exception lock without its parent: %q", line)
	}
	// Found by the broker outside the session (no guard): never green.
	st.SecretProgram = &proto.Program{Name: "pinentry-curses", Trust: proto.TrustOther, Outside: true, Parent: "gpg-agent"}
	line = renderStatus(statusSegments(st, uiState{session: "w"}), 200)
	if !strings.Contains(line, "LOCK pinentry-curses (not a system program) (outside the session, for gpg-agent)") || !strings.Contains(line, sgrAmber) {
		t.Errorf("outside lock: %q", line)
	}
	st.SecretProgram = &proto.Program{Name: "p", Trust: proto.TrustOther, Outside: true, Parent: "x\x1b[31mfake"}
	if line := renderStatus(statusSegments(st, uiState{session: "w"}), 200); strings.Contains(line, "\x1b[31mfake") {
		t.Error("escape sequence in the parent name passed into the status line")
	}
	// Text from the session cannot inject escape sequences.
	st.SecretProgram = &proto.Program{Name: "x\x1b[31mfake", Trust: proto.TrustOther}
	if line := renderStatus(statusSegments(st, uiState{session: "w"}), 200); strings.Contains(line, "\x1b[31mfake") {
		t.Error("escape sequence passed into the status line")
	}
	// Width is respected (count runes outside escape sequences).
	narrow := renderStatus(statusSegments(st, uiState{session: "w"}), 20)
	plain := stripSGR(narrow)
	if n := len([]rune(plain)); n != 20 {
		t.Errorf("width %d: %q", n, plain)
	}
}

func stripSGR(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestStatusLineKeyboardRequestWhileHeld(t *testing.T) {
	st := proto.Status{State: proto.State{Shared: true, Agents: 1, Assurance: proto.AssuranceConfined,
		Keyboard: proto.KeyboardHeld, AgentRequestsKeyboard: true}}
	line := renderStatus(statusSegments(st, uiState{session: "w", now: time.Now()}), 300)
	if !strings.Contains(line, "KEYBOARD: you") || !strings.Contains(line, "agent asks for the keyboard") {
		t.Fatalf("held keyboard must still show the agent's request: %q", line)
	}
}

func TestStatusLineWeakAgents(t *testing.T) {
	st := proto.Status{State: proto.State{Shared: true, Agents: 2, Assurance: proto.AssuranceWeak, RequireConfined: false},
		WeakAgents: 2}
	line := renderStatus(statusSegments(st, uiState{session: "w", now: time.Now()}), 300)
	if !strings.Contains(line, "2 unconfined agents") || !strings.Contains(line, sgrAlert) {
		t.Fatalf("weak agents not flagged: %q", line)
	}
	st = proto.Status{State: proto.State{Shared: true, Agents: 0, Assurance: proto.AssuranceConfined, RequireConfined: true},
		RefusedAgents: 1}
	line = renderStatus(statusSegments(st, uiState{session: "w", now: time.Now()}), 300)
	if !strings.Contains(line, "refused 1 unconfined agent") || !strings.Contains(line, "confined-only") {
		t.Fatalf("refusals or confined-only not shown: %q", line)
	}
}
