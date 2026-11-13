//go:build vmtest

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

// confirmShells are the shells the confirm policy tests run in, with the
// line the person types to load the shell's completion and the one that
// binds Space to magic-space (as oh-my-zsh does for zsh).
var confirmShells = []struct {
	name       string
	argv       []string
	completion string
	magicSpace string
}{
	{"bash", []string{"bash", "--norc", "--noprofile"},
		"source /usr/share/bash-completion/bash_completion",
		`bind '" ": magic-space'`},
	{"zsh", []string{"zsh", "-f"},
		"autoload -U compinit && compinit -u",
		"bindkey ' ' magic-space"},
}

func needShell(t *testing.T, argv0 string) {
	t.Helper()
	if _, err := exec.LookPath(argv0); err != nil {
		t.Skipf("%s not installed", argv0)
	}
}

// wantPolicyDenied fails unless err is policy_denied.
func wantPolicyDenied(t *testing.T, what string, err error) {
	t.Helper()
	if proto.ErrorCode(err) != proto.ErrPolicyDenied {
		t.Errorf("%s under --policy confirm: got %v, want policy_denied", what, err)
	}
}

// TestConfirmRefusesRecallAndCompletion (review COT-1, COT-3): under
// --policy confirm the keys and text that complete, recall history or
// expand history references are refused, in bash and zsh; plain text with
// an approved Enter still runs. A project's ./configure and Makefile that
// run code when completed (bash-completion and zsh's compsys run them)
// stay untouched while the agent tries to complete them.
func TestConfirmRefusesRecallAndCompletion(t *testing.T) {
	for _, sh := range confirmShells {
		t.Run(sh.name, func(t *testing.T) {
			needShell(t, sh.argv[0])
			dir := t.TempDir()
			configure := "#!/bin/sh\ntouch \"$(dirname \"$0\")/configure-ran\"\necho '  --prefix=DIR  install prefix'\n"
			if err := os.WriteFile(filepath.Join(dir, "configure"), []byte(configure), 0o755); err != nil {
				t.Fatal(err)
			}
			mk := "X := $(shell touch " + filepath.Join(dir, "make-ran") + ")\nall:\n\t@true\nbuild:\n\t@true\n"
			if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(mk), 0o644); err != nil {
				t.Fatal(err)
			}
			ran := func() []string {
				var out []string
				for _, f := range []string{"configure-ran", "make-ran"} {
					if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
						out = append(out, f)
					}
				}
				return out
			}

			p, a, _ := newSession(t, []string{"--policy", "confirm"}, sh.argv...)
			p.typ("PS1='$ '; PROMPT='$ '; cd " + dir + "\r")
			p.typ(sh.completion + "\r")
			waitQuiet(t, a)

			for _, k := range []string{"Tab", "BTab", "Up", "Down", "PgUp", "PgDn"} {
				wantPolicyDenied(t, "key "+k, a.call("keys", map[string]any{"keys": []string{k}}, nil))
			}
			for _, txt := range []string{"echo a\tb", "echo !!", "echo !1", "echo !-1", "echo hi!", "^a^b", "ls !$", "echo !echo"} {
				wantPolicyDenied(t, "text "+strings.ReplaceAll(txt, "\t", `\t`), a.call("type", map[string]any{"text": txt}, nil))
			}

			// The completion reproduction: the agent types the start of the
			// command and asks for completion (key or tab in text).
			for _, line := range []string{"./configure --", "make "} {
				if err := a.call("type", map[string]any{"text": line}, nil); err != nil {
					t.Fatalf("type %q: %v", line, err)
				}
				wantPolicyDenied(t, "Tab after "+line, a.call("keys", map[string]any{"keys": []string{"Tab"}}, nil))
				wantPolicyDenied(t, "Tab Tab after "+line, a.call("keys", map[string]any{"keys": []string{"Tab", "Tab"}}, nil))
				wantPolicyDenied(t, "tab in text after "+line, a.call("type", map[string]any{"text": "\t"}, nil))
				if err := a.call("keys", map[string]any{"keys": []string{"C-c"}}, nil); err != nil {
					t.Fatalf("C-c: %v", err)
				}
				time.Sleep(300 * time.Millisecond)
			}
			time.Sleep(time.Second)
			if r := ran(); len(r) > 0 {
				t.Errorf("project files ran while the agent tried to complete: %v", r)
			}

			// Plain text with an approved Enter still works.
			waitQuiet(t, a)
			var sent proto.Sent
			if err := a.call("type", map[string]any{"text": "echo plain-$((40+2)) = x", "enter": true}, &sent); err != nil || !sent.HeldEnter {
				t.Fatalf("plain text under confirm: %+v %v", sent, err)
			}
			p.waitScreen("agent wants to run", 3*time.Second)
			from := p.mark()
			p.typ("\x1dy")
			p.waitOutput(from, "plain-42 = x", 5*time.Second)

			// Control: the same files do run code when the person completes,
			// so the refusals above are what kept them from running.
			waitQuiet(t, a)
			p.typeSlowly("./configure --\t\t")
			time.Sleep(1500 * time.Millisecond)
			p.typ("\x03")
			p.typeSlowly("make \t\t")
			time.Sleep(1500 * time.Millisecond)
			p.typ("\x03")
			t.Logf("%s: person completion ran %v (control: shows the payload is live)", sh.name, ran())
		})
	}
}

// TestConfirmNoHistoryExpansionByEditing: the text rule lets an agent
// type a '!' followed by a blank, '=' or '('. It must not be able to turn
// that into a history reference with the editing keys it may still send
// (Left, Backspace, more text) and have magic-space expand it, which
// draws a command the person typed in private mode on the screen without
// any Enter (review COT-3).
func TestConfirmNoHistoryExpansionByEditing(t *testing.T) {
	for _, sh := range confirmShells {
		t.Run(sh.name, func(t *testing.T) {
			needShell(t, sh.argv[0])
			p, a, _ := newSession(t, []string{"--policy", "confirm"}, sh.argv...)
			p.typ("PS1='$ '; PROMPT='$ '\r")
			p.typ(sh.magicSpace + "\r")
			priv := marker("HX")
			p.typ("\x1dp")
			deadline := time.Now().Add(3 * time.Second)
			for !a.state().Private && time.Now().Before(deadline) {
				time.Sleep(30 * time.Millisecond)
			}
			p.typ("echo " + priv + "\r")
			time.Sleep(300 * time.Millisecond)
			p.typ("clear\r")
			time.Sleep(300 * time.Millisecond)
			p.typ("\x1dp")
			for a.state().Private && time.Now().Before(deadline.Add(3*time.Second)) {
				time.Sleep(30 * time.Millisecond)
			}
			waitQuiet(t, a)

			// Each step alone is allowed or refused; together they must not
			// leave "!-2" (the private command) on the line for Space.
			steps := []struct {
				op   string
				args map[string]any
			}{
				{"type", map[string]any{"text": "echo !="}},
				{"keys", map[string]any{"keys": []string{"Left"}}},
				{"type", map[string]any{"text": "-2"}},
				{"keys", map[string]any{"keys": []string{"Space"}}},
			}
			for _, s := range steps {
				err := a.call(s.op, s.args, nil)
				t.Logf("%s %v: %v", s.op, s.args, err)
				time.Sleep(200 * time.Millisecond)
			}
			time.Sleep(500 * time.Millisecond)
			scr := a.screenText()
			if strings.Contains(scr, priv) {
				t.Errorf("history expansion by editing drew a private command on the agent's screen:\n%s", scr)
			}
			// Same with Backspace instead of Left: "echo ! " then delete the
			// blank and type the event.
			_ = a.call("keys", map[string]any{"keys": []string{"C-c"}}, nil)
			time.Sleep(300 * time.Millisecond)
			for _, s := range []struct {
				op   string
				args map[string]any
			}{
				{"type", map[string]any{"text": "echo ! "}},
				{"keys", map[string]any{"keys": []string{"Backspace"}}},
				{"type", map[string]any{"text": "-2"}},
				{"type", map[string]any{"text": " "}},
			} {
				err := a.call(s.op, s.args, nil)
				t.Logf("%s %v: %v", s.op, s.args, err)
				time.Sleep(200 * time.Millisecond)
			}
			time.Sleep(500 * time.Millisecond)
			if scr := a.screenText(); strings.Contains(scr, priv) {
				t.Errorf("history expansion after Backspace drew a private command on the agent's screen:\n%s", scr)
			}
			assertNoLeak(t, a, priv)
			_ = a.call("keys", map[string]any{"keys": []string{"C-c"}}, nil)
		})
	}
}
