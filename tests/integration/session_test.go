//go:build vmtest

package integration

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

// prompt is one secret prompt scenario.
type prompt struct {
	name    string
	command string // typed by the person, Enter included
	program string // expected foreground program at the prompt
	trust   string
	answers []string // what the person types at each consecutive prompt (Enter added)
	after   string   // output that shows the command finished
	abort   bool     // abort the prompt that follows the answers
}

// TestSecretPrompts: the five common secret prompts (and a few more) are
// detected; agent input is refused while they are active; what the person
// types never reaches the agent, the audit log or the broker log.
func TestSecretPrompts(t *testing.T) {
	pw := password(t)
	m1, m2, m3, m4 := marker("RS"), marker("GP"), marker("OS"), marker("SU")
	cases := []prompt{
		{"sudo", "sudo -k; sudo -v; echo sudo-rc=$?-$((40+2))\r", "sudo", proto.TrustSystem, []string{pw}, "sudo-rc=0-42", false},
		{"read -s", "read -rs -p 'pw: ' V; echo; echo len=${#V}-$((40+2))\r", "bash", proto.TrustOther, []string{m1}, "len=18-42", false},
		{"python getpass", "python3 -c 'import getpass; print(\"n=%d\" % len(getpass.getpass(\"pw: \")))'; echo py-$((40+2))\r", "python3", proto.TrustOther, []string{m2}, "py-42", false},
		{"openssl passwd", "openssl passwd -6 >/dev/null; echo ossl-rc=$?-$((40+2))\r", "openssl", proto.TrustSystem, []string{m3, m3}, "ossl-rc=0-42", false},
		{"su", "su -c true root; echo su-$((40+2))\r", "su", proto.TrustSystem, []string{m4}, "su-42", false},
		{"passwd", "passwd; echo passwd-$((40+2))\r", "passwd", proto.TrustSystem, []string{pw}, "passwd-42", true},
		{"ssh", "ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null localhost echo ssh-$((40+2))\r", "ssh", proto.TrustSystem, []string{pw}, "ssh-42", false},
	}
	p, a, _ := newSession(t, nil, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	time.Sleep(300 * time.Millisecond)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			from := p.mark()
			p.typ(c.command)
			for i, ans := range c.answers {
				st := a.waitSecret(proto.SecretActive, 15*time.Second)
				if i == 0 {
					// The name is the executable's (python3.14 for python3),
					// with the name it was started under when they differ.
					if st.SecretProgram == nil || !strings.HasPrefix(st.SecretProgram.Name, c.program) || st.SecretProgram.Trust != c.trust {
						t.Errorf("secret program %+v, want %s (%s)", st.SecretProgram, c.program, c.trust)
					}
					// The person's status line shows the lock.
					p.waitScreen("LOCK "+c.program, 3*time.Second)
					// Agent input is refused while the prompt is active.
					err := a.call("type", map[string]any{"text": "agent-guess"}, nil)
					if proto.ErrorCode(err) != proto.ErrSecretInputActive && proto.ErrorCode(err) != proto.ErrPersonTyping {
						t.Errorf("agent typed at a secret prompt: %v", err)
					}
				}
				p.typeSlowly(ans)
				p.typ("\r")
				// Wait until this prompt is consumed before the next one.
				if i+1 < len(c.answers) {
					time.Sleep(400 * time.Millisecond)
				}
			}
			if c.abort {
				// The next prompt (new password) is answered with end of
				// file until the program gives up (passwd ignores C-c).
				// Only while the program still runs: an end of file that
				// reaches the shell after passwd gave up ends the session.
				a.waitSecret(proto.SecretActive, 10*time.Second)
				inProgram := func() bool {
					fg := a.state().Foreground
					return fg != nil && strings.HasPrefix(fg.Name, c.program)
				}
				for i := 0; i < 5 && !strings.Contains(p.output()[from:], c.after) && inProgram(); i++ {
					p.typ("\x04")
					time.Sleep(500 * time.Millisecond)
				}
			}
			a.waitSecret(proto.SecretNone, 15*time.Second)
			p.waitOutput(from, c.after, 15*time.Second)
			// The person's terminal never echoed what was typed.
			for _, ans := range c.answers {
				if strings.Contains(p.output()[from:], ans) {
					t.Errorf("the secret was echoed on the person's terminal")
				}
			}
		})
	}
	assertNoLeak(t, a, pw, m1, m2, m3, m4)
}

// TestZshReadSecret: zsh's read -s.
func TestZshReadSecret(t *testing.T) {
	m := marker("ZR")
	p, a, _ := newSession(t, nil, "zsh", "-f")
	time.Sleep(400 * time.Millisecond)
	from := p.mark()
	p.typ("read -s 'V?pw: '; echo; echo zlen=${#V}\r")
	st := a.waitSecret(proto.SecretActive, 10*time.Second)
	if st.SecretProgram == nil || !strings.HasPrefix(st.SecretProgram.Name, "zsh") || st.SecretProgram.Trust != proto.TrustOther {
		t.Errorf("program %+v", st.SecretProgram)
	}
	p.typeSlowly(m)
	p.typ("\r")
	a.waitSecret(proto.SecretNone, 10*time.Second)
	p.waitOutput(from, "zlen=", 10*time.Second)
	assertNoLeak(t, a, m)
}

// TestRawModeNeverSecret: raw mode programs and line editors never light
// the lock.
func TestRawModeNeverSecret(t *testing.T) {
	type step struct {
		keys string
		wait time.Duration
	}
	run := func(t *testing.T, a *agent, p *person, steps []step) {
		t.Helper()
		stop := make(chan struct{})
		bad := make(chan proto.State, 1)
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				var s proto.State
				if err := a.cl.Call(context.Background(), "state", nil, &s); err == nil && s.SecretInput == proto.SecretActive {
					select {
					case bad <- s:
					default:
					}
				}
				time.Sleep(25 * time.Millisecond)
			}
		}()
		for _, s := range steps {
			if s.keys != "" {
				p.typeSlowly(s.keys)
			}
			time.Sleep(s.wait)
		}
		close(stop)
		select {
		case s := <-bad:
			t.Errorf("secret input detected: %+v", s.SecretProgram)
		default:
		}
	}
	t.Run("bash", func(t *testing.T) {
		p, a, _ := newSession(t, nil, "bash", "--norc", "--noprofile")
		run(t, a, p, []step{
			{"echo readline line", 300 * time.Millisecond},
			{"\x01\x05\x1b[D", 300 * time.Millisecond},
			{"\r", 300 * time.Millisecond},
			{"vim -u NONE -N /tmp/cotty-it-vim.txt\r", 1500 * time.Millisecond},
			{"ihello from vim\x1b", 500 * time.Millisecond},
			{":wq\r", 800 * time.Millisecond},
			{"seq 1 500 | less\r", 1000 * time.Millisecond},
			{" ", 300 * time.Millisecond},
			{"/42\r", 300 * time.Millisecond},
			{"q", 500 * time.Millisecond},
			{"htop -d 5\r", 2000 * time.Millisecond},
			{"q", 600 * time.Millisecond},
			{"git log 2>/dev/null | head -1; echo done\r", 500 * time.Millisecond},
		})
	})
	t.Run("zsh", func(t *testing.T) {
		p, a, _ := newSession(t, nil, "zsh", "-f")
		run(t, a, p, []step{
			{"", 500 * time.Millisecond},
			{"echo zle line", 300 * time.Millisecond},
			{"\x01\x1b[C\x1b[C", 300 * time.Millisecond},
			{"\r", 300 * time.Millisecond},
			{"bindkey -v\r", 300 * time.Millisecond},
			{"echo vi mode\x1bbi", 300 * time.Millisecond},
			{"\r", 300 * time.Millisecond},
		})
	})
}

// TestSudoPwfeedbackDetected: with pwfeedback (sudo's option, and sudo-rs's
// default) sudo reads in raw mode and prints an asterisk per key. The
// prompt is secret input (setuid root, no child yet), and the asterisks
// reach the person's screen but never the agent.
func TestSudoPwfeedbackDetected(t *testing.T) {
	pw := password(t)
	p, a, _ := newSession(t, nil, "bash", "--norc", "--noprofile")
	time.Sleep(300 * time.Millisecond)
	from := p.mark()
	p.typ("sudo -k; sudo id -u; echo id-rc=$?\r")
	st := a.waitSecret(proto.SecretActive, 15*time.Second)
	if st.SecretProgram == nil || !strings.HasPrefix(st.SecretProgram.Name, "sudo") || st.SecretProgram.Trust != proto.TrustSystem {
		t.Errorf("pwfeedback prompt judged %+v, want sudo (system)", st.SecretProgram)
	}
	p.waitScreen("LOCK sudo", 3*time.Second)
	p.typeSlowly(pw)
	// sudo echoed asterisks: pwfeedback was in effect. Read the screen, not
	// the raw stream: the client may draw its status line between two
	// asterisks.
	if !strings.Contains(strings.Join(p.screen(), "\n"), strings.Repeat("*", 4)) {
		t.Fatalf("no asterisks: pwfeedback not in effect, the test proves nothing")
	}
	if sc := a.screenText(); strings.Contains(sc, "****") {
		t.Errorf("asterisks visible to the agent during the prompt: %q", sc)
	}
	p.typ("\r")
	a.waitSecret(proto.SecretNone, 15*time.Second)
	p.waitOutput(from, "id-rc=0", 15*time.Second)
	waitQuiet(t, a)
	if strings.Contains(a.all(), "****") {
		t.Errorf("asterisks visible to the agent after the prompt")
	}
	assertNoLeak(t, a, pw)
}

// TestPassthrough: the person's terminal gets the program's bytes
// unchanged (colours included) and cotty's status line in the last row.
func TestPassthrough(t *testing.T) {
	p, a, name := newSession(t, nil, "bash", "--norc", "--noprofile")
	time.Sleep(300 * time.Millisecond)
	from := p.mark()
	p.typ("printf '\\e[1;31mRED\\e[0m %s \\u4f60\\u597d\\n' $((6*7))\r")
	p.waitOutput(from, "\x1b[1;31mRED\x1b[0m 42 你好", 5*time.Second)
	p.waitScreen("RED 42 你好", 3*time.Second)
	a.waitScreen("RED 42 你好", 3*time.Second)
	if !strings.Contains(p.statusLine(), "cotty:"+name) {
		t.Errorf("status line: %q", p.statusLine())
	}
	// Scrolling output never runs into the status line.
	p.typ("seq 1 200\r")
	p.waitScreen("200", 5*time.Second)
	time.Sleep(200 * time.Millisecond)
	if !strings.Contains(p.statusLine(), "cotty:"+name) {
		t.Errorf("status line overwritten: %q", p.statusLine())
	}
	// A program that addresses the last row lands on its own last row.
	p.typ("printf '\\e[99;1HBOTTOM'; sleep 0.5; echo\r")
	time.Sleep(700 * time.Millisecond)
	scr := p.screen()
	if strings.Contains(scr[outerRows-1], "BOTTOM") {
		t.Errorf("a program wrote into the status row: %q", scr[outerRows-1])
	}
	// The committed lines reach the agent through since.
	var sn proto.Since
	if err := a.call("since", map[string]int{"cursor": 0}, &sn); err != nil || !strings.Contains(strings.Join(sn.Lines, "\n"), "\n100\n") {
		t.Errorf("since: %v %d lines", err, len(sn.Lines))
	}
}

// TestArbitration: person typing, keyboard hold, private mode.
func TestArbitration(t *testing.T) {
	p, a, _ := newSession(t, nil, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	// Person typing blocks the agent.
	p.typ("echo person")
	time.Sleep(200 * time.Millisecond)
	err := a.call("type", map[string]any{"text": "x"}, nil)
	if proto.ErrorCode(err) != proto.ErrPersonTyping {
		t.Errorf("agent typed while the person typed: %v", err)
	}
	p.typ("\r")
	waitQuiet(t, a)
	from := p.mark()
	if err := a.call("type", map[string]any{"text": "echo agent-$((1+1))", "enter": true}, nil); err != nil {
		t.Fatal(err)
	}
	p.waitOutput(from, "agent-2", 5*time.Second)
	a.waitScreen("agent-2", 3*time.Second)

	// Keyboard hold (^] k).
	p.typ("\x1dk")
	deadline := time.Now().Add(3 * time.Second)
	for a.state().Keyboard != proto.KeyboardHeld && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}
	time.Sleep(1600 * time.Millisecond)
	if err := a.call("type", map[string]any{"text": "x"}, nil); proto.ErrorCode(err) != proto.ErrKeyboardHeld {
		t.Errorf("agent typed while the person held the keyboard: %v", err)
	}
	p.waitScreen("KEYBOARD: you", 3*time.Second)
	p.typ("\x1dk")

	// Private mode (^] p): the agent's view freezes; rows written during
	// it stay masked afterwards.
	priv := marker("PV")
	p.typ("\x1dp")
	deadline = time.Now().Add(3 * time.Second)
	for !a.state().Private && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}
	p.typ("echo " + priv + "\r")
	p.waitScreen(priv, 3*time.Second)
	if err := a.call("type", map[string]any{"text": "x"}, nil); proto.ErrorCode(err) != proto.ErrPrivateMode {
		t.Errorf("agent typed during private mode: %v", err)
	}
	p.waitScreen("PRIVATE", 3*time.Second)
	p.typ("\x1dp")
	deadline = time.Now().Add(3 * time.Second)
	for a.state().Private && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}
	if !strings.Contains(a.screenText(), "[private]") {
		t.Errorf("rows from private mode not masked:\n%s", a.screenText())
	}
	assertNoLeak(t, a, priv)
}

// TestConfirmPolicy: the Enter of an agent line waits for the person.
func TestConfirmPolicy(t *testing.T) {
	p, a, _ := newSession(t, []string{"--policy", "confirm"}, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	waitQuiet(t, a)
	var sent proto.Sent
	if err := a.call("type", map[string]any{"text": "echo confirmed-$((2+3))\r"}, &sent); err != nil || !sent.HeldEnter {
		t.Fatalf("type: %+v %v", sent, err)
	}
	p.waitScreen("agent wants to run: $ echo confirmed-$((2+3))", 3*time.Second)
	if err := a.call("type", map[string]any{"text": "x"}, nil); proto.ErrorCode(err) != proto.ErrConfirmationPending {
		t.Errorf("second line while pending: %v", err)
	}
	if err := a.call("type", map[string]any{"text": "\x0f"}, nil); proto.ErrorCode(err) == "" {
		t.Errorf("control character accepted under confirm")
	}
	from := p.mark()
	p.typ("\x1dy")
	p.waitOutput(from, "confirmed-5", 5*time.Second)

	// Rejection: the line stays typed, nothing runs.
	waitQuiet(t, a)
	if err := a.call("type", map[string]any{"text": "echo rejected-$((3+4))", "enter": true}, &sent); err != nil {
		t.Fatal(err)
	}
	from = p.mark()
	p.waitScreen("agent wants to run", 3*time.Second)
	p.typ("\x1dn")
	time.Sleep(800 * time.Millisecond)
	if strings.Contains(p.output()[from:], "rejected-7") {
		t.Errorf("a rejected line ran")
	}
}

// TestPersonAdmission: who may attach as the person.
func TestPersonAdmission(t *testing.T) {
	p, _, name := newSession(t, nil, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")

	// The test binary is not cotty: role denied.
	cl, err := proto.Dial(socketPath(name))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.Hello(context.Background(), proto.Hello{Role: proto.RolePerson})
	_ = cl.Close()
	if proto.ErrorCode(err) != proto.ErrRoleDenied {
		t.Errorf("non-cotty person hello: %v", err)
	}

	// A command typed in the session cannot attach as the person.
	from := p.mark()
	p.typ("cotty attach " + name + "; echo inner-rc=$?\r")
	p.waitOutput(from, "inner-rc=1", 10*time.Second)
	if !strings.Contains(p.output()[from:], "not classified as a person") {
		t.Errorf("inner attach: %q", p.output()[from:])
	}

	// A second person from another terminal proves the reattach code
	// (shown with ^] c in the attached client), then waits for the
	// attached person's approval (review N1: the code on every admission,
	// approval as a second gate).
	p.typ("\x1dc")
	p.waitScreen("reattach code:", 5*time.Second)
	cm := regexp.MustCompile(`reattach code: ([0-9A-Z]{5}-[0-9A-Z]{5})`).FindStringSubmatch(p.statusLine())
	if cm == nil {
		t.Fatalf("no code in the status line: %q", p.statusLine())
	}
	q := startPerson(t, "attach", name)
	q.waitOutput(0, "Reattach code", 5*time.Second)
	q.typ(cm[1] + "\r")
	p.waitScreen("attach request", 5*time.Second)
	time.Sleep(200 * time.Millisecond)
	p.typ("\x1da")
	q.waitScreen("cotty:"+name, 5*time.Second)
	// The new person sees the session as it is.
	q.waitScreen("inner-rc=1", 3*time.Second)

	// Both detach; reattach needs the code.
	q.typ("\x1dd")
	q.waitExit(5 * time.Second)
	p.typ("\x1dd")
	p.waitExit(5 * time.Second)
	re := regexp.MustCompile(`reattach code ([0-9A-Z]{5}-[0-9A-Z]{5})`)
	mm := re.FindStringSubmatch(p.output())
	if mm == nil {
		t.Fatalf("no reattach code printed: %q", p.output()[max(0, len(p.output())-300):])
	}
	r := startPerson(t, "attach", name)
	r.waitOutput(0, "Reattach code", 5*time.Second)
	r.typ("00000-00000\r")
	r.waitOutput(0, "wrong code", 5*time.Second)
	r.waitOutput(0, "Reattach code", 5*time.Second)
	r.typ(mm[1] + "\r")
	r.waitScreen("cotty:"+name, 5*time.Second)
	from = r.mark()
	r.typ("echo back-$((5*5))\r")
	r.waitOutput(from, "back-25", 5*time.Second)
}

// TestNotShared: agents cannot connect to a session that is not shared.
func TestNotShared(t *testing.T) {
	name := "ns" + marker("")[:8]
	p := startPerson(t, "new", "--name", name, "--", "bash", "--norc", "--noprofile")
	p.waitScreen("cotty:"+name, 10*time.Second)
	t.Cleanup(func() { killSession(name) })
	cl, err := proto.Dial(socketPath(name))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := cl.Hello(context.Background(), proto.Hello{Role: proto.RoleAgent}); proto.ErrorCode(err) != proto.ErrNotShared {
		t.Errorf("agent hello on unshared session: %v", err)
	}
	// ^] s shares it.
	p.typ("\x1ds")
	time.Sleep(300 * time.Millisecond)
	dialAgent(t, name)
}

// TestLeakCheckWorks is the control for assertNoLeak: text typed with
// echo on does reach the agent and is found.
func TestLeakCheckWorks(t *testing.T) {
	p, a, _ := newSession(t, nil, "bash", "--norc", "--noprofile")
	time.Sleep(300 * time.Millisecond)
	m := marker("VIS")
	p.typ("echo " + m + "\r")
	a.waitScreen(m, 5*time.Second)
	if !strings.Contains(a.all(), m) {
		t.Fatal("control marker not found in what the agent received")
	}
	// The audit log has the session's events, and no person keystrokes.
	files := leakFiles(t)
	for _, ev := range []string{`"event":"session.start"`, `"event":"attach"`} {
		if !strings.Contains(files, ev) {
			t.Errorf("audit log lacks %s", ev)
		}
	}
	if strings.Contains(files, m) {
		t.Error("person keystrokes (echo on) are in the audit log")
	}
}

// sudoAuth authenticates sudo once in the session (the person types the
// password at the lock), so later sudo commands run without a prompt.
func sudoAuth(t *testing.T, p *person, a *agent, pw string) {
	t.Helper()
	from := p.mark()
	p.typ("sudo -k; sudo -v; echo auth-$((40+2))\r")
	st := a.waitSecret(proto.SecretActive, 15*time.Second)
	if st.SecretProgram == nil || !strings.HasPrefix(st.SecretProgram.Name, "sudo") || st.SecretProgram.Trust != proto.TrustSystem {
		t.Errorf("sudo prompt judged %+v, want sudo (system)", st.SecretProgram)
	}
	p.typeSlowly(pw)
	p.typ("\r")
	a.waitSecret(proto.SecretNone, 15*time.Second)
	p.waitOutput(from, "auth-42", 15*time.Second)
}

// TestSudoCommandsNotSecret: once sudo has run the command it was given
// (sudo vim, sudo -i, sudo -s, sudo less), the command reads the keys, not
// sudo: no secret input, also where sudo relays the terminal in raw mode
// (sudo-rs, Ubuntu 26.04).
func TestSudoCommandsNotSecret(t *testing.T) {
	pw := password(t)
	p, a, _ := newSession(t, nil, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	time.Sleep(300 * time.Millisecond)
	sudoAuth(t, p, a, pw)
	steps := []struct {
		keys, after string
	}{
		{"sudo vim -u NONE -N /tmp/cotty-it-sudo.txt\r", ""},
		{"ihello\x1b:q!\r", "$ "},
		{"sudo -i\r", ""},
		{"echo root-$((40+2)) $(id -u)\r", "root-42 0"},
		{"exit\r", "$ "},
		{"sudo -s\r", ""},
		{"echo shell-$((40+2))\r", "shell-42"},
		{"exit\r", "$ "},
		{"sudo less /etc/hosts\r", ""},
		{"q", "$ "},
	}
	for _, s := range steps {
		from := p.mark()
		p.typ(s.keys)
		deadline := time.Now().Add(1500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if st := a.state(); st.SecretInput == proto.SecretActive {
				t.Fatalf("after %q: secret input %+v", s.keys, st.SecretProgram)
			}
			time.Sleep(50 * time.Millisecond)
		}
		if s.after != "" {
			p.waitOutput(from, s.after, 10*time.Second)
		}
	}
	// The agent can type in a root shell sudo started.
	p.typ("sudo -i\r")
	time.Sleep(1500 * time.Millisecond)
	waitQuiet(t, a)
	if err := a.call("type", map[string]any{"text": "echo agent-$((40+2)); exit", "enter": true}, nil); err != nil {
		t.Fatalf("agent typing in sudo -i: %v", err)
	}
	a.waitScreen("agent-42", 10*time.Second)
	assertNoLeak(t, a, pw)
}

// TestSudoWrongPasswordRetry: a wrong password, then the right one: the
// prompt is secret both times and neither reaches the agent; marks the
// prompt prints per key (sudo-rs's asterisks) are hidden from agents.
func TestSudoWrongPasswordRetry(t *testing.T) {
	pw := password(t)
	wrong := marker("WP")
	p, a, _ := newSession(t, nil, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	time.Sleep(300 * time.Millisecond)
	from := p.mark()
	p.typ("sudo -k; sudo true; echo retry-rc=$?-$((40+2))\r")
	a.waitSecret(proto.SecretActive, 15*time.Second)
	p.typeSlowly(wrong)
	// While the prompt is active the agent's screen shows no key marks.
	if sc := a.screenText(); strings.Contains(sc, "**") {
		t.Errorf("key marks visible to the agent during the prompt: %q", sc)
	}
	p.typ("\r")
	// The retry prompt is secret again.
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(p.output()[from:], "try again") && !strings.Contains(p.output()[from:], "Sorry") && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	st := a.waitSecret(proto.SecretActive, 15*time.Second)
	if st.SecretProgram == nil || !strings.HasPrefix(st.SecretProgram.Name, "sudo") {
		t.Errorf("retry prompt judged %+v", st.SecretProgram)
	}
	p.typeSlowly(pw)
	p.typ("\r")
	a.waitSecret(proto.SecretNone, 15*time.Second)
	p.waitOutput(from, "retry-rc=0-42", 15*time.Second)
	waitQuiet(t, a)
	if all := a.all(); strings.Contains(all, "**") {
		t.Errorf("key marks visible to the agent after the prompt")
	}
	assertNoLeak(t, a, pw, wrong)
}

// TestSudoFromScriptDetected (review T3): a script, a subshell or a
// Makefile that runs sudo more than half a second after it took the
// terminal. With sudo-rs (raw mode, Ubuntu 26.04) only the members of the
// foreground group show the prompt, and they must be judged fresh, not as
// described while the group was young.
func TestSudoFromScriptDetected(t *testing.T) {
	pw := password(t)
	p, a, _ := newSession(t, nil, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	time.Sleep(300 * time.Millisecond)
	p.typ("printf 'all:\\n\\t@sleep 1\\n\\t@sudo true\\n' > /tmp/cotty-it-make.mk\r")
	time.Sleep(300 * time.Millisecond)
	cases := []struct{ name, line string }{
		{"sh -c", "sudo -k; sh -c 'sleep 1; sudo true'; echo late-rc=$?-$((40+2))\r"},
		{"subshell", "sudo -k; (sleep 1; sudo true); echo late-rc=$?-$((40+2))\r"},
		{"make", "sudo -k; make -s -f /tmp/cotty-it-make.mk 2>/dev/null || sh -c 'sleep 1; sudo true'; echo late-rc=$?-$((40+2))\r"},
	}
	for _, tc := range cases {
		from := p.mark()
		p.typ(tc.line)
		st := a.waitSecret(proto.SecretActive, 15*time.Second)
		// The lock judges the whole group: the script's shell is a member
		// too ("dash (as sh) | sudo", amber), which is right.
		if st.SecretProgram == nil || !strings.Contains(st.SecretProgram.Name, "sudo") {
			t.Errorf("%s: prompt judged %+v, want sudo among the members", tc.name, st.SecretProgram)
		}
		p.typeSlowly(pw)
		if sc := a.screenText(); strings.Contains(sc, "**") {
			t.Errorf("%s: key marks visible to the agent during the prompt: %q", tc.name, sc)
		}
		p.typ("\r")
		a.waitSecret(proto.SecretNone, 15*time.Second)
		p.waitOutput(from, "late-rc=0-42", 15*time.Second)
		waitQuiet(t, a)
	}
	if strings.Contains(a.all(), "**") {
		t.Errorf("key marks visible to the agent after the prompts")
	}
	assertNoLeak(t, a, pw)
}
