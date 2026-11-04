//go:build vmtest

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMCPSudo is the main end to end case: the agent (this test, through
// cotty mcp) runs commands, hits `sudo -v`, is refused while the person
// types the real sudo password, waits for secret_ended and reads the
// result. The password never reaches anything the agent received.
func TestMCPSudo(t *testing.T) {
	pw := password(t)
	p, name := newSession(t, []string{"--ai"}, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	time.Sleep(2 * time.Second) // the person's typing window ends

	c := startMCP(t)
	tools := c.rpc("tools/list", map[string]any{})["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 8 {
		t.Fatalf("%d tools", len(tools))
	}
	c.mustTool("term_sessions", nil, "- "+name+":")

	c.mustTool("term_run", map[string]any{"session": name, "command": "echo hello-$((6*7))"},
		"status: done", "hello-42")

	from := p.mark()
	text := c.mustTool("term_run", map[string]any{"session": name, "command": "sudo -k; sudo -v; echo sudo-rc=$?-$((40+2))", "timeout_s": 20},
		"status: secret_prompt", "sudo", "green lock", "for=secret_ended")
	if strings.Contains(text, "sudo-rc=") {
		t.Fatalf("the command finished before the password:\n%s", text)
	}
	p.waitScreen("LOCK sudo", 3*time.Second)

	// The agent cannot type during the prompt, through any tool.
	c.wantError("term_type", map[string]any{"session": name, "text": "agent-guess", "enter": true}, "secret_input_active")
	c.wantError("term_keys", map[string]any{"session": name, "keys": []string{"Enter"}}, "secret_input_active")
	c.wantError("term_run", map[string]any{"session": name, "command": "true"}, "secret_input_active")
	c.mustTool("term_read", map[string]any{"session": name}, "secret prompt: ACTIVE, sudo")

	// The agent waits; meanwhile the person types the password.
	id := c.startTool("term_wait", map[string]any{"session": name, "for": "secret_ended", "timeout_s": 60})
	time.Sleep(500 * time.Millisecond)
	p.typeSlowly(pw)
	p.typ("\r")
	text, isErr := toolText(t, c.recv(id))
	if isErr || !strings.Contains(text, "matched: true") || !strings.Contains(text, "reason: secret_ended") {
		t.Fatalf("term_wait secret_ended:\n%s", text)
	}
	p.waitOutput(from, "sudo-rc=0-42", 15*time.Second)
	c.mustTool("term_wait", map[string]any{"session": name, "for": "regex", "pattern": `sudo-rc=\d+-42`, "timeout_s": 15}, "matched: true", "sudo-rc=0-42")
	c.mustTool("term_read", map[string]any{"session": name}, "sudo-rc=0-42", "secret prompt: none")
	c.mustTool("term_read", map[string]any{"session": name, "mode": "since", "cursor": 0}, "next_cursor:")

	// The person's terminal never echoed it either.
	if strings.Contains(p.output()[from:], pw) {
		t.Errorf("the password was echoed on the person's terminal")
	}
	assertNoLeak(t, c, pw)
}

// TestMCPMaskedSecret: values on the masking list (secrets.conf, read by
// the broker at start or later by name through term_mask) never reach the
// agent: printed plainly, split by colour escape sequences, wrapped across
// rows, read as the screen, as scrollback and through term_run.
func TestMCPMaskedSecret(t *testing.T) {
	cfgHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	dir := filepath.Join(cfgHome, "cotty")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	value := marker("MV")
	later := marker("LV")
	writeConf := func(names ...string) {
		var conf, env strings.Builder
		conf.WriteString("[secrets]\n")
		for _, n := range names {
			fmt.Fprintf(&conf, "%s = file:%s\n", n, n)
		}
		fmt.Fprintf(&env, "E2E_TOKEN=%s\nE2E_LATER=%s\n", value, later)
		for p, c := range map[string]string{"secrets.conf": conf.String(), "secrets.env": env.String()} {
			if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeConf("E2E_TOKEN")

	files := t.TempDir()
	put := func(name, content string) string {
		p := filepath.Join(files, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	plain := put("plain", "token: "+value+"\n")
	// The emulator renders colour codes away; the masker sees the text.
	colour := put("colour", "c: "+value[:5]+"\x1b[31m"+value[5:11]+"\x1b[0;1;4m"+value[11:]+"\x1b[0m end\n")
	// The value wraps from one row into the next.
	wrap := put("wrap", strings.Repeat("w", outerCols-8)+value+"\n")
	laterFile := put("later", "later: "+later+"\n")

	p, name := newSession(t, []string{"--ai"}, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	c := startMCP(t, "--session", name)
	time.Sleep(2 * time.Second)
	for _, f := range []string{plain, colour, wrap} {
		p.typ("cat " + f + "\r")
	}
	p.waitScreen("end", 5*time.Second)
	time.Sleep(1600 * time.Millisecond)
	text := c.mustTool("term_read", nil, "[masked:E2E_TOKEN]")
	if n := strings.Count(text, "[masked:E2E_TOKEN]"); n < 3 {
		t.Errorf("want 3 masked spans on screen, got %d:\n%s", n, text)
	}
	// Push it all into the scrollback and read it back.
	p.typ("for i in $(seq 60); do echo filler $i; done\r")
	p.waitScreen("filler 60", 5*time.Second)
	time.Sleep(1600 * time.Millisecond)
	text = c.mustTool("term_read", map[string]any{"mode": "since", "cursor": 0}, "[masked:E2E_TOKEN]")
	if n := strings.Count(text, "[masked:E2E_TOKEN]"); n < 3 {
		t.Errorf("want 3 masked spans in the scrollback, got %d:\n%s", n, text)
	}
	// The agent's own command output.
	c.mustTool("term_run", map[string]any{"command": "cat " + colour}, "status: done", "[masked:E2E_TOKEN]")

	// A secret added to secrets.conf after the session started is masked
	// once the agent asks for it by name; the value never comes back.
	writeConf("E2E_TOKEN", "E2E_LATER")
	c.mustTool("term_mask", map[string]any{"name": "E2E_LATER"}, "E2E_LATER")
	c.wantError("term_mask", map[string]any{"name": "E2E_NOPE"}, "unknown_secret")
	c.mustTool("term_run", map[string]any{"command": "cat " + laterFile}, "status: done", "[masked:E2E_LATER]")

	assertNoLeak(t, c, value, later)
	audit := leakFiles()
	mustContain(t, audit, `"mask.hit"`, "E2E_TOKEN")
}

// TestMCPPrivateMode: private mode freezes the agent's view and refuses
// its input; rows from that time read [private] afterwards.
func TestMCPPrivateMode(t *testing.T) {
	p, name := newSession(t, []string{"--ai"}, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	c := startMCP(t, "--session", name)
	time.Sleep(2 * time.Second)
	c.mustTool("term_run", map[string]any{"command": "echo before-private"}, "status: done", "before-private")

	priv := marker("PV")
	p.typ("\x1dp")
	p.waitScreen("PRIVATE", 3*time.Second)
	c.mustTool("term_read", nil, "private mode: ON")
	p.typ("echo " + priv + "\r")
	p.waitScreen(priv, 3*time.Second)
	time.Sleep(1600 * time.Millisecond)
	c.wantError("term_type", map[string]any{"text": "x"}, "private_mode")
	c.wantError("term_run", map[string]any{"command": "true"}, "private_mode")
	if text, _ := c.tool("term_read", nil); strings.Contains(text, priv) {
		t.Fatalf("private row visible:\n%s", text)
	}
	p.typ("\x1dp")
	deadline := time.Now().Add(3 * time.Second)
	for {
		text, _ := c.tool("term_read", nil)
		if strings.Contains(text, "private mode: off") {
			mustContain(t, text, "[private]")
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("private mode never ended:\n%s", text)
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(1600 * time.Millisecond)
	c.mustTool("term_run", map[string]any{"command": "echo after-private"}, "status: done", "after-private")
	assertNoLeak(t, c, priv)
}

// TestMCPConfirmPolicy: under --policy confirm the person approves each
// line; term_run waits for the answer and reports a rejection.
func TestMCPConfirmPolicy(t *testing.T) {
	p, name := newSession(t, []string{"--ai", "--policy", "confirm"}, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	c := startMCP(t, "--session", name)
	time.Sleep(2 * time.Second)

	id := c.startTool("term_run", map[string]any{"command": "echo confirmed-$((2+3))", "timeout_s": 30})
	p.waitScreen("agent wants to run: $ echo confirmed-$((2+3))", 5*time.Second)
	p.typ("\x1dy")
	text, isErr := toolText(t, c.recv(id))
	if isErr || !strings.Contains(text, "status: done") || !strings.Contains(text, "confirmed-5") {
		t.Fatalf("approved run:\n%s", text)
	}
	time.Sleep(1600 * time.Millisecond)

	id = c.startTool("term_run", map[string]any{"command": "echo rejected-$((3+4))", "timeout_s": 30})
	p.waitScreen("agent wants to run", 5*time.Second)
	from := p.mark()
	p.typ("\x1dn")
	text, isErr = toolText(t, c.recv(id))
	if isErr || !strings.Contains(text, "status: rejected") {
		t.Fatalf("rejected run:\n%s", text)
	}
	if strings.Contains(p.output()[from:], "rejected-7") {
		t.Errorf("a rejected line ran")
	}
	time.Sleep(1600 * time.Millisecond)
	// Control characters are refused under confirm; C-c is allowed.
	c.wantError("term_keys", map[string]any{"keys": []string{"C-o"}}, "policy_denied")
	c.mustTool("term_keys", map[string]any{"keys": []string{"C-c"}}, "sent:")

	// A pending line blocks more input; term_wait for=confirmation returns
	// when the person answers.
	time.Sleep(1600 * time.Millisecond)
	c.mustTool("term_type", map[string]any{"text": "echo pending-$((1+8))", "enter": true}, "held_enter: true")
	c.wantError("term_type", map[string]any{"text": "x"}, "confirmation_pending")
	id = c.startTool("term_wait", map[string]any{"for": "confirmation", "timeout_s": 30})
	time.Sleep(300 * time.Millisecond)
	from = p.mark()
	p.typ("\x1dy")
	text, isErr = toolText(t, c.recv(id))
	if isErr || !strings.Contains(text, "matched: true") {
		t.Fatalf("wait confirmation:\n%s", text)
	}
	p.waitOutput(from, "pending-9", 5*time.Second)
}

// TestMCPArbitration: the person typing and holding the keyboard.
func TestMCPArbitration(t *testing.T) {
	p, name := newSession(t, []string{"--ai"}, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	c := startMCP(t, "--session", name)
	time.Sleep(2 * time.Second)

	// The person types continuously: term_type retries once, then says so.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			p.typ("a")
			time.Sleep(200 * time.Millisecond)
		}
	}()
	time.Sleep(300 * time.Millisecond)
	c.wantError("term_type", map[string]any{"text": "x"}, "person_typing")
	close(stop)
	p.typ("\x15") // C-u clears the person's line
	time.Sleep(1600 * time.Millisecond)

	p.typ("\x1dk")
	p.waitScreen("KEYBOARD: you", 3*time.Second)
	time.Sleep(1600 * time.Millisecond)
	c.wantError("term_run", map[string]any{"command": "true"}, "keyboard_held")
	c.mustTool("term_request_keyboard", nil, "requested")
	c.mustTool("term_read", nil, "keyboard: held by the person", "your keyboard request is shown")
	p.typ("\x1dk")
	time.Sleep(1600 * time.Millisecond)
	c.mustTool("term_run", map[string]any{"command": "echo got-keyboard"}, "status: done", "got-keyboard")
}

// TestMCPNotShared: a session that is not shared is invisible and refused.
func TestMCPNotShared(t *testing.T) {
	p, name := newSession(t, nil, "bash", "--norc", "--noprofile")
	_ = p
	c := startMCP(t)
	if text, _ := c.tool("term_sessions", nil); strings.Contains(text, name) {
		t.Fatalf("unshared session listed:\n%s", text)
	}
	c.wantError("term_read", map[string]any{"session": name}, "not_shared")
	c.wantError("term_run", map[string]any{"session": name, "command": "id"}, "not_shared")
}

// TestMCPRunStatuses: interactive programs, timeouts and exit codes with
// and without shell integration.
func TestMCPRunStatuses(t *testing.T) {
	p, name := newSession(t, []string{"--ai"}, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	c := startMCP(t, "--session", name)
	time.Sleep(2 * time.Second)

	c.mustTool("term_run", map[string]any{"command": "sleep 2; echo slept"}, "status: done", "slept")
	c.mustTool("term_run", map[string]any{"command": "sleep 30", "timeout_s": 2}, "status: running")
	c.mustTool("term_keys", map[string]any{"keys": []string{"C-c"}}, "sent:")
	c.mustTool("term_wait", map[string]any{"for": "idle"}, "matched: true")
	c.mustTool("term_run", map[string]any{"command": "seq 1 300 | less"}, "status: interactive")
	c.mustTool("term_type", map[string]any{"text": "q"}, "sent:")
	c.mustTool("term_wait", map[string]any{"for": "idle"}, "matched: true")
	text := c.mustTool("term_run", map[string]any{"command": "seq 1 1000", "max_lines": 50}, "status: done", "1000", "earlier lines left out")
	if strings.Contains(text, "\n949\n") {
		t.Errorf("max_lines not applied")
	}
	c.mustTool("term_run", map[string]any{"command": "false"}, "status: done", "exit_code: unknown")

	// Shell integration (OSC 133, FinalTerm style) makes exit codes known.
	c.mustTool("term_run", map[string]any{"command": `PROMPT_COMMAND='printf "\033]133;D;%s\007\033]133;A\007" $?'; PS1='$ \[\033]133;B\007\]'; trap 'printf "\033]133;C\007"' DEBUG`}, "status: done")
	c.mustTool("term_run", map[string]any{"command": "(exit 3)"}, "status: done", "exit_code: 3")
	c.mustTool("term_run", map[string]any{"command": "echo ok"}, "status: done", "exit_code: 0", "ok")
}
