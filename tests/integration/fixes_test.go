//go:build vmtest

package integration

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

// osc133Bash sets up OSC 133 marks in bash as shells with integration do
// (review B1: fish, VTE, kitty, starship emit them).
const osc133Bash = "PS1=$'\\[\\e]133;A\\a\\]$ \\[\\e]133;B\\a\\]'; PS0=$'\\e]133;C\\a'\r"

// TestPrivateModeLastCommand (review B1): what the person runs in private
// mode never reaches last_command, the state or any event, during or
// after private mode.
func TestPrivateModeLastCommand(t *testing.T) {
	secret := marker("PV")
	p, a, _ := newSession(t, nil, "bash", "--norc", "--noprofile")
	p.typ(osc133Bash)
	time.Sleep(300 * time.Millisecond)
	from := p.mark()
	p.typ("echo before-$((40+2))\r")
	p.waitOutput(from, "before-42", 5*time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(a.state().Shell.LastCommand, "echo before") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if st := a.state(); !st.Shell.Integration || !strings.Contains(st.Shell.LastCommand, "echo before") {
		t.Fatalf("OSC 133 not seen: %+v", st.Shell)
	}
	p.typ("\x1dp")
	p.waitScreen("PRIVATE", 3*time.Second)
	from = p.mark()
	p.typ("export TOKEN=" + secret + "; echo private-$((40+2))\r")
	p.waitOutput(from, "private-42", 5*time.Second)
	time.Sleep(300 * time.Millisecond)
	st := a.state()
	if strings.Contains(st.Shell.LastCommand, secret) || !st.Private {
		t.Errorf("state during private mode: %+v", st.Shell)
	}
	p.typ("\x1dp")
	time.Sleep(500 * time.Millisecond)
	if st := a.state(); strings.Contains(st.Shell.LastCommand, secret) || st.Shell.LastCommand != "" {
		t.Errorf("last_command after private mode: %q", st.Shell.LastCommand)
	}
	assertNoLeak(t, a, secret)
}

// eventCounter is a second agent connection that counts state and output
// events.
type eventCounter struct {
	mu     sync.Mutex
	events []string
	cl     *proto.Client
}

func countEvents(t *testing.T, name string) *eventCounter {
	t.Helper()
	cl, err := proto.Dial(socketPath(name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Hello(context.Background(), proto.Hello{Role: proto.RoleAgent, Client: "cotty-it-events"}); err != nil {
		t.Fatal(err)
	}
	if err := cl.Call(context.Background(), "subscribe", map[string][]string{"events": {"state", "output"}}, nil); err != nil {
		t.Fatal(err)
	}
	e := &eventCounter{cl: cl}
	go func() {
		for ev := range cl.Events() {
			e.mu.Lock()
			e.events = append(e.events, ev.Event+" "+string(ev.Data))
			e.mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = cl.Close() })
	return e
}

func (e *eventCounter) mark() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.events)
}

func (e *eventCounter) since(from int) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events[from:]...)
}

// TestSecretPromptEvents (review B2): an agent subscribed to state and
// output gets no event per keystroke at a secret prompt.
func TestSecretPromptEvents(t *testing.T) {
	secret := marker("EV") // 18 characters
	p, a, name := newSession(t, nil, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	time.Sleep(300 * time.Millisecond)
	e := countEvents(t, name)
	p.typ("read -rs -p 'pw: ' V; echo; echo len=${#V}-$((40+2))\r")
	a.waitSecret(proto.SecretActive, 10*time.Second)
	time.Sleep(300 * time.Millisecond)
	from := e.mark()
	for _, r := range secret {
		p.typ(string(r))
		time.Sleep(80 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	during := e.since(from)
	if len(during) > 0 {
		t.Errorf("%d events while %d secret keys were typed: %q", len(during), len(secret), during)
	}
	out := p.mark()
	p.typ("\r")
	a.waitSecret(proto.SecretNone, 10*time.Second)
	p.waitOutput(out, "len=18-42", 5*time.Second)
	assertNoLeak(t, a, secret)
}

// TestAttachRefusesFakeListener (review B3): a process of the user that
// takes the session socket's place does not get the person's attach, and
// the reattach code is never typed to it.
func TestAttachRefusesFakeListener(t *testing.T) {
	p, _, name := newSession(t, nil, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	time.Sleep(300 * time.Millisecond)
	p.typ("\x1dd")
	p.waitExit(10 * time.Second)
	code := regexp.MustCompile(`reattach code ([0-9A-Z]{5}-[0-9A-Z]{5})`).FindStringSubmatch(p.output())
	if code == nil {
		t.Fatalf("no reattach code at detach: %q", p.output())
	}
	sock := socketPath(name)
	if err := os.Rename(sock, sock+".real"); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(sock, 0o600)
	var mu sync.Mutex
	var got strings.Builder
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					f, err := proto.ReadFrame(c)
					if err != nil {
						return
					}
					mu.Lock()
					got.Write(f.Payload)
					mu.Unlock()
					var req proto.Request
					_ = json.Unmarshal(f.Payload, &req)
					// Pose as a broker that wants the code, then admits anything.
					_ = proto.WriteJSON(c, proto.Response{ID: req.ID, Error: &proto.Error{Code: proto.ErrCodeRequired,
						Challenge: &proto.Challenge{Kind: proto.AuthCode, Nonce: strings.Repeat("00", 32),
							Salt: strings.Repeat("11", 16), Iterations: proto.CodeKDFIterations}}})
				}
			}(c)
		}
	}()
	q := startPerson(t, "attach", name)
	q.waitExit(15 * time.Second)
	_ = ln.Close()
	_ = os.Remove(sock)
	if err := os.Rename(sock+".real", sock); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q.output(), "not the session's broker") {
		t.Errorf("attach to a fake listener did not refuse: %q", q.output())
	}
	if strings.Contains(q.output(), "Reattach code") {
		t.Errorf("the person was asked for the code by a fake listener")
	}
	mu.Lock()
	seen := got.String()
	mu.Unlock()
	if strings.Contains(seen, code[1]) || strings.Contains(seen, strings.ReplaceAll(code[1], "-", "")) {
		t.Errorf("the reattach code reached the fake listener")
	}
	// The real session is still reachable with the real code, from a
	// fresh terminal (the wrong-code backoff is per terminal).
	r := startPerson(t, "attach", name)
	r.waitOutput(0, "Reattach code", 10*time.Second)
	r.typ(code[1] + "\r")
	r.waitScreen("cotty:"+name, 15*time.Second)
}

// TestFakeLockPipeline (review B6): a fake password prompt behind a
// trusted pipeline leader, started by the agent after a first job, gets
// the amber lock and the "started by agent" note.
func TestFakeLockPipeline(t *testing.T) {
	p, a, _ := newSession(t, nil, "bash", "--norc", "--noprofile")
	p.typ("PS1='$ '\r")
	waitQuiet(t, a)
	line := `sleep 3; sleep 600 | python3 -c 'import getpass; getpass.getpass("[sudo] password for x: ")'`
	if err := a.call("type", map[string]any{"text": line, "enter": true}, nil); err != nil {
		t.Fatalf("agent type: %v", err)
	}
	st := a.waitSecret(proto.SecretActive, 15*time.Second)
	sp := st.SecretProgram
	if sp == nil || sp.Trust != proto.TrustOther || !sp.AgentStarted || !strings.Contains(sp.Name, "python3") {
		t.Errorf("fake prompt judged %+v, want amber, agent-started, naming python3", sp)
	}
	p.waitScreen("not a system program", 3*time.Second)
	p.waitScreen("started by agent", 3*time.Second)
	p.typ("\x03")
	a.waitSecret(proto.SecretNone, 10*time.Second)
}

// TestTypeaheadNotEchoed (review S9): keys the person types ahead of a
// password prompt, before the program turned echo off, are not echoed.
func TestTypeaheadNotEchoed(t *testing.T) {
	secret := marker("TA")
	p, a, _ := newSession(t, nil, "sh")
	time.Sleep(400 * time.Millisecond)
	from := p.mark()
	// One write: the command, Enter, then the password typed ahead.
	p.typ("stty -echo; read V; stty echo; echo; echo tlen=${#V}-$((40+2))\r" + secret + "\r")
	p.waitOutput(from, "tlen=18-42", 10*time.Second)
	if strings.Contains(p.output()[from:], secret) {
		t.Errorf("typeahead was echoed on the person's terminal")
	}
	assertNoLeak(t, a, secret)
}
