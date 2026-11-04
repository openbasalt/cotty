//go:build vmtest

// Package integration drives real cotty sessions: a scripted person types
// into `cotty new` / `cotty attach` through a PTY the test owns (like a
// terminal emulator would), and a test agent connects to the session
// socket. Run only inside the lab VM (tests/lab/vm-broker.sh test): it
// starts shells, sudo and ssh prompts.
//
// Environment: COTTY_BIN (installed, root-owned cotty), and
// COTTY_TEST_PASSWORD_FILE (the test user's password, typed at real sudo,
// su, passwd and ssh prompts).
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/vt"
	"github.com/creack/pty"

	"github.com/openbasalt/cotty/internal/proto"
)

const (
	outerRows = 30
	outerCols = 110
)

func cottyBin(t *testing.T) string {
	b := os.Getenv("COTTY_BIN")
	if b == "" {
		t.Skip("COTTY_BIN not set (run through tests/lab/vm-broker.sh test)")
	}
	return b
}

func password(t *testing.T) string {
	p := os.Getenv("COTTY_TEST_PASSWORD_FILE")
	if p == "" {
		t.Skip("COTTY_TEST_PASSWORD_FILE not set")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// marker returns a random string to type at a prompt and search for later.
func marker(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

func runtimeDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "cotty")
	}
	return filepath.Join(os.TempDir(), "cotty-"+strconv.Itoa(os.Getuid()))
}

func socketPath(name string) string { return filepath.Join(runtimeDir(), name+".sock") }

// person is a terminal the test drives: a PTY whose slave runs cotty.
type person struct {
	t    *testing.T
	cmd  *exec.Cmd
	pty  *os.File
	mu   sync.Mutex
	raw  bytes.Buffer
	emu  *vt.SafeEmulator
	done chan struct{}
}

// startPerson runs `cotty args...` on a new terminal (its own session
// and controlling terminal, like a terminal emulator tab).
func startPerson(t *testing.T, args ...string) *person {
	t.Helper()
	cmd := exec.Command(cottyBin(t), args...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: outerRows, Cols: outerCols})
	if err != nil {
		t.Fatal(err)
	}
	p := &person{t: t, cmd: cmd, pty: f, emu: vt.NewSafeEmulator(outerCols, outerRows), done: make(chan struct{})}
	// The emulator answers terminal queries, as the person's terminal would.
	go func() { _, _ = io.Copy(f, p.emu) }()
	go func() {
		defer close(p.done)
		buf := make([]byte, 32<<10)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				p.mu.Lock()
				p.raw.Write(buf[:n])
				p.mu.Unlock()
				_, _ = p.emu.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
		_ = f.Close()
		_ = cmd.Wait()
	})
	return p
}

func (p *person) typ(s string) {
	p.t.Helper()
	if _, err := p.pty.Write([]byte(s)); err != nil {
		p.t.Fatalf("person typing: %v", err)
	}
}

// typeSlowly types like a person, one key at a time.
func (p *person) typeSlowly(s string) {
	for _, r := range s {
		p.typ(string(r))
		time.Sleep(15 * time.Millisecond)
	}
}

func (p *person) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.raw.String()
}

func (p *person) mark() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.raw.Len()
}

// screen returns the rows of the person's terminal (including cotty's
// status line in the last row).
func (p *person) screen() []string {
	out := make([]string, outerRows)
	for y := 0; y < outerRows; y++ {
		var b strings.Builder
		for x := 0; x < outerCols; {
			c := p.emu.CellAt(x, y)
			if c == nil || c.Content == "" {
				b.WriteByte(' ')
				x++
				continue
			}
			b.WriteString(c.Content)
			x += max(c.Width, 1)
		}
		out[y] = strings.TrimRight(b.String(), " ")
	}
	return out
}

func (p *person) statusLine() string { return p.screen()[outerRows-1] }

// waitOutput waits until the raw output after mark contains s.
func (p *person) waitOutput(from int, s string, d time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		ok := p.raw.Len() >= from && strings.Contains(p.raw.String()[from:], s)
		p.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.t.Fatalf("person's terminal never showed %q; screen:\n%s", s, strings.Join(p.screen(), "\n"))
}

func (p *person) waitScreen(s string, d time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(p.screen(), "\n"), s) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.t.Fatalf("person's screen never showed %q:\n%s", s, strings.Join(p.screen(), "\n"))
}

func (p *person) waitExit(d time.Duration) {
	select {
	case <-p.done:
	case <-time.After(d):
		p.t.Fatalf("cotty did not exit; screen:\n%s", strings.Join(p.screen(), "\n"))
	}
}

// agent is a test agent on the session socket. Everything it receives is
// kept in seen, to search for markers.
type agent struct {
	t    *testing.T
	cl   *proto.Client
	mu   sync.Mutex
	seen bytes.Buffer
}

func dialAgent(t *testing.T, name string) *agent {
	t.Helper()
	var cl *proto.Client
	var err error
	for i := 0; i < 100; i++ {
		if cl, err = proto.Dial(socketPath(name)); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{t: t, cl: cl}
	h, err := cl.Hello(context.Background(), proto.Hello{Role: proto.RoleAgent, Client: "cotty-it"})
	if err != nil {
		t.Fatalf("agent hello: %v", err)
	}
	a.record(h)
	if err := cl.Call(context.Background(), "subscribe", map[string][]string{"events": {"state", "output"}}, nil); err != nil {
		t.Fatal(err)
	}
	go func() {
		for ev := range cl.Events() {
			a.mu.Lock()
			a.seen.Write(ev.Data)
			a.mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = cl.Close() })
	return a
}

func (a *agent) record(v any) {
	b, _ := json.Marshal(v)
	a.mu.Lock()
	a.seen.Write(b)
	a.seen.WriteByte('\n')
	a.mu.Unlock()
}

func (a *agent) call(op string, args, out any) error {
	var raw json.RawMessage
	err := a.cl.Call(context.Background(), op, args, &raw)
	a.mu.Lock()
	a.seen.Write(raw)
	a.seen.WriteByte('\n')
	a.mu.Unlock()
	if err == nil && out != nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, out)
	}
	return err
}

func (a *agent) state() proto.State {
	a.t.Helper()
	var s proto.State
	if err := a.call("state", nil, &s); err != nil {
		a.t.Fatalf("state: %v", err)
	}
	return s
}

func (a *agent) screen() proto.Screen {
	a.t.Helper()
	var s proto.Screen
	if err := a.call("screen", nil, &s); err != nil {
		a.t.Fatalf("screen: %v", err)
	}
	return s
}

func (a *agent) screenText() string { return strings.Join(a.screen().Rows, "\n") }

// waitSecret polls until secret_input has the wanted value.
func (a *agent) waitSecret(want string, d time.Duration) proto.State {
	a.t.Helper()
	deadline := time.Now().Add(d)
	var s proto.State
	for time.Now().Before(deadline) {
		s = a.state()
		if s.SecretInput == want {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	a.t.Fatalf("secret_input never became %q (last state %+v)\nagent screen:\n%s", want, s, a.screenText())
	return s
}

// waitScreen waits until the agent's (masked) screen contains s.
func (a *agent) waitScreen(s string, d time.Duration) {
	a.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(a.screenText(), s) {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	a.t.Fatalf("agent screen never showed %q:\n%s", s, a.screenText())
}

// all returns everything the agent received, plus a full read of the
// committed lines and the screen.
func (a *agent) all() string {
	var sn proto.Since
	_ = a.call("since", map[string]int{"cursor": 0, "limit": 5000}, &sn)
	_ = a.call("screen", map[string]int{"context": 200}, nil)
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seen.String()
}

// newSession starts `cotty new` for a person and returns it with an agent.
func newSession(t *testing.T, extra []string, shell ...string) (*person, *agent, string) {
	t.Helper()
	name := "it" + marker("")[:8]
	args := append([]string{"new", "--name", name, "--ai"}, extra...)
	if len(shell) > 0 {
		args = append(append(args, "--"), shell...)
	}
	p := startPerson(t, args...)
	a := dialAgent(t, name)
	p.waitScreen("cotty:"+name, 10*time.Second)
	t.Cleanup(func() { killSession(name) })
	return p, a, name
}

func killSession(name string) {
	b, err := os.ReadFile(filepath.Join(runtimeDir(), name+".json"))
	if err != nil {
		return
	}
	var m struct {
		BrokerPID int `json:"broker_pid"`
	}
	if json.Unmarshal(b, &m) == nil && m.BrokerPID > 0 {
		_ = syscall.Kill(m.BrokerPID, syscall.SIGTERM)
	}
}

// waitQuiet waits until the agent may type (the person stopped typing).
func waitQuiet(t *testing.T, a *agent) {
	t.Helper()
	// Keystrokes typed just before may still be on their way through the
	// attach client.
	time.Sleep(300 * time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	ok := 0
	for time.Now().Before(deadline) {
		if a.state().AgentMayType {
			if ok++; ok == 2 {
				return
			}
		} else {
			ok = 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("agent never allowed to type: %+v", a.state())
}

// leakFiles returns the audit log and the broker logs.
func leakFiles(t *testing.T) string {
	var b strings.Builder
	home, _ := os.UserHomeDir()
	if data, err := os.ReadFile(filepath.Join(home, ".local", "state", "cotty", "audit.jsonl")); err == nil {
		b.Write(data)
	}
	logs, _ := filepath.Glob(filepath.Join(runtimeDir(), "*.log"))
	for _, l := range logs {
		if data, err := os.ReadFile(l); err == nil {
			b.Write(data)
		}
	}
	return b.String()
}

// assertNoLeak checks that none of the secrets appears in what the agent
// received, in the audit log or in the broker logs.
func assertNoLeak(t *testing.T, a *agent, secrets ...string) {
	t.Helper()
	seen := a.all()
	files := leakFiles(t)
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(seen, s) {
			t.Errorf("a secret typed by the person reached the agent")
		}
		if strings.Contains(files, s) {
			t.Errorf("a secret typed by the person is in the audit log or a broker log")
		}
	}
}
