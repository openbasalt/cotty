//go:build vmtest

// Package e2e drives `cotty mcp` end to end: a scripted person types into
// `cotty new` through a PTY the test owns, and an MCP client (the test
// playing the agent, or a real agent CLI) talks JSON-RPC to `cotty mcp`
// over stdio. Run only inside the lab VM (tests/e2e/vm.sh): it starts
// shells and real sudo prompts.
//
// Environment: COTTY_BIN (installed, root-owned cotty) and
// COTTY_TEST_PASSWORD_FILE (the test user's password, typed at sudo).
//
// The person harness is adapted from tests/integration/harness_test.go
// (WP-A); test packages cannot import each other.
package e2e

import (
	"bufio"
	"bytes"
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
)

const (
	outerRows = 30
	outerCols = 110
)

func cottyBin(t *testing.T) string {
	b := os.Getenv("COTTY_BIN")
	if b == "" {
		t.Skip("COTTY_BIN not set (run through tests/e2e/vm.sh)")
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

// cleanEnv is the environment for cotty processes: never an agent
// credential (the real-agent test has one in its own environment).
func cleanEnv(extra ...string) []string {
	var out []string
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		switch k {
		case "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_TOKEN_FILE":
			continue
		}
		out = append(out, e)
	}
	return append(out, extra...)
}

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

func startPerson(t *testing.T, args ...string) *person {
	t.Helper()
	cmd := exec.Command(cottyBin(t), args...)
	cmd.Env = cleanEnv("TERM=xterm-256color")
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: outerRows, Cols: outerCols})
	if err != nil {
		t.Fatal(err)
	}
	p := &person{t: t, cmd: cmd, pty: f, emu: vt.NewSafeEmulator(outerCols, outerRows), done: make(chan struct{})}
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

func (p *person) waitOutput(from int, s string, d time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if out := p.output(); len(out) >= from && strings.Contains(out[from:], s) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.t.Fatalf("person's terminal never showed %q; screen:\n%s", s, strings.Join(p.screen(), "\n"))
}

// newSession starts `cotty new` for a person.
func newSession(t *testing.T, extra []string, shell ...string) (*person, string) {
	t.Helper()
	name := "e2e" + marker("")[:8]
	args := append([]string{"new", "--name", name}, extra...)
	if len(shell) > 0 {
		args = append(append(args, "--"), shell...)
	}
	p := startPerson(t, args...)
	p.waitScreen("cotty:"+name, 10*time.Second)
	t.Cleanup(func() { killSession(name) })
	return p, name
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

// mcpClient runs `cotty mcp` and speaks JSON-RPC to it, like an agent
// CLI. Every byte the server sends is kept in seen.
type mcpClient struct {
	t       *testing.T
	cmd     *exec.Cmd
	in      io.WriteCloser
	rd      *bufio.Reader
	id      int
	logPath string
	mu      sync.Mutex
	seen    bytes.Buffer
}

func startMCP(t *testing.T, args ...string) *mcpClient {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "mcp.log")
	cmd := exec.Command(cottyBin(t), append([]string{"mcp", "--log", logPath}, args...)...)
	cmd.Env = cleanEnv()
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// The test process has no controlling terminal of a cotty session, but
	// own its own session anyway, as an agent CLI's child would.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &mcpClient{t: t, cmd: cmd, in: in, rd: bufio.NewReaderSize(out, 1<<20), logPath: logPath}
	t.Cleanup(func() {
		_ = in.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
		if t.Failed() {
			t.Logf("cotty mcp stderr:\n%s", stderr.String())
		}
	})
	m := c.rpc("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "cotty-e2e", "version": "1"}})
	if m["result"] == nil {
		t.Fatalf("initialize: %v", m)
	}
	c.notify("notifications/initialized")
	return c
}

func (c *mcpClient) notify(method string) {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	_, _ = c.in.Write(append(b, '\n'))
}

// send writes a request and returns its id; recv reads the answer.
func (c *mcpClient) send(method string, params any) int {
	c.t.Helper()
	c.id++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	if _, err := c.in.Write(append(b, '\n')); err != nil {
		c.t.Fatal(err)
	}
	return c.id
}

func (c *mcpClient) recv(id int) map[string]any {
	c.t.Helper()
	type line struct {
		b   []byte
		err error
	}
	ch := make(chan line, 1)
	go func() { b, err := c.rd.ReadBytes('\n'); ch <- line{b, err} }()
	var l line
	select {
	case l = <-ch:
	case <-time.After(6 * time.Minute):
		c.t.Fatal("cotty mcp did not answer")
	}
	if l.err != nil {
		c.t.Fatalf("cotty mcp: %v", l.err)
	}
	c.mu.Lock()
	c.seen.Write(l.b)
	c.mu.Unlock()
	var m map[string]any
	if err := json.Unmarshal(l.b, &m); err != nil {
		c.t.Fatal(err)
	}
	if got, _ := m["id"].(float64); int(got) != id {
		c.t.Fatalf("answer for id %v, want %d", m["id"], id)
	}
	return m
}

func (c *mcpClient) rpc(method string, params any) map[string]any {
	c.t.Helper()
	return c.recv(c.send(method, params))
}

// toolText unpacks a tools/call answer.
func toolText(t *testing.T, m map[string]any) (string, bool) {
	t.Helper()
	res, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/call: %v", m)
	}
	content := res["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	isErr, _ := res["isError"].(bool)
	return text, isErr
}

func (c *mcpClient) startTool(name string, args map[string]any) int {
	return c.send("tools/call", map[string]any{"name": name, "arguments": args})
}

func (c *mcpClient) tool(name string, args map[string]any) (string, bool) {
	c.t.Helper()
	text, isErr := toolText(c.t, c.recv(c.startTool(name, args)))
	c.t.Logf("%s %v -> isError=%v\n%s", name, args, isErr, indent(text))
	return text, isErr
}

func indent(s string) string { return "    " + strings.ReplaceAll(s, "\n", "\n    ") }

// mustTool calls a tool that must succeed and contain every want.
func (c *mcpClient) mustTool(name string, args map[string]any, want ...string) string {
	c.t.Helper()
	text, isErr := c.tool(name, args)
	if isErr {
		c.t.Fatalf("%s failed:\n%s", name, text)
	}
	for _, w := range want {
		if !strings.Contains(text, w) {
			c.t.Fatalf("%s: no %q in:\n%s", name, w, text)
		}
	}
	return text
}

// wantError calls a tool that must fail with one of the codes.
func (c *mcpClient) wantError(name string, args map[string]any, codes ...string) string {
	c.t.Helper()
	text, isErr := c.tool(name, args)
	if !isErr {
		c.t.Fatalf("%s succeeded, want error %v:\n%s", name, codes, text)
	}
	for _, code := range codes {
		if strings.Contains(text, "error: "+code+"\n") || strings.HasSuffix(text, "error: "+code) {
			return text
		}
	}
	c.t.Fatalf("%s: want error %v, got:\n%s", name, codes, text)
	return text
}

func (c *mcpClient) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen.String()
}

// leakFiles returns the audit log and the broker logs.
func leakFiles() string {
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

// assertNoLeak checks that no secret appears in anything the MCP server
// sent, in its log, in the audit log or in the broker logs. It also
// checks that the places it searches are not empty, so a broken capture
// cannot pass.
func assertNoLeak(t *testing.T, c *mcpClient, secrets ...string) {
	t.Helper()
	seen := c.all()
	mlog, _ := os.ReadFile(c.logPath)
	files := leakFiles()
	if len(seen) == 0 || len(mlog) == 0 || !strings.Contains(files, `"event"`) {
		t.Fatalf("leak check has nothing to search: responses %d bytes, mcp log %d bytes, audit %d bytes", len(seen), len(mlog), len(files))
	}
	for i, s := range secrets {
		if s == "" {
			continue
		}
		where := map[string]string{"an MCP response": seen, "the MCP server log": string(mlog), "the audit log or a broker log": files}
		for w, text := range where {
			if strings.Contains(text, s) {
				t.Errorf("secret %d reached %s", i, w)
			}
		}
	}
}

func mustContain(t *testing.T, text string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Fatalf("no %q in:\n%s", w, text)
		}
	}
}
