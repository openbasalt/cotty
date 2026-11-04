package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

// fakeBroker speaks the broker protocol on a socket, with a scripted
// screen and state. Pure unit test: no PTY, no shell.
type fakeBroker struct {
	t      *testing.T
	name   string
	shared bool
	ln     net.Listener

	mu     sync.Mutex
	rows   []string
	cursor proto.Cursor
	state  proto.State
	since  []string
	typed  []string
	// onType runs (locked) after an accepted type/keys request.
	onType func(f *fakeBroker, text string)
}

func newFake(t *testing.T, dir, name string, shared bool) *fakeBroker {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(dir, name+".sock"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeBroker{t: t, name: name, shared: shared, ln: ln,
		rows:   []string{"$ ", "", ""},
		cursor: proto.Cursor{Row: 0, Col: 2, Visible: true},
		state: proto.State{Session: name, Keyboard: proto.KeyboardFree, AgentMayType: true, SecretInput: proto.SecretNone,
			Foreground: &proto.Program{PID: 100, Name: "bash", Trust: proto.TrustSystem}, Policy: proto.PolicyAuto,
			Rows: 3, Cols: 80, Persons: 1, Shared: shared},
	}
	t.Cleanup(func() { _ = ln.Close() })
	go f.accept()
	return f
}

func (f *fakeBroker) accept() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.serve(c)
	}
}

func (f *fakeBroker) serve(c net.Conn) {
	defer c.Close()
	var wmu sync.Mutex
	reply := func(id int64, res any, e *proto.Error) {
		wmu.Lock()
		defer wmu.Unlock()
		if e != nil {
			_ = proto.WriteJSON(c, proto.Response{ID: id, Error: e})
			return
		}
		if res == nil {
			res = struct{}{}
		}
		_ = proto.WriteJSON(c, proto.Response{ID: id, OK: true, Result: res})
	}
	role := ""
	for {
		fr, err := proto.ReadFrame(c)
		if err != nil {
			return
		}
		var r proto.Request
		if json.Unmarshal(fr.Payload, &r) != nil {
			return
		}
		if r.Op == "hello" {
			var h proto.Hello
			_ = json.Unmarshal(r.Args, &h)
			if !f.shared && h.Role == proto.RoleAgent {
				reply(r.ID, nil, proto.Errorf(proto.ErrNotShared, "not shared"))
				return
			}
			role = h.Role
			reply(r.ID, proto.HelloResult{V: 1, Session: f.name, Role: role, Assurance: proto.AssuranceWeak, Shared: f.shared}, nil)
			continue
		}
		if r.Op == "wait" {
			go func(r proto.Request) { res, e := f.wait(r); reply(r.ID, res, e) }(r)
			continue
		}
		res, e := f.op(r)
		reply(r.ID, res, e)
	}
}

func (f *fakeBroker) op(r proto.Request) (any, *proto.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Op {
	case "info":
		return proto.Info{Session: f.name, Shared: f.shared, Policy: f.state.Policy, Rows: 3, Cols: 80, Persons: 1}, nil
	case "state":
		return f.state, nil
	case "screen":
		return proto.Screen{Rows: append([]string(nil), f.rows...), Wrapped: make([]bool, len(f.rows)), Cursor: f.cursor,
			RowsN: len(f.rows), Cols: 80, CursorSince: int64(len(f.since)), State: f.state}, nil
	case "since":
		var a struct {
			Cursor int64 `json:"cursor"`
		}
		_ = json.Unmarshal(r.Args, &a)
		lines := f.since[min(int(a.Cursor), len(f.since)):]
		return proto.Since{Lines: lines, Wrapped: make([]bool, len(lines)), Cursor: int64(len(f.since)), First: a.Cursor}, nil
	case "type", "keys":
		switch {
		case f.state.Private:
			return nil, proto.Errorf(proto.ErrPrivateMode, "private")
		case f.state.SecretInput == proto.SecretActive:
			return nil, proto.Errorf(proto.ErrSecretInputActive, "a secret prompt is active; wait for secret_ended")
		}
		var a struct {
			Text  string   `json:"text"`
			Enter bool     `json:"enter"`
			Keys  []string `json:"keys"`
		}
		_ = json.Unmarshal(r.Args, &a)
		text := a.Text
		if a.Keys != nil {
			text = strings.Join(a.Keys, " ")
		}
		f.typed = append(f.typed, text)
		if f.onType != nil {
			f.onType(f, text)
		}
		return proto.Sent{Sent: len(text)}, nil
	case "mask":
		return nil, proto.Errorf(proto.ErrUnknownSecret, "no secret")
	case "request_keyboard":
		f.state.AgentRequestsKeyboard = true
		return nil, nil
	}
	return nil, proto.Errorf(proto.ErrUnknownOp, "unknown op %q", r.Op)
}

// wait: idle and change answer at once; secret_ended polls the state.
func (f *fakeBroker) wait(r proto.Request) (any, *proto.Error) {
	var a proto.WaitArgs
	_ = json.Unmarshal(r.Args, &a)
	deadline := time.Now().Add(time.Duration(a.TimeoutMS) * time.Millisecond)
	for {
		f.mu.Lock()
		st := f.state
		f.mu.Unlock()
		switch a.For {
		case proto.WaitIdle, proto.WaitChange, proto.WaitPrompt:
			if a.IdleMS > 0 {
				time.Sleep(time.Duration(min(a.IdleMS, 50)) * time.Millisecond)
			}
			return proto.WaitResult{Matched: true, Reason: a.For, State: st}, nil
		case proto.WaitSecretEnded:
			if st.SecretInput != proto.SecretActive {
				return proto.WaitResult{Matched: true, Reason: a.For, State: st}, nil
			}
		}
		if time.Now().After(deadline) {
			return proto.WaitResult{Reason: "timeout", State: st}, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// client drives the MCP server over pipes.
type client struct {
	t   *testing.T
	in  io.Writer
	rd  *bufio.Reader
	id  int
	mu  sync.Mutex
	all strings.Builder
}

func startServer(t *testing.T, srv *Server) *client {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Run(ctx, inR, outW); close(done) }()
	t.Cleanup(func() { _ = inW.Close(); cancel(); <-done })
	c := &client{t: t, in: inW, rd: bufio.NewReader(outR)}
	c.rpc("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "t", "version": "1"}})
	return c
}

func (c *client) rpc(method string, params any) map[string]any {
	c.t.Helper()
	c.id++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	if _, err := c.in.Write(append(b, '\n')); err != nil {
		c.t.Fatal(err)
	}
	line, err := c.rd.ReadBytes('\n')
	if err != nil {
		c.t.Fatal(err)
	}
	c.all.Write(line)
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		c.t.Fatal(err)
	}
	return m
}

// tool calls a tool and returns its text and isError.
func (c *client) tool(name string, args map[string]any) (string, bool) {
	c.t.Helper()
	m := c.rpc("tools/call", map[string]any{"name": name, "arguments": args})
	res, ok := m["result"].(map[string]any)
	if !ok {
		c.t.Fatalf("%s: %v", name, m)
	}
	content := res["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	isErr, _ := res["isError"].(bool)
	return text, isErr
}

func TestToolsList(t *testing.T) {
	c := startServer(t, &Server{Dir: t.TempDir()})
	m := c.rpc("tools/list", map[string]any{})
	tools := m["result"].(map[string]any)["tools"].([]any)
	want := []string{"term_sessions", "term_read", "term_run", "term_type", "term_keys", "term_wait", "term_mask", "term_request_keyboard"}
	if len(tools) != len(want) {
		t.Fatalf("%d tools", len(tools))
	}
	for i, x := range tools {
		tm := x.(map[string]any)
		if tm["name"] != want[i] {
			t.Errorf("tool %d: %v", i, tm["name"])
		}
		if len(tm["description"].(string)) < 80 {
			t.Errorf("%s: description too short", want[i])
		}
	}
}

func TestInitializeVersion(t *testing.T) {
	c := startServer(t, &Server{Dir: t.TempDir()})
	m := c.rpc("initialize", map[string]any{"protocolVersion": "2025-03-26"})
	if v := m["result"].(map[string]any)["protocolVersion"]; v != "2025-03-26" {
		t.Errorf("version %v", v)
	}
	m = c.rpc("initialize", map[string]any{"protocolVersion": "1999-01-01"})
	if v := m["result"].(map[string]any)["protocolVersion"]; v != protocolVersions[0] {
		t.Errorf("version %v", v)
	}
}

func TestSessionsOnlyShared(t *testing.T) {
	dir := t.TempDir()
	newFake(t, dir, "work", true)
	newFake(t, dir, "private", false)
	c := startServer(t, &Server{Dir: dir})
	text, isErr := c.tool("term_sessions", nil)
	if isErr || !strings.Contains(text, "- work:") || strings.Contains(text, "private") {
		t.Fatalf("term_sessions: %s", text)
	}
	// The unshared session is refused by name too.
	text, isErr = c.tool("term_read", map[string]any{"session": "private"})
	if !isErr || !strings.Contains(text, "error: not_shared") || !strings.Contains(text, "cotty share") {
		t.Fatalf("read unshared: %s", text)
	}
	// One shared session: it is the default.
	text, isErr = c.tool("term_read", nil)
	if isErr || !strings.Contains(text, "session: work") || !strings.Contains(text, "secret prompt: none") {
		t.Fatalf("read: %s", text)
	}
}

func TestNoAndAmbiguousSession(t *testing.T) {
	dir := t.TempDir()
	c := startServer(t, &Server{Dir: dir})
	text, isErr := c.tool("term_read", nil)
	if !isErr || !strings.Contains(text, "error: no_session") || !strings.Contains(text, "cotty new --ai") {
		t.Fatalf("no session: %s", text)
	}
	newFake(t, dir, "a", true)
	newFake(t, dir, "b", true)
	text, isErr = c.tool("term_read", nil)
	if !isErr || !strings.Contains(text, "error: ambiguous_session") {
		t.Fatalf("ambiguous: %s", text)
	}
	if _, isErr = c.tool("term_read", map[string]any{"session": "b"}); isErr {
		t.Fatal("explicit session refused")
	}
}

func TestAgentSocketMode(t *testing.T) {
	dir := t.TempDir()
	newFake(t, dir, "work", true)
	c := startServer(t, &Server{AgentSocket: filepath.Join(dir, "work.sock")})
	if text, isErr := c.tool("term_sessions", nil); isErr || !strings.Contains(text, "- work:") {
		t.Fatalf("sessions: %s", text)
	}
	c2 := startServer(t, &Server{AgentSocket: filepath.Join(dir, "missing.sock")})
	if text, isErr := c2.tool("term_read", nil); !isErr || !strings.Contains(text, "no_session") {
		t.Fatalf("missing socket: %s", text)
	}
}

func TestAgentDirMode(t *testing.T) {
	dir := t.TempDir()
	newFake(t, dir, "work", true)
	c := startServer(t, &Server{AgentDir: dir})
	if text, isErr := c.tool("term_sessions", nil); isErr || !strings.Contains(text, "- work:") {
		t.Fatalf("sessions: %s", text)
	}
	if text, isErr := c.tool("term_read", nil); isErr || !strings.Contains(text, "session: work") {
		t.Fatalf("read: %s", text)
	}
	// A session without an endpoint in the directory is not shared.
	if text, isErr := c.tool("term_read", map[string]any{"session": "gone"}); !isErr || !strings.Contains(text, "error: not_shared") {
		t.Fatalf("missing endpoint: %s", text)
	}
	// A session shared later shows up without restarting the server.
	newFake(t, dir, "later", true)
	if text, isErr := c.tool("term_sessions", nil); isErr || !strings.Contains(text, "- later:") {
		t.Fatalf("later session: %s", text)
	}
	// A missing directory means no session.
	c2 := startServer(t, &Server{AgentDir: filepath.Join(dir, "none")})
	if text, isErr := c2.tool("term_read", nil); !isErr || !strings.Contains(text, "no_session") {
		t.Fatalf("missing dir: %s", text)
	}
}

func TestRunDone(t *testing.T) {
	dir := t.TempDir()
	f := newFake(t, dir, "work", true)
	f.onType = func(f *fakeBroker, text string) {
		f.rows = []string{"$ echo hi", "hi", "$ "}
		f.cursor = proto.Cursor{Row: 2, Col: 2}
	}
	c := startServer(t, &Server{Dir: dir})
	text, isErr := c.tool("term_run", map[string]any{"command": "echo hi"})
	if isErr || !strings.Contains(text, "status: done") || !strings.Contains(text, "--- output (1 lines) ---\nhi\n") {
		t.Fatalf("run: %s", text)
	}
	if f.typed[0] != "echo hi" {
		t.Errorf("typed %q", f.typed)
	}
	if !strings.Contains(text, "exit_code: unknown") {
		t.Errorf("exit code line: %s", text)
	}
}

func TestRunSecretPrompt(t *testing.T) {
	dir := t.TempDir()
	f := newFake(t, dir, "work", true)
	f.onType = func(f *fakeBroker, text string) {
		f.rows = []string{"$ sudo -v", "[sudo] password for me: ", ""}
		f.cursor = proto.Cursor{Row: 1, Col: 24}
		f.state.SecretInput = proto.SecretActive
		f.state.AgentMayType = false
		f.state.SecretProgram = &proto.Program{PID: 200, Name: "sudo", Exe: "/usr/bin/sudo", Trust: proto.TrustSystem}
	}
	c := startServer(t, &Server{Dir: dir})
	text, isErr := c.tool("term_run", map[string]any{"command": "sudo -v"})
	if isErr || !strings.Contains(text, "status: secret_prompt") || !strings.Contains(text, "green lock") ||
		!strings.Contains(text, "for=secret_ended") || !strings.Contains(text, "[sudo] password for me:") {
		t.Fatalf("run: %s", text)
	}
	// The agent is refused while the prompt is active, with the state.
	text, isErr = c.tool("term_type", map[string]any{"text": "guess"})
	if !isErr || !strings.Contains(text, "error: secret_input_active") || !strings.Contains(text, "secret prompt: ACTIVE, sudo (/usr/bin/sudo)") {
		t.Fatalf("type: %s", text)
	}
	// term_wait for idle ends at once with secret_prompt.
	text, _ = c.tool("term_wait", map[string]any{"for": "idle", "timeout_s": 5})
	if !strings.Contains(text, "reason: secret_prompt") {
		t.Fatalf("wait idle: %s", text)
	}
	// The person finishes; secret_ended returns.
	go func() {
		time.Sleep(100 * time.Millisecond)
		f.mu.Lock()
		f.state.SecretInput = proto.SecretNone
		f.state.SecretProgram = nil
		f.mu.Unlock()
	}()
	text, _ = c.tool("term_wait", map[string]any{"for": "secret_ended", "timeout_s": 5})
	if !strings.Contains(text, "matched: true") || !strings.Contains(text, "reason: secret_ended") {
		t.Fatalf("wait secret_ended: %s", text)
	}
}

func TestErrorsAreTyped(t *testing.T) {
	dir := t.TempDir()
	f := newFake(t, dir, "work", true)
	f.state.Private = true
	c := startServer(t, &Server{Dir: dir})
	text, isErr := c.tool("term_keys", map[string]any{"keys": []string{"C-c"}})
	if !isErr || !strings.Contains(text, "error: private_mode") || !strings.Contains(text, "what to do:") {
		t.Fatalf("private: %s", text)
	}
	text, isErr = c.tool("term_mask", map[string]any{"name": "NOPE"})
	if !isErr || !strings.Contains(text, "error: unknown_secret") {
		t.Fatalf("mask: %s", text)
	}
	text, isErr = c.tool("term_wait", map[string]any{"for": "sunrise"})
	if !isErr || !strings.Contains(text, "error: bad_arguments") {
		t.Fatalf("bad wait: %s", text)
	}
	text, isErr = c.tool("term_nope", nil)
	if !isErr || !strings.Contains(text, "unknown_tool") {
		t.Fatalf("unknown tool: %s", text)
	}
}

func TestLogHasNoContent(t *testing.T) {
	dir := t.TempDir()
	f := newFake(t, dir, "work", true)
	f.onType = func(f *fakeBroker, text string) {
		f.rows = []string{"$ echo CONTENT-MARKER", "CONTENT-MARKER", "$ "}
		f.cursor = proto.Cursor{Row: 2, Col: 2}
	}
	logPath := filepath.Join(dir, "mcp.log")
	lf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	c := startServer(t, &Server{Dir: dir, Log: newLogger(lf)})
	if _, isErr := c.tool("term_run", map[string]any{"command": "echo CONTENT-MARKER"}); isErr {
		t.Fatal("run failed")
	}
	b, _ := os.ReadFile(logPath)
	if strings.Contains(string(b), "CONTENT-MARKER") || !strings.Contains(string(b), "tool=term_run") {
		t.Fatalf("log: %s", b)
	}
}

func TestBrokerGone(t *testing.T) {
	dir := t.TempDir()
	f := newFake(t, dir, "work", true)
	c := startServer(t, &Server{Dir: dir, Session: "work"})
	if _, isErr := c.tool("term_read", nil); isErr {
		t.Fatal("read")
	}
	_ = f.ln.Close()
	_ = os.Remove(filepath.Join(dir, "work.sock"))
	text, isErr := c.tool("term_read", nil)
	if !isErr || !(strings.Contains(text, "session_ended") || strings.Contains(text, "unknown_session")) {
		t.Fatalf("gone: %s", text)
	}
}

func TestAsToolError(t *testing.T) {
	if e := asToolError(proto.ErrClosed); e.Code != proto.ErrSessionEnded {
		t.Errorf("%v", e)
	}
	if e := asToolError(errors.New("boom")); e.Code != errUnreachable {
		t.Errorf("%v", e)
	}
}

func newLogger(w io.Writer) *log.Logger { return log.New(w, "", 0) }

// S32: without shell integration a builtin waiting for input (read x)
// leaves the shell in front and quiet; that is not done.
func TestRunReadBuiltinIsNotDone(t *testing.T) {
	dir := t.TempDir()
	f := newFake(t, dir, "work", true)
	f.onType = func(f *fakeBroker, text string) {
		f.rows = []string{"$ read x", "", ""}
		f.cursor = proto.Cursor{Row: 1, Col: 0}
	}
	c := startServer(t, &Server{Dir: dir})
	text, isErr := c.tool("term_run", map[string]any{"command": "read x"})
	if isErr || !strings.Contains(text, "status: running") || !strings.Contains(text, "not at a fresh prompt") {
		t.Fatalf("run: %s", text)
	}
	// A question with a prompt of its own is not a shell prompt either.
	f.mu.Lock()
	f.onType = func(f *fakeBroker, text string) {
		f.rows = []string{"$ read -p 'Name: ' x", "Name: ", ""}
		f.cursor = proto.Cursor{Row: 1, Col: 6}
	}
	f.rows, f.cursor = []string{"$ ", "", ""}, proto.Cursor{Row: 0, Col: 2}
	f.mu.Unlock()
	if text, _ := c.tool("term_run", map[string]any{"command": "read -p 'Name: ' x"}); !strings.Contains(text, "status: running") {
		t.Fatalf("question: %s", text)
	}
}

// S32: tool calls that type into one session take turns.
func TestSessionInputLock(t *testing.T) {
	s := &Server{}
	ctx := context.Background()
	unlock, err := s.lockSession(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	// Another session is independent.
	u2, err := s.lockSession(ctx, "b")
	if err != nil {
		t.Fatal(err)
	}
	u2()
	got := make(chan struct{})
	go func() {
		u, err := s.lockSession(ctx, "a")
		if err == nil {
			u()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("second caller did not wait")
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("second caller not released")
	}
	cctx, cancel := context.WithCancel(ctx)
	unlock, _ = s.lockSession(ctx, "a")
	defer unlock()
	cancel()
	if _, err := s.lockSession(cctx, "a"); err == nil {
		t.Fatal("cancelled wait took the lock")
	}
}
