package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
	"github.com/openbasalt/cotty/internal/session"
)

// Version is reported in serverInfo and in the broker hello.
const Version = "0.1.0"

// Server is the stdio MCP server.
type Server struct {
	// AgentSocket, when set, is the only socket the server uses: the cotty
	// agent socket that `cotty agent` binds into a confined agent
	// ($COTTY_AGENT_SOCKET). Session names then come from the broker.
	AgentSocket string
	// AgentDir is the agent endpoint directory
	// ($XDG_RUNTIME_DIR/cotty/agent, $COTTY_AGENT_DIR inside `cotty
	// agent`): one <name>.sock per session shared with agents, served by
	// that session's broker. Used when AgentSocket is empty; it is the
	// default of `cotty mcp`.
	AgentDir string
	// Dir is the session runtime directory scanned for <name>.sock when
	// AgentSocket and AgentDir are empty (default: session.Dir()).
	Dir string
	// Session is the default session name (`cotty mcp --session`).
	Session string
	// Log receives one line per tool call: tool, session, duration,
	// outcome and sizes. Never terminal content, never typed text.
	Log *log.Logger

	out io.Writer
	omu sync.Mutex

	rmu     sync.Mutex
	running map[string]context.CancelFunc

	cmu   sync.Mutex
	conns map[string]*agentConn

	// lmu guards locks: one input lock per session, so tool calls that
	// type (term_type, term_keys, term_run) on the same session run one
	// after the other instead of mixing their keystrokes and output.
	lmu   sync.Mutex
	locks map[string]chan struct{}
}

// lockSession takes the input lock of a session, or gives up when ctx
// ends. The returned function releases it.
func (s *Server) lockSession(ctx context.Context, name string) (func(), error) {
	s.lmu.Lock()
	if s.locks == nil {
		s.locks = map[string]chan struct{}{}
	}
	ch := s.locks[name]
	if ch == nil {
		ch = make(chan struct{}, 1)
		s.locks[name] = ch
	}
	s.lmu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// agentConn is one agent connection to a session broker.
type agentConn struct {
	name   string
	socket string
	hello  proto.HelloResult
	cl     *proto.Client
}

func (s *Server) version() string { return Version }

func (s *Server) logf(format string, a ...any) {
	if s.Log != nil {
		s.Log.Printf(format, a...)
	}
}

// toolError is an error with a code the model can act on.
type toolError struct {
	Code         string
	Message      string
	RetryAfterMS int64
}

func (e *toolError) Error() string { return e.Code + ": " + e.Message }

// MCP-side error codes (the broker's are in docs/protocol.md section 11).
const (
	errNoSession        = "no_session"
	errAmbiguousSession = "ambiguous_session"
	errUnknownSession   = "unknown_session"
	errUnreachable      = "broker_unreachable"
	errBadArguments     = "bad_arguments"
	errUnknownTool      = "unknown_tool"
)

// asToolError converts broker and transport errors.
func asToolError(err error) *toolError {
	var te *toolError
	if errors.As(err, &te) {
		return te
	}
	var pe *proto.Error
	if errors.As(err, &pe) {
		return &toolError{Code: pe.Code, Message: pe.Message, RetryAfterMS: pe.RetryAfterMS}
	}
	if errors.Is(err, proto.ErrClosed) {
		return &toolError{Code: proto.ErrSessionEnded, Message: "the connection to the session closed"}
	}
	if errors.Is(err, context.Canceled) {
		return &toolError{Code: "cancelled", Message: "the request was cancelled"}
	}
	return &toolError{Code: errUnreachable, Message: err.Error()}
}

// sessionEntry is a session the server can see.
type sessionEntry struct {
	socket string
	info   proto.Info
}

// candidates lists the sockets to look at.
func (s *Server) candidates() ([]string, error) {
	if s.AgentSocket != "" {
		if _, err := os.Stat(s.AgentSocket); err != nil {
			return nil, &toolError{Code: errNoSession,
				Message: "the cotty agent socket " + s.AgentSocket + " does not exist (no session was shared when the agent started)"}
		}
		return []string{s.AgentSocket}, nil
	}
	if s.AgentDir != "" {
		names, err := session.Names(s.AgentDir)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		out := make([]string, 0, len(names))
		for _, n := range names {
			out = append(out, filepath.Join(s.AgentDir, n+".sock"))
		}
		return out, nil
	}
	dir := s.Dir
	if dir == "" {
		d, err := session.Dir()
		if err != nil {
			return nil, err
		}
		dir = d
	}
	names, err := session.Names(dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, session.PathsFor(dir, n).Socket)
	}
	return out, nil
}

// sessions returns the sessions shared with agents. A session that is not
// shared is never listed, even when the broker would answer info to this
// process (an unconfined process may be classified as a person).
func (s *Server) sessions(ctx context.Context) ([]sessionEntry, error) {
	socks, err := s.candidates()
	if err != nil {
		return nil, err
	}
	var out []sessionEntry
	for _, sock := range socks {
		info, err := sessionInfo(ctx, sock)
		if err != nil || !info.Shared {
			continue
		}
		out = append(out, sessionEntry{socket: sock, info: info})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].info.Session < out[j].info.Session })
	return out, nil
}

func sessionInfo(ctx context.Context, sock string) (proto.Info, error) {
	var info proto.Info
	cl, err := proto.Dial(sock)
	if err != nil {
		return info, err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := cl.Hello(ctx, proto.Hello{Role: proto.RoleInfo, Client: "cotty-mcp/" + Version}); err != nil {
		return info, err
	}
	err = cl.Call(ctx, "info", nil, &info)
	return info, err
}

// resolve picks the session for a tool call.
func (s *Server) resolve(ctx context.Context, name string) (string, string, error) {
	if name == "" {
		name = s.Session
	}
	if name != "" && !session.ValidName(name) {
		return "", "", &toolError{Code: errUnknownSession, Message: fmt.Sprintf("invalid session name %q", name)}
	}
	if name != "" && s.AgentSocket == "" && s.AgentDir != "" {
		// The agent endpoint of a session exists only while it is shared.
		sock := filepath.Join(s.AgentDir, name+".sock")
		if fi, err := os.Stat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
			return "", "", &toolError{Code: proto.ErrNotShared, Message: fmt.Sprintf("session %q is not shared with agents (or does not exist)", name)}
		}
		return name, sock, nil
	}
	if name != "" && s.AgentSocket == "" {
		// Connect directly: the broker itself answers not_shared.
		dir := s.Dir
		if dir == "" {
			d, err := session.Dir()
			if err != nil {
				return "", "", err
			}
			dir = d
		}
		sock := session.PathsFor(dir, name).Socket
		if _, err := os.Stat(sock); err != nil {
			return "", "", &toolError{Code: errUnknownSession, Message: fmt.Sprintf("no session %q; call term_sessions", name)}
		}
		return name, sock, nil
	}
	list, err := s.sessions(ctx)
	if err != nil {
		return "", "", err
	}
	if name != "" {
		for _, e := range list {
			if e.info.Session == name {
				return name, e.socket, nil
			}
		}
		return "", "", &toolError{Code: errUnknownSession, Message: fmt.Sprintf("no session %q is shared with agents; call term_sessions", name)}
	}
	switch len(list) {
	case 0:
		return "", "", &toolError{Code: errNoSession, Message: "no terminal session is shared with agents"}
	case 1:
		return list[0].info.Session, list[0].socket, nil
	}
	names := make([]string, 0, len(list))
	for _, e := range list {
		names = append(names, e.info.Session)
	}
	return "", "", &toolError{Code: errAmbiguousSession,
		Message: "several sessions are shared: " + strings.Join(names, ", ") + "; pass session"}
}

// conn returns the agent connection to a session, dialing when needed.
func (s *Server) conn(ctx context.Context, name string) (*agentConn, error) {
	name, sock, err := s.resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	s.cmu.Lock()
	ac := s.conns[sock]
	s.cmu.Unlock()
	if ac != nil {
		select {
		case <-ac.cl.Done():
			// The broker closed it (session ended or unshared): dial again.
		default:
			return ac, nil
		}
	}
	cl, err := proto.Dial(sock)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
			return nil, &toolError{Code: proto.ErrSessionEnded, Message: fmt.Sprintf("session %q is gone; call term_sessions", name)}
		}
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	h, err := cl.Hello(hctx, proto.Hello{Role: proto.RoleAgent, Client: "cotty-mcp/" + Version})
	if err != nil {
		_ = cl.Close()
		return nil, err
	}
	ac = &agentConn{name: h.Session, socket: sock, hello: h, cl: cl}
	s.cmu.Lock()
	if s.conns == nil {
		s.conns = map[string]*agentConn{}
	}
	if old := s.conns[sock]; old != nil {
		_ = old.cl.Close()
	}
	s.conns[sock] = ac
	s.cmu.Unlock()
	s.logf("connected session=%s role=agent assurance=%s", h.Session, h.Assurance)
	return ac, nil
}

func (s *Server) closeConns() {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	for k, ac := range s.conns {
		_ = ac.cl.Close()
		delete(s.conns, k)
	}
}
