// Package mcp is cotty's MCP server (`cotty mcp`): stdio JSON-RPC 2.0,
// started by an agent CLI as one of its MCP servers. It is a client of the
// session brokers with the agent role only, so everything it can hand to
// the model is what the broker gives an agent: the masked screen, the
// session state and typed arbitration errors. See docs/mcp.md.
//
// The JSON-RPC loop is adapted from basalt-shell's internal/mcp
// (github.com/basalt-os/basalt-shell, same owner, Apache-2.0, commit
// a24af18); the broker client and the tools are cotty's own.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
)

// Protocol versions this server speaks, newest first. The server answers
// with the client's version when it is one of these.
var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

// Run serves MCP on in and out until in closes or ctx ends.
func (s *Server) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	s.out = out
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer s.closeConns()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	var wg sync.WaitGroup
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if strings.TrimSpace(string(line)) == "" {
			continue
		}
		var req rpcReq
		if err := json.Unmarshal(line, &req); err != nil {
			s.write(rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcErr{Code: -32700, Message: "parse error"}})
			continue
		}
		if req.Method == "notifications/cancelled" {
			s.cancelRequest(req.Params)
			continue
		}
		rctx, rcancel := context.WithCancel(ctx)
		s.trackRequest(req.ID, rcancel)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer rcancel()
			defer s.untrackRequest(req.ID)
			s.dispatch(rctx, req)
		}()
	}
	// stdin closed: the agent is gone; end pending waits too.
	cancel()
	wg.Wait()
	return sc.Err()
}

func (s *Server) write(r rpcResp) {
	b, _ := json.Marshal(r)
	s.omu.Lock()
	defer s.omu.Unlock()
	_, _ = s.out.Write(append(b, '\n'))
}

func (s *Server) trackRequest(id json.RawMessage, cancel context.CancelFunc) {
	if len(id) == 0 {
		return
	}
	s.rmu.Lock()
	if s.running == nil {
		s.running = map[string]context.CancelFunc{}
	}
	s.running[string(id)] = cancel
	s.rmu.Unlock()
}

func (s *Server) untrackRequest(id json.RawMessage) {
	if len(id) == 0 {
		return
	}
	s.rmu.Lock()
	delete(s.running, string(id))
	s.rmu.Unlock()
}

// cancelRequest handles notifications/cancelled: a long term_wait or
// term_run stops when the client gives up on it.
func (s *Server) cancelRequest(params json.RawMessage) {
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(params, &p) != nil || len(p.RequestID) == 0 {
		return
	}
	s.rmu.Lock()
	cancel := s.running[string(p.RequestID)]
	s.rmu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Server) dispatch(ctx context.Context, req rpcReq) {
	reply := func(res any, e *rpcErr) {
		if len(req.ID) == 0 {
			return // a notification gets no answer
		}
		s.write(rpcResp{JSONRPC: "2.0", ID: req.ID, Result: res, Error: e})
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := protocolVersions[0]
		for _, v := range protocolVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		reply(map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "cotty", "title": "cotty shared terminal", "version": s.version()},
			"instructions":    serverInstructions,
		}, nil)
	case "notifications/initialized":
	case "ping":
		reply(map[string]any{}, nil)
	case "tools/list":
		reply(map[string]any{"tools": toolList()}, nil)
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			reply(nil, &rpcErr{Code: -32602, Message: "invalid params"})
			return
		}
		reply(s.call(ctx, p.Name, p.Arguments), nil)
	default:
		reply(nil, &rpcErr{Code: -32601, Message: "method not found: " + req.Method})
	}
}

// serverInstructions is what the client shows the model about the server
// as a whole.
const serverInstructions = "cotty is a real terminal that you share with a person who watches it live. " +
	"Use term_run for ordinary commands, term_read to look at the screen, term_type and term_keys for interactive programs. " +
	"Everything you type is shown to the person. " +
	"Passwords and other secret prompts are typed only by the person: when one appears (status secret_prompt), tell the person what it is for, " +
	"then call term_wait with for=secret_ended; never try to type, guess or ask for a secret. " +
	"Your input is refused while the person is typing, while they hold the keyboard, during a secret prompt and in private mode; " +
	"every error says what to do instead. Known secrets appear as [masked:NAME] and rows from private mode as [private]."
