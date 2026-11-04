package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/openbasalt/cotty/internal/mcp"
	"github.com/openbasalt/cotty/internal/session"
)

func init() {
	register(command{name: "mcp", usage: "[--session NAME] [--agent-dir DIR | --socket PATH] [--log FILE]",
		summary: "MCP server for agents (stdio; started by the agent CLI)", run: runMCP})
}

func runMCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	sess := fs.String("session", "", "default session (default: the only shared one)")
	sock := fs.String("socket", "", "use only this socket (default: $COTTY_AGENT_SOCKET when set)")
	agentDir := fs.String("agent-dir", "", "agent endpoint directory (default: $COTTY_AGENT_DIR, else $XDG_RUNTIME_DIR/cotty/agent)")
	logPath := fs.String("log", "", "append one line per tool call to FILE (no terminal content); default: stderr")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return fail("usage: cotty mcp [--session NAME] [--agent-dir DIR | --socket PATH] [--log FILE]")
	}
	if *sess != "" && !session.ValidName(*sess) {
		return fail("invalid session name %q", *sess)
	}
	// Nothing below needs to keep secrets, but a core file of this process
	// would hold masked screen text: do not write one.
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})

	var w io.Writer = os.Stderr
	if *logPath != "" {
		if err := os.MkdirAll(filepath.Dir(*logPath), 0o700); err != nil {
			return fail("%v", err)
		}
		f, err := os.OpenFile(*logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return fail("%v", err)
		}
		defer f.Close()
		w = f
	}
	srv := &mcp.Server{AgentSocket: agentSocket(*sock), Session: *sess,
		Log: log.New(w, "cotty-mcp ", log.LstdFlags|log.Lmicroseconds)}
	if srv.AgentSocket == "" {
		srv.AgentDir = agentDirFor(*agentDir)
	}
	srv.Log.Printf("start pid=%d agent_socket=%q agent_dir=%q default_session=%q", os.Getpid(), srv.AgentSocket, srv.AgentDir, srv.Session)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	signal.Ignore(syscall.SIGPIPE)
	if err := srv.Run(ctx, os.Stdin, os.Stdout); err != nil {
		srv.Log.Printf("end: %v", err)
		return 1
	}
	srv.Log.Printf("end")
	return 0
}

// agentSocket is the single socket to use when one was named: --socket or
// $COTTY_AGENT_SOCKET. Empty: use the agent endpoint directory.
func agentSocket(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("COTTY_AGENT_SOCKET")
}

// agentDirFor picks the agent endpoint directory: --agent-dir,
// $COTTY_AGENT_DIR (set by `cotty agent`), else
// $XDG_RUNTIME_DIR/cotty/agent (docs/protocol.md section 1). The
// directory holds one socket per session shared with agents.
func agentDirFor(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv("COTTY_AGENT_DIR"); v != "" {
		return v
	}
	if base := os.Getenv("XDG_RUNTIME_DIR"); base != "" {
		return filepath.Join(base, "cotty", session.AgentSubdir)
	}
	return filepath.Join(os.TempDir(), "cotty-"+strconv.Itoa(os.Getuid()), session.AgentSubdir)
}
