package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/broker"
	"github.com/openbasalt/cotty/internal/guard"
	"github.com/openbasalt/cotty/internal/harden"
	"github.com/openbasalt/cotty/internal/session"
)

// Inherited descriptors between `cotty new` and the broker it starts.
const (
	fdReady = 3 // broker writes "ready\n" once it listens
	fdToken = 4 // `cotty new` writes the creator token, then closes
)

func init() {
	register(command{name: "__broker", hidden: true, summary: "run a session broker (started by cotty new)", run: runBroker})
}

// brokerFlags are shared by `cotty new` (which passes them on) and the
// broker; the guard parses a broker's command line with them too.
type brokerFlags = session.BrokerFlags

// auditPath is $XDG_STATE_HOME/cotty/audit.jsonl.
func auditPath() string {
	base := session.StateBase()
	if base == "" {
		return ""
	}
	return filepath.Join(base, "audit.jsonl")
}

func runBroker(args []string) int {
	var bf brokerFlags
	fs := flag.NewFlagSet("__broker", flag.ContinueOnError)
	bf.DefineBroker(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !session.ValidName(bf.Name) {
		return fail("invalid session name %q", bf.Name)
	}
	// Harden first: from here the process holds what the person types.
	if err := harden.Process(); err != nil {
		return fail("hardening: %v", err)
	}
	syscall.Umask(0o077)
	// Every descriptor cotty new left us (the ready pipe, anything its own
	// caller leaked) stays out of the session shell: Go does not close
	// inherited descriptors on exec.
	_ = unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC)
	token := ""
	if f := os.NewFile(fdToken, "token"); f != nil {
		b, _ := io.ReadAll(io.LimitReader(f, 256))
		_ = f.Close()
		token = strings.TrimSpace(string(b))
	}
	dir, err := session.Dir()
	if err != nil {
		return fail("%v", err)
	}
	logger := log.New(os.Stderr, "cotty-broker["+bf.Name+"] ", log.LstdFlags)
	stateDir, err := session.StateDir(bf.Name)
	if err != nil {
		// The session still works; the shell keeps its own HISTFILE.
		logger.Printf("session state directory: %v", err)
		stateDir = ""
	}
	ready := os.NewFile(fdReady, "ready")
	// The masking list: every secret secrets.conf names, resolved now (a
	// source may take a while, such as a keyring unlock prompt) and held
	// in locked memory until the session ends.
	masker := broker.NewEngine(broker.EngineConfig{Width: bf.Cols, Logf: logger.Printf})
	// Layer 3: the session's pts protection, and `strong` only while the
	// guard confirms it alive.
	gs := guard.NewSession()
	if bf.Insecure && (gs.Guard.Loaded() || guard.Enforcing()) {
		// An insecure broker admits any process of the user without a
		// secret: never next to the guard (the guard refuses to register
		// it as well).
		return fail("--dev-insecure is refused while cotty-guard is loaded")
	}
	// Before the broker binds its sockets: with the guard running, only
	// registered brokers may bind, rename or remove in the runtime
	// directories, so no other process of the user can replace them, and
	// the session name is this broker's while it runs.
	if agentDir, err := session.AgentDir(dir); err != nil {
		return fail("%v", err)
	} else if err := gs.RegisterBroker(bf.Name, []string{dir, agentDir}); err != nil {
		return fail("%v", err)
	}
	logger.Printf("masking %d named secrets", len(masker.Names()))
	b, err := broker.New(broker.Config{
		Masker: masker,
		Name:   bf.Name, Dir: dir, Shell: fs.Args(), Policy: bf.Policy, Shared: bf.AI,
		Insecure: bf.Insecure, RequireConfined: bf.RequireConf, StateDir: stateDir,
		Rows: bf.Rows, Cols: bf.Cols, CreatorToken: token,
		CountSecretKeys: bf.CountSecret, AuditPath: auditPath(), Logger: logger,
		Guard: gs, ProtectPTS: gs.Protect, ClaimSocket: gs.ClaimSocket, PTSException: gs.PTSException,
		Ready: func() {
			if ready != nil {
				_, _ = ready.Write([]byte("ready\n"))
				_ = ready.Close()
			}
		},
	})
	if err != nil {
		if ready != nil {
			fmt.Fprintf(ready, "error %v\n", err)
		}
		return fail("%v", err)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigs
		b.Kill()
	}()
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	code, err := b.Run()
	if err != nil {
		if ready != nil {
			fmt.Fprintf(ready, "error %v\n", err)
		}
		return fail("%v", err)
	}
	return code
}
