// Command cotty-guard is cotty's optional layer 3: a root daemon that
// loads BPF LSM programs enforcing the agent rules in the kernel, pins
// their maps under /sys/fs/bpf/cotty, answers unprivileged requests that
// only ever restrict (register an agent cgroup, tag oneself, protect a
// terminal), answers the broker's tag lookups and writes every denial to
// the audit log. See docs/guard.md.
//
//	cotty-guard [run] [flags]   the daemon (systemd: cotty-guard.service)
//	cotty-guard status          ask a running daemon (any user)
//	cotty-guard uninstall       remove the pinned programs and maps (root,
//	                            daemon stopped): ends the enforcement and
//	                            forgets every tag, registration and
//	                            protection; a stop or restart keeps them
//	cotty-guard facts           what this kernel offers (any user; loads nothing)
//	cotty-guard hooks           the kernel's signature of every hook the guard
//	                            uses, checked against what the programs read
//	                            (any user; reads BTF, loads nothing)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/openbasalt/cotty/internal/guard"
	"github.com/openbasalt/cotty/internal/guard/daemon"
)

type listFlag []string

func (l *listFlag) String() string     { return fmt.Sprint(*l) }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run":
		os.Exit(run(args))
	case "status":
		os.Exit(status())
	case "uninstall":
		os.Exit(uninstall(args))
	case "facts":
		os.Exit(printJSON(guard.ReadFacts()))
	case "hooks":
		os.Exit(hooks())
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "cotty-guard: unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: cotty-guard [run] [--socket PATH] [--pin DIR] [--audit FILE] [--allow-socket PATH]... [--cotty PATH]... [--exceptions FILE] [--verbose]")
	fmt.Fprintln(os.Stderr, "       cotty-guard status | facts | hooks")
	fmt.Fprintln(os.Stderr, "       cotty-guard uninstall [--pin DIR] [--socket PATH]")
}

func run(args []string) int {
	fs := flag.NewFlagSet("cotty-guard run", flag.ContinueOnError)
	var o daemon.Options
	var extra, cottyPaths listFlag
	fs.StringVar(&o.SocketPath, "socket", guard.SocketPath, "socket for unprivileged requests")
	fs.StringVar(&o.PinPath, "pin", guard.PinPath, "bpffs directory for pinned maps and links")
	fs.StringVar(&o.AuditPath, "audit", guard.AuditPath, "audit log of denials")
	fs.Var(&cottyPaths, "cotty", "path of the installed cotty binary brokers must run (repeatable; default /usr/bin/cotty and /usr/local/bin/cotty)")
	fs.Var(&extra, "allow-socket", "a pathname Unix socket (or a directory of them) every agent may connect to (repeatable)")
	fs.StringVar(&o.ExceptionsPath, "exceptions", guard.ExceptionsPath, "pts exception list: executables that may open a cotty session pts (root-owned, closed to group and others; absent means none; reloaded on SIGHUP)")
	fs.BoolVar(&o.Verbose, "verbose", false, "log every denial to stderr too")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	o.ExtraSockets = extra
	o.CottyPaths = cottyPaths
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "cotty-guard: the daemon must run as root")
		return 1
	}
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := daemon.Run(ctx, o); err != nil {
		if errors.Is(err, daemon.ErrUnsupported) {
			// Not an error for the system: the guard is optional.
			log.Printf("cotty-guard: %v; exiting", err)
			return 0
		}
		log.Printf("cotty-guard: %v", err)
		return 1
	}
	return 0
}

func uninstall(args []string) int {
	fs := flag.NewFlagSet("cotty-guard uninstall", flag.ContinueOnError)
	pin := fs.String("pin", guard.PinPath, "bpffs directory of the pinned maps and links")
	sock := fs.String("socket", guard.SocketPath, "the daemon's socket (refuses while it answers)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "cotty-guard: uninstall must run as root")
		return 1
	}
	if err := daemon.Uninstall(*pin, *sock); err != nil {
		fmt.Fprintf(os.Stderr, "cotty-guard: uninstall: %v\n", err)
		return 1
	}
	fmt.Println("cotty-guard: programs detached, maps removed")
	return 0
}

func hooks() int {
	hs, err := daemon.CheckHooks()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cotty-guard: %v\n", err)
		return 1
	}
	rc := 0
	for _, h := range hs {
		res := "ok"
		switch {
		case !h.OK && h.Optional && strings.HasPrefix(h.Signature, "missing"):
			res = "absent (optional, not attached)"
		case !h.OK:
			res, rc = "MISMATCH (want "+h.Want+")", 1
		}
		fmt.Printf("%-22s %s  %s\n", h.Hook, res, h.Signature)
	}
	return rc
}

func status() int {
	c, err := guard.Dial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cotty-guard: %v\n", err)
		return 1
	}
	defer c.Close()
	st, err := c.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cotty-guard: %v\n", err)
		return 1
	}
	return printJSON(st)
}

func printJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return 1
	}
	return 0
}
