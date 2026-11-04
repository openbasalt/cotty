package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/openbasalt/cotty/internal/confine"
)

func init() {
	register(command{name: "agent", summary: "start an AI agent CLI confined (cotty agent [--profile P] [--project DIR] -- CMD...)", run: runAgent})
	// Inner stages of the launcher, run by cotty itself.
	register(command{name: confine.StageInit, hidden: true, run: func([]string) int { confine.RunInit(); return 1 }})
	register(command{name: confine.StageExec, hidden: true, run: func([]string) int { confine.RunExec(); return 1 }})
	register(command{name: confine.StageProbe, hidden: true, run: func([]string) int { confine.RunUsernsProbe(); return 1 }})
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runAgent(args []string) int {
	fs := flag.NewFlagSet("cotty agent", flag.ContinueOnError)
	var opts confine.Options
	var ro, rw multiFlag
	var inScope string
	var list, dryRun bool
	fs.StringVar(&opts.Profile, "profile", "", "agent profile (default: guessed from the command, else generic)")
	fs.StringVar(&opts.Project, "project", "", "project directory the agent may read and write (default: current directory)")
	fs.Var(&ro, "ro", "extra path visible read-only (repeatable)")
	fs.Var(&rw, "rw", "extra path visible read-write (repeatable)")
	fs.StringVar(&opts.AgentDir, "agent-dir", "", "cotty agent endpoint directory (default: $XDG_RUNTIME_DIR/cotty/agent, created when missing)")
	fs.BoolVar(&opts.NoMCP, "no-mcp", false, "do not point the agent at cotty mcp")
	fs.StringVar(&opts.PTY, "pty", "auto", "auto: a private pty when stdio is a terminal; always: a private pty in any case")
	fs.BoolVar(&opts.Quiet, "quiet", false, "no banner (gaps are printed anyway)")
	fs.BoolVar(&opts.AllowGitInit, "allow-git-init", false, "in a project without .git, let the agent create one (its hooks and config would run with your rights when you use git there)")
	fs.BoolVar(&opts.AllowAbstractSockets, "allow-abstract-sockets", false, "start on Landlock ABI < 6 even when X11 or D-Bus listen on abstract sockets the agent could reach")
	fs.BoolVar(&opts.AllowGitLinks, "allow-git-links", false, "start even when a git file cotty protects (.git, its config or hooks, core.hooksPath) is a symbolic link the agent could replace")
	fs.BoolVar(&opts.ShowHidden, "show-hidden", false, "leave the profile's hidden directories visible (claude: ~/.claude/ide, whose lock files hold your IDE's auth token; needed when the agent should talk to your IDE)")
	fs.BoolVar(&list, "list-profiles", false, "list the profiles and exit")
	fs.BoolVar(&dryRun, "dry-run", false, "print the computed plan as JSON and exit")
	fs.StringVar(&inScope, "in-scope", "", "internal: the systemd scope this run was started in")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: cotty agent [flags] [--] [CMD [ARGS...]]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if list {
		for _, n := range confine.ListProfiles() {
			p, err := confine.LoadProfile(n)
			if err != nil {
				fmt.Printf("%-14s (error: %v)\n", n, err)
				continue
			}
			fmt.Printf("%-14s %s\n", n, p.Description)
		}
		return 0
	}
	if opts.PTY != "auto" && opts.PTY != "always" {
		fmt.Fprintln(os.Stderr, "cotty agent: --pty is auto or always")
		return 2
	}
	opts.Argv = fs.Args()
	opts.ExtraRO, opts.ExtraRW = ro, rw
	if dryRun {
		opts.DryRun = true
		self, _ := os.Executable()
		pl, err := confine.BuildPlan(opts, os.Environ(), self)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cotty agent: %v\n", err)
			return 125
		}
		return printJSON(pl)
	}
	// The run under systemd-run gets the arguments without --in-scope.
	raw := make([]string, 0, len(args))
	for _, a := range args {
		if !strings.HasPrefix(a, "--in-scope=") && !strings.HasPrefix(a, "-in-scope=") {
			raw = append(raw, a)
		}
	}
	return confine.Launch(confine.LaunchArgs{Opts: opts, RawArgs: raw, InScope: inScope})
}
