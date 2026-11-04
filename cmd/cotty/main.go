// Command cotty is a terminal shared by a person and an AI agent. See
// docs/PLAN.md.
//
// Subcommands live one per file (cmd_<name>.go) and register themselves
// in init, so work packages add commands without touching this file.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// command is one subcommand.
type command struct {
	name    string
	usage   string // arguments, shown after the name
	summary string
	hidden  bool
	run     func(args []string) int
}

var commands = map[string]command{}

// register adds a subcommand; called from init functions.
func register(c command) {
	if _, dup := commands[c.name]; dup {
		panic("cotty: duplicate command " + c.name)
	}
	commands[c.name] = c
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: cotty <command> [arguments]")
	fmt.Fprintln(os.Stderr)
	names := make([]string, 0, len(commands))
	for n, c := range commands {
		if !c.hidden {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		c := commands[n]
		fmt.Fprintf(os.Stderr, "  %-34s %s\n", strings.TrimSpace(n+" "+c.usage), c.summary)
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	name := os.Args[1]
	switch name {
	case "-h", "--help", "help":
		usage()
		return
	}
	c, ok := commands[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "cotty: unknown command %q\n", name)
		usage()
		os.Exit(2)
	}
	os.Exit(c.run(os.Args[2:]))
}

// fail prints an error and returns exit code 1.
func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "cotty: "+format+"\n", a...)
	return 1
}
