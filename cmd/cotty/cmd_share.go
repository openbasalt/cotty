package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/openbasalt/cotty/internal/attach"
	"github.com/openbasalt/cotty/internal/harden"
	"github.com/openbasalt/cotty/internal/proto"
	"github.com/openbasalt/cotty/internal/session"
)

func init() {
	register(command{name: "share", usage: "[--off] [--require-confined[=false]] SESSION", summary: "make a session visible to agents (or hide it)", run: runShare})
	register(command{name: "kill", usage: "SESSION", summary: "end a session", run: runKill})
}

// control opens a control connection (person classification plus the
// reattach code, proven to the broker and proven back).
func control(name, client string) (*proto.Client, error) {
	verifier, err := brokerVerifier()
	if err != nil {
		return nil, err
	}
	dir, err := session.Dir()
	if err != nil {
		return nil, err
	}
	name, err = session.Resolve(dir, name)
	if err != nil {
		return nil, err
	}
	cl, _, err := attach.Connect(attach.ConnectOptions{Socket: session.PathsFor(dir, name).Socket, Session: name,
		Hello: proto.Hello{Role: proto.RoleControl, Client: client}, PromptCode: attach.PromptCode,
		// The code is typed in this process: not dumpable from then on.
		Harden:   harden.Process,
		Verifier: verifier})
	return cl, err
}

func runShare(args []string) int {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	off := fs.Bool("off", false, "hide the session from agents")
	reqConf := fs.Bool("require-confined", false, "refuse agents that were not started with cotty agent; =false accepts them again")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		return fail("usage: cotty share [--off] [--require-confined[=false]] SESSION")
	}
	args2 := map[string]any{"on": !*off}
	fs.Visit(func(f *flag.Flag) {
		// Only an explicit flag changes the setting; plain `cotty share`
		// keeps what the session has.
		if f.Name == "require-confined" {
			args2["require_confined"] = *reqConf
		}
	})
	cl, err := control(fs.Arg(0), "cotty-share")
	if err != nil {
		return fail("%v", err)
	}
	defer cl.Close()
	var res struct {
		RequireConfined bool `json:"require_confined"`
	}
	if err := cl.Call(context.Background(), "share", args2, &res); err != nil {
		return fail("%v", err)
	}
	switch {
	case *off:
		fmt.Printf("session %s is hidden from agents\n", fs.Arg(0))
	case res.RequireConfined:
		fmt.Printf("session %s is shared with confined agents only\n", fs.Arg(0))
	default:
		fmt.Printf("session %s is shared with agents\n", fs.Arg(0))
	}
	return 0
}

func runKill(args []string) int {
	if len(args) != 1 {
		return fail("usage: cotty kill SESSION")
	}
	cl, err := control(args[0], "cotty-kill")
	if err != nil {
		return fail("%v", err)
	}
	defer cl.Close()
	if err := cl.Call(context.Background(), "kill", nil, nil); err != nil {
		return fail("%v", err)
	}
	return 0
}
