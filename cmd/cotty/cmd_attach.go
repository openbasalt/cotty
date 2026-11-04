package main

import (
	"flag"

	"github.com/openbasalt/cotty/internal/attach"
	"github.com/openbasalt/cotty/internal/session"
)

func init() {
	register(command{name: "attach", usage: "[--dev-insecure] [session]", summary: "attach to a session as the person", run: runAttach})
}

func runAttach(args []string) int {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	insecure := fs.Bool("dev-insecure", false, "development only: accept a broker started with --dev-insecure (admission without a secret)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	args = fs.Args()
	if len(args) > 1 {
		return fail("usage: cotty attach [--dev-insecure] [session]")
	}
	dir, err := session.Dir()
	if err != nil {
		return fail("%v", err)
	}
	name := ""
	if len(args) == 1 {
		name = args[0]
	}
	name, err = session.Resolve(dir, name)
	if err != nil {
		return fail("%v", err)
	}
	verifier, err := brokerVerifier()
	if err != nil {
		return fail("%v", err)
	}
	return attachAndReport(attach.Options{Session: name, Socket: session.PathsFor(dir, name).Socket,
		Verifier: verifier, Insecure: *insecure})
}
