package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/openbasalt/cotty/internal/confine"
	"github.com/openbasalt/cotty/internal/guard"
)

func init() {
	register(command{name: "guard", usage: "[status|facts]", summary: "state of cotty-guard, the optional kernel enforcement (layer 3)", run: runGuard})
}

func runGuard(args []string) int {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "facts":
		return printJSON(guard.ReadFacts())
	case "status":
		c, err := guard.Dial()
		if err != nil {
			fmt.Fprintln(os.Stderr, guardCheck().Explain)
			return 1
		}
		defer c.Close()
		st, err := c.Status()
		if err != nil {
			return fail("cotty-guard: %v", err)
		}
		return printJSON(st)
	}
	return fail("usage: cotty guard [status|facts]")
}

// guardCheck is the `cotty doctor` line for layer 3.
func guardCheck() confine.Check {
	f := guard.ReadFacts()
	c, err := guard.Dial()
	if err == nil {
		defer c.Close()
		st, serr := c.Status()
		if serr == nil && st.Loaded {
			return confine.Check{Name: "guard", Status: "ok",
				Value:   fmt.Sprintf("running, %d programs, %d agent cgroups", len(st.Programs), st.Agents),
				Explain: "cotty-guard enforces the agent rules in the kernel (BPF LSM): sessions can reach the strong assurance level."}
		}
		if serr != nil {
			err = serr
		} else {
			err = errors.New("programs not attached")
		}
	}
	switch {
	case !f.BPFLSM || !f.BTF:
		return confine.Check{Name: "guard", Status: "info", Value: "not possible on this kernel", Explain: f.Explain}
	case errors.Is(err, guard.ErrNotRunning):
		return confine.Check{Name: "guard", Status: "info", Value: "not running",
			Explain: "the kernel can run cotty-guard (bpf LSM active, BTF present); install it and run `systemctl enable --now cotty-guard` for the strong assurance level."}
	}
	return confine.Check{Name: "guard", Status: "warn", Value: "not answering",
		Explain: "cotty-guard is installed but did not answer: " + strings.TrimSpace(err.Error())}
}
