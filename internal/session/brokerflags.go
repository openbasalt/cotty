package session

import (
	"flag"
	"io"
)

// BrokerFlags are the flags of `cotty __broker`. `cotty new` defines the
// shared ones and passes them on; cotty-guard parses a broker's command
// line with the same definitions, so both read it alike (review G1).
type BrokerFlags struct {
	Name        string
	AI          bool
	Policy      string
	Insecure    bool
	CountSecret bool
	RequireConf bool
	Rows, Cols  int
}

// Define adds the flags `cotty new` shares with the broker.
func (f *BrokerFlags) Define(fs *flag.FlagSet) {
	fs.StringVar(&f.Name, "name", "", "session name (default: the lowest free number)")
	fs.BoolVar(&f.AI, "ai", false, "share the session with agents from the start")
	fs.StringVar(&f.Policy, "policy", "auto", "agent input policy: auto or confirm")
	fs.BoolVar(&f.Insecure, "dev-insecure", false, "development only: every process of the user counts as a person")
	fs.BoolVar(&f.CountSecret, "count-secret-keys", false, "log how many keys were typed at secret prompts")
	fs.BoolVar(&f.RequireConf, "require-confined", false, "refuse agents that were not started with cotty agent (assurance weak)")
}

// DefineBroker adds every flag of `cotty __broker`.
func (f *BrokerFlags) DefineBroker(fs *flag.FlagSet) {
	f.Define(fs)
	fs.IntVar(&f.Rows, "rows", 24, "")
	fs.IntVar(&f.Cols, "cols", 80, "")
}

// ParseBrokerArgs parses a broker's arguments (after "__broker") the way
// the broker does. It returns the flags and the shell command line.
func ParseBrokerArgs(args []string) (BrokerFlags, []string, error) {
	var f BrokerFlags
	fs := flag.NewFlagSet("__broker", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f.DefineBroker(fs)
	err := fs.Parse(args)
	return f, fs.Args(), err
}
