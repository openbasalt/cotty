package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/openbasalt/cotty/internal/confine"
	"github.com/openbasalt/cotty/internal/peer"
	"github.com/openbasalt/cotty/internal/secretsrc"
)

func init() {
	register(command{name: "doctor", summary: "check what this system offers for confining agents", run: runDoctor})
}

func runDoctor(args []string) int {
	fs := flag.NewFlagSet("cotty doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	r := confine.Doctor()
	r.Checks = append(r.Checks, sessionChecks()...)
	r.Checks = append(r.Checks, guardCheck())
	r.Sessions, r.SessionsNote = sessionsSummary(r.Assurance, r.Checks)
	if *asJSON {
		return printJSON(r)
	}
	for _, c := range r.Checks {
		fmt.Printf("%-5s %-9s %s\n", strings.ToUpper(c.Status), c.Name, c.Value)
		if c.Explain != "" {
			fmt.Printf("%s\n", indent(wrap(c.Explain, 70), "                "))
		}
	}
	fmt.Printf("\nassurance for `cotty agent` (layer 2): %s\n", r.Assurance)
	for _, g := range r.Gaps {
		fmt.Printf("%s\n", indent(wrap("- "+g, 70), "  "))
	}
	fmt.Printf("\nassurance for new sessions: %s\n", r.Sessions)
	if r.SessionsNote != "" {
		fmt.Printf("%s\n", indent(wrap(r.SessionsNote, 70), "  "))
	}
	if r.Assurance == "unavailable" {
		return 1
	}
	return 0
}

// sessionsSummary says which assurance a session created now can reach,
// from the layer 2 level and the binary and guard checks: strong needs
// layer 2, a trusted binary and a running guard (peer.Classifier). A
// session keeps the level it got at its start: one created before the
// guard started stays below strong (guard.Session treats it as a lapse).
func sessionsSummary(layer2 string, checks []confine.Check) (string, string) {
	status := map[string]string{}
	for _, c := range checks {
		status[c.Name] = c.Status
	}
	guardRunning := status["guard"] == "ok"
	switch {
	case layer2 == "unavailable":
		return "unavailable (cotty agent cannot start here)", ""
	case status["binary"] == "warn":
		return "weak (the cotty binary can be replaced by your user)", "Sessions report weak until cotty is installed root-owned (see the binary line above)."
	case guardRunning:
		return "strong available for new sessions (cotty-guard running)",
			"Sessions created before cotty-guard started stay at their level (confined); start a new session to get strong."
	case status["guard"] == "warn":
		return "confined (cotty-guard not answering)", "Sessions are not strong while cotty-guard does not answer."
	}
	return "confined (cotty-guard not running)",
		"Sessions created before cotty-guard starts stay confined; only sessions created after it starts can reach strong."
}

// sessionChecks report what the session side (broker, masking list)
// depends on.
func sessionChecks() []confine.Check {
	var out []confine.Check
	add := func(name, status, value, explain string) {
		out = append(out, confine.Check{Name: name, Status: status, Value: value, Explain: explain})
	}
	if exe, err := os.Executable(); err == nil {
		if ok, why := peer.ExeTrust(exe, os.Getuid()); ok {
			add("binary", "ok", exe, "Root-owned and not writable by you: a person attach is checked against this binary, so sessions report assurance confined or strong.")
		} else {
			add("binary", "warn", exe, "This cotty can be replaced by your user ("+why+"), so a program of yours could pose as the attach client; sessions report assurance weak. Install cotty from a package or as root in /usr/local/bin.")
		}
	}
	cfgPath := secretsrc.DefaultConfigPath()
	cfg, err := secretsrc.LoadConfig(cfgPath)
	usesSS := false
	switch {
	case errors.Is(err, os.ErrNotExist):
		add("secrets", "info", "no masking list", "No "+cfgPath+": only the built-in token rules mask what agents read. Add values with `cotty secrets add NAME`.")
	case err != nil:
		add("secrets", "warn", "unreadable", err.Error())
	default:
		for _, e := range cfg.Secrets {
			if e.Ref.Scheme == secretsrc.SchemeSecretService {
				usesSS = true
			}
		}
		add("secrets", "ok", strconv.Itoa(len(cfg.Secrets))+" named", "Sessions mask these values and the built-in token rules in everything agents read. `cotty secrets check` reads each one without printing it.")
	}
	if p, err := exec.LookPath("secret-tool"); err == nil {
		add("secret-tool", "ok", p, "Secret Service references (secret-service:attr=val) can be read.")
	} else if usesSS {
		add("secret-tool", "fail", "missing", "secrets.conf has Secret Service references but secret-tool is not installed (libsecret-tools on Debian and Ubuntu, libsecret on Fedora and Arch).")
	} else {
		add("secret-tool", "info", "missing", "Only needed for Secret Service references (libsecret-tools on Debian and Ubuntu, libsecret on Fedora and Arch).")
	}
	return out
}

func printJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return 1
	}
	return 0
}

// wrap breaks s into lines of at most width characters at spaces.
func wrap(s string, width int) string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(s) {
		if line != "" && len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func indent(s, prefix string) string {
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix)
}
