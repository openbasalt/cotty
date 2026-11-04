// Profile parsing for cotty agent.
//
// Adapted from basalt-agent's internal/profile (basalt-os/basalt-os,
// packages/basalt-agent, Apache-2.0, same owner): the same INI shape
// ([section] headers, "key = value" lines, list keys repeat), with the
// sections cotty needs instead of basalt-agent's install, secrets and
// egress ones.
//
//	[agent]   name, description, command (program looked up in PATH),
//	          args (space separated, always passed first),
//	          match = NAME (repeatable): executable names that select this
//	          profile when cotty agent is given a command but no --profile
//	[home]    rw = REL (repeatable): a path under $HOME the agent may read
//	          and write (its own login state and settings); a trailing "/"
//	          marks a directory that is created when missing,
//	          ro = REL (repeatable): read-only (its installed program),
//	          protect = REL (repeatable): read-only on top of an rw entry
//	          (files whose content later runs with the person's rights,
//	          such as hook definitions), applied only when the file exists,
//	          seed = SRC DST: before the launch, outside, copy the file
//	          ~/SRC to ~/DST (0600) when DST does not exist yet (the first
//	          state of a file the agent keeps elsewhere)
//	[paths]   ro = /ABS, rw = /ABS (repeatable): paths outside $HOME,
//	          dev = NAME (repeatable): a host device node under /dev to
//	          expose (kvm, dri/renderD128)
//	[sockets] allow = /ABS (repeatable): a pathname Unix socket the agent
//	          may connect to (Landlock ABI 9 and later enforce the list)
//	[env]     KEY = value, set for the agent
//	[scrub]   keep = NAME or PREFIX* (repeatable): pass a variable that is
//	          not on the environment allowlist (env.go), such as the model
//	          provider key the CLI needs; drop = NAME or PREFIX*
//	          (repeatable): remove one that is
//	[mcp]     style = claude | codex | opencode | manual | none: how
//	          cotty agent points the agent at `cotty mcp`
//
// Profiles are looked up in ~/.config/cotty/profiles, then
// /etc/cotty/profiles, then the set built into the binary.
package confine

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/openbasalt/cotty/profiles"
)

// Profile is one agent's confinement profile.
type Profile struct {
	Name        string
	Description string
	Command     string
	Args        []string
	Match       []string
	HomeRW      []string // relative to $HOME
	HomeRO      []string
	HomeProtect []string
	// HomeHide are directories under a writable home entry that the agent
	// sees empty (a tmpfs on top): what is there outside is neither
	// readable nor writable inside.
	HomeHide  []string
	HomeSeed  [][2]string // {src, dst}, relative to $HOME
	PathRO    []string    // absolute
	PathRW    []string
	Devices   []string // names under /dev
	Sockets   []string // absolute socket paths
	Env       map[string]string
	ScrubKeep []string
	ScrubDrop []string
	MCPStyle  string
	Source    string
}

var (
	nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	envRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	devRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_./-]*$`)
)

// reservedEnv are variables the launcher owns; a profile cannot set them.
var reservedEnv = map[string]bool{
	"HOME": true, "PATH": true, "XDG_RUNTIME_DIR": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"SSH_AUTH_SOCK": true, "DBUS_SESSION_BUS_ADDRESS": true, "DISPLAY": true, "WAYLAND_DISPLAY": true,
	"COTTY_AGENT": true, "COTTY_AGENT_SOCKET": true, "COTTY_AGENT_DIR": true, "COTTY_ASSURANCE": true,
}

// ValidName reports whether s can be a profile name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ProfileDirs returns the directories searched for profiles, in order.
func ProfileDirs() []string {
	var dirs []string
	if cfg, err := os.UserConfigDir(); err == nil {
		dirs = append(dirs, filepath.Join(cfg, "cotty", "profiles"))
	}
	return append(dirs, "/etc/cotty/profiles")
}

// LoadProfile finds and parses the profile name: user directory, system
// directory, then the built-in set.
func LoadProfile(name string) (*Profile, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("bad profile name %q", name)
	}
	for _, d := range ProfileDirs() {
		f := filepath.Join(d, name+".conf")
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		defer fh.Close()
		return parseNamed(fh, f, name)
	}
	fh, err := profiles.FS.Open(name + ".conf")
	if err != nil {
		return nil, fmt.Errorf("no profile %q (cotty agent --list-profiles)", name)
	}
	defer fh.Close()
	return parseNamed(fh, "builtin:"+name+".conf", name)
}

func parseNamed(r io.Reader, src, name string) (*Profile, error) {
	p, err := ParseProfile(r, src)
	if err != nil {
		return nil, err
	}
	if p.Name != name {
		return nil, fmt.Errorf("%s: name = %q, want %q", src, p.Name, name)
	}
	return p, nil
}

// ListProfiles returns every profile name visible through the
// directories and the built-in set.
func ListProfiles() []string {
	seen := map[string]bool{}
	for _, d := range ProfileDirs() {
		m, _ := filepath.Glob(filepath.Join(d, "*.conf"))
		for _, f := range m {
			if n := strings.TrimSuffix(filepath.Base(f), ".conf"); ValidName(n) {
				seen[n] = true
			}
		}
	}
	m, _ := fs.Glob(profiles.FS, "*.conf")
	for _, f := range m {
		if n := strings.TrimSuffix(path.Base(f), ".conf"); ValidName(n) {
			seen[n] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// GuessProfile returns the profile whose match list (or command) names the
// executable of argv0, else "generic".
func GuessProfile(argv0 string) string {
	base := filepath.Base(argv0)
	for _, n := range ListProfiles() {
		if n == "generic" {
			continue
		}
		p, err := LoadProfile(n)
		if err != nil {
			continue
		}
		if p.Command == base {
			return n
		}
		for _, m := range p.Match {
			if m == base {
				return n
			}
		}
	}
	return "generic"
}

// ParseProfile parses one profile from r; src names it in errors.
func ParseProfile(r io.Reader, src string) (*Profile, error) {
	p := &Profile{Env: map[string]string{}, Source: src, MCPStyle: "none"}
	sc := bufio.NewScanner(r)
	section, n := "", 0
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%s:%d: %s", src, n, fmt.Sprintf(format, a...))
	}
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			switch section {
			case "agent", "home", "paths", "sockets", "env", "scrub", "mcp":
			default:
				return nil, fail("unknown section [%s]", section)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fail("expected key = value")
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch section + "." + k {
		case "agent.name":
			p.Name = v
		case "agent.description":
			p.Description = v
		case "agent.command":
			p.Command = v
		case "agent.args":
			p.Args = strings.Fields(v)
		case "agent.match":
			p.Match = append(p.Match, strings.Fields(v)...)
		case "home.rw", "home.ro", "home.protect", "home.hide":
			if err := checkRel(v); err != nil {
				return nil, fail("%v", err)
			}
			switch k {
			case "rw":
				p.HomeRW = append(p.HomeRW, v)
			case "ro":
				p.HomeRO = append(p.HomeRO, v)
			case "hide":
				p.HomeHide = append(p.HomeHide, strings.TrimSuffix(v, "/"))
			default:
				p.HomeProtect = append(p.HomeProtect, v)
			}
		case "home.seed":
			f := strings.Fields(v)
			if len(f) != 2 {
				return nil, fail("seed takes two home paths: SRC DST")
			}
			for _, x := range f {
				if err := checkRel(x); err != nil || strings.HasSuffix(x, "/") {
					return nil, fail("bad seed path %q", x)
				}
			}
			p.HomeSeed = append(p.HomeSeed, [2]string{f[0], f[1]})
		case "paths.ro", "paths.rw":
			if !filepath.IsAbs(v) || filepath.Clean(v) == "/" {
				return nil, fail("%s must be an absolute path other than /", k)
			}
			if k == "ro" {
				p.PathRO = append(p.PathRO, filepath.Clean(v))
			} else {
				p.PathRW = append(p.PathRW, filepath.Clean(v))
			}
		case "paths.dev":
			if !devRe.MatchString(v) || strings.Contains(v, "..") {
				return nil, fail("bad device name %q", v)
			}
			p.Devices = append(p.Devices, v)
		case "sockets.allow":
			if !filepath.IsAbs(v) {
				return nil, fail("socket path must be absolute")
			}
			p.Sockets = append(p.Sockets, filepath.Clean(v))
		case "scrub.keep":
			if pre, ok := strings.CutSuffix(v, "*"); ok && len(pre) < 3 {
				return nil, fail("keep = %s would pass too much of your environment (tokens included): name the variables or a prefix of 3 characters or more", v)
			}
			if !envRe.MatchString(strings.TrimSuffix(v, "*")) {
				return nil, fail("bad variable name %q", v)
			}
			p.ScrubKeep = append(p.ScrubKeep, v)
		case "scrub.drop":
			if !envRe.MatchString(strings.TrimSuffix(v, "*")) {
				return nil, fail("bad variable name %q", v)
			}
			p.ScrubDrop = append(p.ScrubDrop, v)
		case "mcp.style":
			switch v {
			case "claude", "codex", "opencode", "manual", "none":
				p.MCPStyle = v
			default:
				return nil, fail("unknown mcp style %q", v)
			}
		default:
			if section == "env" {
				if !envRe.MatchString(k) || reservedEnv[k] {
					return nil, fail("variable %q cannot be set by a profile", k)
				}
				p.Env[k] = v
				continue
			}
			return nil, fail("unknown key %q in [%s]", k, section)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return p, p.validate()
}

// checkRel accepts a clean relative path under $HOME, optionally ending in
// "/" (a directory created when missing).
func checkRel(v string) error {
	t := strings.TrimSuffix(v, "/")
	if t == "" || filepath.IsAbs(t) || filepath.Clean(t) != t || t == "." || strings.HasPrefix(t, "..") {
		return fmt.Errorf("home path %q must be relative to $HOME, clean, and not $HOME itself", v)
	}
	// The person's own credential stores never go into a profile, nor
	// does a parent directory that contains one.
	for _, prot := range protectedHomeRel {
		if t == prot || strings.HasPrefix(t, prot+"/") || strings.HasPrefix(prot, t+"/") {
			return fmt.Errorf("home path %q is or contains %s, a credential store or cotty's own state, and cannot be given to an agent", v, "~/"+prot)
		}
	}
	return nil
}

// protectedHomeRel are paths under $HOME no agent may see: credential
// stores, the keyring, and cotty's own configuration (secret sources) and
// state (audit log, session history).
var protectedHomeRel = []string{".ssh", ".gnupg", ".password-store", ".pki", ".mozilla", ".aws", ".kube", ".docker",
	".local/share/keyrings", ".config/cotty", ".local/state/cotty",
	// Forge, cloud, package registry and storage credentials.
	".config/gh", ".netrc", ".git-credentials", ".config/gcloud", ".azure", ".npmrc", ".pypirc",
	".cargo/credentials.toml", ".cargo/credentials", ".vault-token", ".config/rclone"}

func (p *Profile) validate() error {
	if !ValidName(p.Name) {
		return fmt.Errorf("%s: bad or missing name", p.Source)
	}
	if p.Command != "" && strings.ContainsAny(p.Command, "/ \t") {
		return fmt.Errorf("%s: command must be a program name looked up in PATH", p.Source)
	}
	return nil
}
