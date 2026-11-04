// Package secretsrc reads the secret values cotty masks, from the sources a
// person configured: a 0600 env-style file, the desktop Secret Service,
// `pass`, or an external command.
//
// The configuration lives in ~/.config/cotty/secrets.conf (or
// $XDG_CONFIG_HOME/cotty/secrets.conf). It names each secret and says
// where its value comes from; it holds no values itself:
//
//	# cotty secrets: NAME = reference
//	[settings]
//	env_file = ~/.config/cotty/secrets.env   # default shown
//
//	[secrets]
//	GITHUB_TOKEN = file:GITHUB_TOKEN          # key in env_file
//	DB_PASSWORD  = secret-service:service=db,user=app
//	NPM_TOKEN    = pass:dev/npm               # first line of `pass show dev/npm`
//	HUB_KEY      = cmd:hub-key                # stdout of the command below
//
//	[commands]
//	hub-key = ["ai-hub", "secret", "get", "openai/api-key"]
//
// Commands are argv arrays in JSON and run without a shell. Values never
// appear in errors or logs: errors name the secret, the reference and the
// failure, never the content (command stderr is discarded for that reason).
//
// The Secret Service is reached through `secret-tool lookup` (libsecret)
// rather than a D-Bus client library: it keeps the dependency footprint at
// zero, libsecret handles the session encryption and collection unlocking
// prompts, and the broker only needs a value at start-up or on demand. The
// cost is that secret-tool must be installed (libsecret-tools on Debian and
// Ubuntu, libsecret on Fedora and Arch).
package secretsrc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Config is a parsed secrets.conf.
type Config struct {
	// EnvFile is the file that file: references read.
	EnvFile string
	// Secrets maps each secret name to its reference, in file order.
	Secrets []Entry
	// Commands maps a command name to its argv.
	Commands map[string][]string
}

// Entry is one line of the [secrets] section.
type Entry struct {
	Name string
	Ref  Ref
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ConfigDir returns $XDG_CONFIG_HOME/cotty or ~/.config/cotty.
func ConfigDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "cotty")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "cotty")
}

// DefaultConfigPath is ConfigDir()/secrets.conf.
func DefaultConfigPath() string { return filepath.Join(ConfigDir(), "secrets.conf") }

// DefaultEnvFile is ConfigDir()/secrets.env.
func DefaultEnvFile() string { return filepath.Join(ConfigDir(), "secrets.env") }

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[1:])
	}
	return p
}

// openPrivate opens path without following a final symlink and checks that
// it is a regular file owned by the current user, with no permission bits
// in forbidden. It returns the open file.
func openPrivate(path string, forbidden os.FileMode, hint string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s: is a symbolic link; %s", path, hint)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	sys, _ := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm()&forbidden != 0 || sys == nil || int(sys.Uid) != os.Getuid() {
		f.Close()
		return nil, fmt.Errorf("%s: %s", path, hint)
	}
	return f, nil
}

// LoadConfig reads a secrets.conf. The file must be a regular file owned by
// the user and not writable by group or others (it decides which commands
// run). A missing file is reported with an error wrapping os.ErrNotExist.
func LoadConfig(path string) (*Config, error) {
	f, err := openPrivate(path, 0o022, "must be a regular file owned by you and not writable by others (chmod 600)")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseConfig(path, string(data))
}

// ParseConfig parses the text of a secrets.conf; path is used in errors.
func ParseConfig(path, text string) (*Config, error) {
	cfg := &Config{EnvFile: DefaultEnvFile(), Commands: map[string][]string{}}
	seen := map[string]bool{}
	section := ""
	for n, line := range strings.Split(text, "\n") {
		ln := n + 1
		line = strings.TrimSpace(stripComment(line))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			switch section {
			case "settings", "secrets", "commands":
			default:
				return nil, fmt.Errorf("%s:%d: unknown section [%s]", path, ln, section)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY = VALUE", path, ln)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch section {
		case "settings":
			switch k {
			case "env_file":
				cfg.EnvFile = expandHome(v)
			default:
				return nil, fmt.Errorf("%s:%d: unknown setting %q", path, ln, k)
			}
		case "secrets":
			if !nameRE.MatchString(k) {
				return nil, fmt.Errorf("%s:%d: bad secret name (want [A-Za-z0-9_.-]{1,64})", path, ln)
			}
			if seen[k] {
				return nil, fmt.Errorf("%s:%d: secret %s defined twice", path, ln, k)
			}
			ref, err := ParseRef(v)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %s: %w", path, ln, k, err)
			}
			seen[k] = true
			cfg.Secrets = append(cfg.Secrets, Entry{Name: k, Ref: ref})
		case "commands":
			if !nameRE.MatchString(k) {
				return nil, fmt.Errorf("%s:%d: bad command name", path, ln)
			}
			var argv []string
			if err := json.Unmarshal([]byte(v), &argv); err != nil || len(argv) == 0 || argv[0] == "" {
				return nil, fmt.Errorf("%s:%d: command %s: want a JSON array of strings, such as [\"prog\", \"arg\"]", path, ln, k)
			}
			cfg.Commands[k] = argv
		default:
			return nil, fmt.Errorf("%s:%d: entry outside a section", path, ln)
		}
	}
	for _, e := range cfg.Secrets {
		if e.Ref.Scheme == SchemeCmd {
			if _, ok := cfg.Commands[e.Ref.Arg]; !ok {
				return nil, fmt.Errorf("%s: secret %s: no command %q in [commands]", path, e.Name, e.Ref.Arg)
			}
		}
	}
	return cfg, nil
}

// stripComment removes a '#' comment that starts a line or follows a
// blank. JSON arrays and references never need a " #".
func stripComment(line string) string {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
		return ""
	}
	if i := strings.Index(line, " #"); i >= 0 {
		return line[:i]
	}
	if i := strings.Index(line, "\t#"); i >= 0 {
		return line[:i]
	}
	return line
}

// Scheme is the kind of a reference.
type Scheme string

const (
	SchemeFile          Scheme = "file"
	SchemeSecretService Scheme = "secret-service"
	SchemePass          Scheme = "pass"
	SchemeCmd           Scheme = "cmd"
)

// Ref says where a value comes from. It holds no value.
type Ref struct {
	Scheme Scheme
	// Arg is the key (file), the pass path (pass) or the command name (cmd).
	Arg string
	// Attrs are the attribute pairs of a secret-service reference, in order.
	Attrs [][2]string
}

// String formats the reference as written in the config.
func (r Ref) String() string {
	if r.Scheme == SchemeSecretService {
		parts := make([]string, len(r.Attrs))
		for i, a := range r.Attrs {
			parts[i] = a[0] + "=" + a[1]
		}
		return string(r.Scheme) + ":" + strings.Join(parts, ",")
	}
	return string(r.Scheme) + ":" + r.Arg
}

// ParseRef parses file:KEY, secret-service:attr=val,..., pass:path or cmd:NAME.
func ParseRef(s string) (Ref, error) {
	scheme, arg, ok := strings.Cut(s, ":")
	if !ok || arg == "" {
		return Ref{}, fmt.Errorf("bad reference %q: want file:KEY, secret-service:attr=val,..., pass:PATH or cmd:NAME", s)
	}
	r := Ref{Scheme: Scheme(scheme), Arg: arg}
	switch r.Scheme {
	case SchemeFile, SchemeCmd:
		if !nameRE.MatchString(arg) {
			return Ref{}, fmt.Errorf("bad reference %q: name must match [A-Za-z0-9_.-]{1,64}", s)
		}
	case SchemePass:
		if strings.HasPrefix(arg, "-") || strings.Contains(arg, "\x00") || strings.Contains(arg, "..") {
			return Ref{}, fmt.Errorf("bad reference %q: bad pass path", s)
		}
	case SchemeSecretService:
		r.Arg = ""
		for _, pair := range strings.Split(arg, ",") {
			k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || k == "" || v == "" || strings.HasPrefix(k, "-") || strings.HasPrefix(v, "-") {
				return Ref{}, fmt.Errorf("bad reference %q: want secret-service:attr=val[,attr=val...]", s)
			}
			r.Attrs = append(r.Attrs, [2]string{k, v})
		}
	default:
		return Ref{}, fmt.Errorf("bad reference %q: unknown source %q", s, scheme)
	}
	return r, nil
}
