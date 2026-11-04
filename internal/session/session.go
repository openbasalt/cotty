// Package session holds where sessions live on disk: the runtime
// directory, socket and metadata paths, session names and listing.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Meta is <name>.json next to the socket.
type Meta struct {
	Name      string `json:"name"`
	BrokerPID int    `json:"broker_pid"`
	PTS       string `json:"pts"`
	PTSRdev   uint64 `json:"pts_rdev"`
	Created   string `json:"created"`
	// BrokerStart is the broker's start time (field 22 of /proc/PID/stat),
	// so a reused pid does not pass for the broker.
	BrokerStart uint64 `json:"broker_start,omitempty"`
}

// A name never starts with "-" or ".": "-x" would read as a flag on a
// broker's command line (review G1).
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$`)

// ValidName reports whether a session name is acceptable.
func ValidName(n string) bool {
	return nameRE.MatchString(n) && n != "." && n != ".."
}

// Dir returns the runtime directory, creating it (0700) when needed and
// checking that it belongs to the user and is not open to others.
func Dir() (string, error) {
	return DirFor(os.Getenv("XDG_RUNTIME_DIR"))
}

// DirFor is Dir for a given $XDG_RUNTIME_DIR value (empty: the /tmp
// fallback).
func DirFor(runtimeDir string) (string, error) {
	var dir string
	if runtimeDir != "" {
		dir = filepath.Join(runtimeDir, "cotty")
	} else {
		dir = filepath.Join(os.TempDir(), "cotty-"+strconv.Itoa(os.Getuid()))
	}
	return dir, ensurePrivateDir(dir)
}

// AgentSubdir is the name of the agent endpoint directory inside the
// runtime directory.
const AgentSubdir = "agent"

// AgentDir returns the agent endpoint directory inside the runtime
// directory dir, creating it (0700) when needed. It holds one socket per
// session shared with agents, <name>.sock, served by that session's
// broker; connections there may only take the agent and info roles.
// `cotty agent` binds this directory (read-only) into the confinement, so
// sessions shared or restarted after the agent started still appear.
func AgentDir(dir string) (string, error) {
	ad := filepath.Join(dir, AgentSubdir)
	return ad, ensurePrivateDir(ad)
}

// ensurePrivateDir creates dir (0700) when missing and checks that it is
// a directory owned by the user and closed to others.
func ensurePrivateDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a directory owned by uid %d", dir, os.Getuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %v, want 0700", dir, fi.Mode().Perm())
	}
	return nil
}

// StateBase returns $XDG_STATE_HOME/cotty (default ~/.local/state/cotty)
// without creating it: the audit log and per-session state live there,
// outside every agent project (cotty agent refuses it as a project or an
// extra path).
func StateBase() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "cotty")
}

// StateDir returns $XDG_STATE_HOME/cotty/sessions/<name>, created 0700:
// the session shell's history file and any shell integration state.
func StateDir(name string) (string, error) {
	base := StateBase()
	if base == "" {
		return "", errors.New("no home directory for the session state")
	}
	if !ValidName(name) {
		return "", fmt.Errorf("invalid session name %q", name)
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	if err := ensurePrivateDir(filepath.Join(base, "sessions")); err != nil {
		return "", err
	}
	d := filepath.Join(base, "sessions", name)
	return d, ensurePrivateDir(d)
}

// Paths of one session.
type Paths struct {
	Dir, Socket, Meta, Log string
	// Lock is held (flock) by the session's broker for its lifetime: one
	// broker per session name.
	Lock string
	// AgentSocket is the session's agent endpoint, present while the
	// session is shared with agents.
	AgentSocket string
}

// PathsFor returns the paths of a session.
func PathsFor(dir, name string) Paths {
	return Paths{
		Dir:         dir,
		Socket:      filepath.Join(dir, name+".sock"),
		Meta:        filepath.Join(dir, name+".json"),
		Log:         filepath.Join(dir, name+".log"),
		Lock:        filepath.Join(dir, name+".lock"),
		AgentSocket: filepath.Join(dir, AgentSubdir, name+".sock"),
	}
}

// Names lists sessions that have a socket, sorted.
func Names(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".sock"); ok && ValidName(n) {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, ea := strconv.Atoi(out[i])
		b, eb := strconv.Atoi(out[j])
		if ea == nil && eb == nil {
			return a < b
		}
		return out[i] < out[j]
	})
	return out, nil
}

// FreeName returns the lowest number not used as a session name.
func FreeName(dir string) (string, error) {
	names, err := Names(dir)
	if err != nil {
		return "", err
	}
	used := map[string]bool{}
	for _, n := range names {
		used[n] = true
	}
	for i := 1; ; i++ {
		if !used[strconv.Itoa(i)] {
			return strconv.Itoa(i), nil
		}
	}
}

// ReadMeta reads a session's metadata.
func ReadMeta(path string) (Meta, error) {
	var m Meta
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}

// WriteMeta writes a session's metadata (0600).
func WriteMeta(path string, m Meta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// OtherTTYs returns the pts devices of the live sessions in dir, except
// the named one.
func OtherTTYs(dir, except string) []uint64 {
	names, _ := Names(dir)
	var out []uint64
	for _, n := range names {
		if n == except {
			continue
		}
		m, err := ReadMeta(PathsFor(dir, n).Meta)
		if err == nil && m.PTSRdev != 0 {
			out = append(out, m.PTSRdev)
		}
	}
	return out
}

// Resolve picks a session: the given name, or the only one. With several
// sessions the name is required: picking one by socket time would let any
// process of the user steer the person to a socket it created.
func Resolve(dir, name string) (string, error) {
	if name != "" {
		if !ValidName(name) {
			return "", fmt.Errorf("invalid session name %q", name)
		}
		if _, err := os.Stat(PathsFor(dir, name).Socket); err != nil {
			return "", fmt.Errorf("no session %q", name)
		}
		return name, nil
	}
	names, err := Names(dir)
	if err != nil {
		return "", err
	}
	switch len(names) {
	case 0:
		return "", errors.New("no cotty sessions")
	case 1:
		return names[0], nil
	}
	return "", fmt.Errorf("several sessions (%s): name one", strings.Join(names, ", "))
}

// CheckPrivateDir checks, without creating anything, that dir is a
// directory owned by the user and closed to others (mode 0700 or
// stricter), and that it is not a symbolic link.
func CheckPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a directory owned by uid %d", dir, os.Getuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %v, want 0700", dir, fi.Mode().Perm())
	}
	return nil
}

// CheckSocket checks that path is a socket owned by the user, closed to
// others, in a private directory (CheckPrivateDir).
func CheckSocket(path string) error {
	if err := CheckPrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || fi.Mode()&os.ModeSocket == 0 || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a socket owned by uid %d", path, os.Getuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %v, want 0600", path, fi.Mode().Perm())
	}
	return nil
}
