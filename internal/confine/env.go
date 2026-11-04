package confine

import (
	"sort"
	"strings"
)

// The agent's environment is built from an allowlist: the variables a
// terminal program needs (locale, terminal type, editor, proxies and CA
// bundles, toolchain locations) pass, everything else is removed. Tokens
// in the environment need no socket to be useful (the network is open),
// so a variable that is not listed here does not reach the agent unless
// its profile keeps it ([scrub] keep = NAME or PREFIX*): model provider
// keys pass only through the profile of the CLI that needs them.

// envAllowExact are variables that pass.
var envAllowExact = []string{
	"HOME", "USER", "LOGNAME", "SHELL", "PATH", "TERM", "COLORTERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION",
	"LANG", "LANGUAGE", "TZ", "EDITOR", "VISUAL", "PAGER", "MANPAGER", "LESS", "LESSCHARSET",
	"NO_COLOR", "FORCE_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "COLUMNS", "LINES", "HOSTNAME",
	"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_DIRS", "XDG_CONFIG_DIRS",
	// Network: proxies and certificate bundles (a proxy URL can carry a
	// password; it is the person's network configuration all the same).
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
	// Toolchains: where they live and how they build.
	"GOPATH", "GOROOT", "GOBIN", "GOFLAGS", "GOPROXY", "GOPRIVATE", "GONOSUMDB", "GONOPROXY", "GOSUMDB",
	"GOTOOLCHAIN", "GOCACHE", "GOMODCACHE", "GOOS", "GOARCH", "GOAMD64", "CGO_ENABLED",
	"CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "PKG_CONFIG_PATH", "MAKEFLAGS",
	"CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTFLAGS", "JAVA_HOME", "GRADLE_USER_HOME",
	"NODE_PATH", "NODE_OPTIONS", "NVM_DIR", "NVM_BIN", "PNPM_HOME", "BUN_INSTALL", "DENO_DIR", "VOLTA_HOME",
	"PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED", "PYTHONIOENCODING", "VIRTUAL_ENV", "PYENV_ROOT",
	"PIPX_HOME", "UV_PYTHON_INSTALL_DIR", "CONDA_PREFIX", "GEM_HOME", "GEM_PATH", "RBENV_ROOT",
	"ASDF_DIR", "ASDF_DATA_DIR", "DEBUGINFOD_URLS",
}

// envAllowPrefix are prefixes of variables that pass.
var envAllowPrefix = []string{"LC_"}

// scrubAlways are prefixes removed even when a profile keeps them: cotty's
// own variables are set by the launcher.
var scrubAlways = []string{"COTTY_"}

// ScrubEnv returns env reduced to the allowlist. keep names more variables
// that pass (NAME or PREFIX*), drop removes some (NAME or PREFIX*), and
// drop wins over the allowlist but not over keep.
func ScrubEnv(env []string, keep, drop []string) []string {
	allow := map[string]bool{}
	for _, k := range envAllowExact {
		allow[k] = true
	}
	keepSet, keepPre := splitPatterns(keep)
	// An empty prefix ("*") would keep the whole environment; profile
	// parsing refuses it, and it is ignored here as well.
	keepPre = nonEmpty(keepPre)
	dropSet, dropPre := splitPatterns(drop)
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if hasAnyPrefix(k, scrubAlways) {
			continue
		}
		if keepSet[k] || hasAnyPrefix(k, keepPre) {
			out = append(out, kv)
			continue
		}
		if dropSet[k] || hasAnyPrefix(k, dropPre) {
			continue
		}
		if allow[k] || hasAnyPrefix(k, envAllowPrefix) {
			out = append(out, kv)
		}
	}
	return out
}

// splitPatterns separates exact names from PREFIX* patterns.
func splitPatterns(ps []string) (map[string]bool, []string) {
	exact := map[string]bool{}
	var pre []string
	for _, p := range ps {
		if q, ok := strings.CutSuffix(p, "*"); ok {
			pre = append(pre, q)
		} else {
			exact[p] = true
		}
	}
	return exact, pre
}

func nonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// SetEnv returns env with each of vars (KEY=VALUE) set, replacing any
// earlier value, sorted.
func SetEnv(env []string, vars map[string]string) []string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	for k, v := range vars {
		m[k] = v
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// configuredDisplays returns the display and session bus settings of env
// that mean an abstract socket can exist (a local DISPLAY such as ":0", a
// WAYLAND_DISPLAY, whose compositor may start Xwayland on demand, an
// abstract or tmpdir D-Bus address). Below Landlock ABI 6 an agent can
// reach their abstract sockets, also ones started after the launch.
func configuredDisplays(env []string) []string {
	var out []string
	if d := GetEnv(env, "DISPLAY"); d != "" {
		// host:N is X11 over TCP; an empty host (":0") or "unix:0" is local.
		if host, _, ok := strings.Cut(d, ":"); ok && (host == "" || host == "unix" || strings.HasPrefix(host, "/")) {
			out = append(out, "DISPLAY="+d)
		}
	}
	if w := GetEnv(env, "WAYLAND_DISPLAY"); w != "" {
		out = append(out, "WAYLAND_DISPLAY="+w)
	}
	// unix:abstract= is abstract; unix:tmpdir= lets the bus pick an
	// abstract socket. unix:path= and unix:dir= are pathname sockets, which
	// the mount view hides (they live in the runtime directory or /tmp).
	if b := GetEnv(env, "DBUS_SESSION_BUS_ADDRESS"); strings.Contains(b, "unix:abstract=") || strings.Contains(b, "unix:tmpdir=") {
		out = append(out, "DBUS_SESSION_BUS_ADDRESS="+b)
	}
	return out
}

// GetEnv returns the value of key in env.
func GetEnv(env []string, key string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}
