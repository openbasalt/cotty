package confine

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

	"github.com/openbasalt/cotty/internal/session"
)

// Options are the launcher's inputs, from the command line.
type Options struct {
	Profile  string   // empty: guessed from Argv[0]
	Project  string   // empty: the current directory
	Argv     []string // empty: the profile's command
	ExtraRO  []string // --ro
	ExtraRW  []string // --rw
	AgentDir string   // empty: $XDG_RUNTIME_DIR/cotty/agent (session.AgentDir)
	NoMCP    bool
	PTY      string // auto or always
	Quiet    bool
	// DryRun computes the plan without creating anything outside
	// (placeholders, profile directories, seeds).
	DryRun bool
	// AllowGitInit leaves a project without .git as it is, so the agent
	// can run `git init` (and plant hooks the person's git would run).
	AllowGitInit bool
	// AllowAbstractSockets starts the agent on Landlock ABI < 6 even when
	// abstract X11 or D-Bus sockets are listening.
	AllowAbstractSockets bool
	// AllowGitLinks starts the agent even when a git file cotty protects
	// (the .git entry, config, hooks, core.hooksPath) is a symbolic link,
	// which the agent could replace.
	AllowGitLinks bool
	// ShowHidden leaves the profile's hidden home directories (home.hide,
	// such as Claude Code's IDE lock files) visible.
	ShowHidden bool
}

// Plan is a computed launch: the spec plus what the launcher reports.
type Plan struct {
	Spec    Spec
	Profile *Profile
	Notes   []string // skipped entries and other remarks for the person
	MCP     bool     // the agent was pointed at cotty mcp
	// Placeholders are paths created outside before the launch so they
	// could be bound read-only (protected files that did not exist).
	Placeholders []string
	// GitWatch are git directories without a commondir file: creating one
	// inside would redirect git, so the launcher watches them.
	GitWatch []string
	// GitEntries are the .git entries of the project at launch; new ones
	// are reported when the agent exits.
	GitEntries []string
	// GitInitGuard is the empty .git placed in a project without one
	// (removed after the run when still empty and no other agent uses it).
	GitInitGuard string
}

// commonHomeRO are files every profile gets read-only: git identity and
// global ignore rules, so commits work. Credential helpers they name point
// at files that stay hidden.
var commonHomeRO = []string{".gitconfig", ".config/git/config", ".config/git/ignore", ".config/git/attributes"}

// systemRO are the system hierarchies an agent may read and execute.
var systemRO = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt", "/var", "/nix", "/snap", "/gnu", "/run", "/sys"}

// systemSockets are system service sockets an agent may connect to when
// Landlock mediates pathname sockets (ABI 9): name resolution, user
// database, logging.
var systemSockets = []string{"/run/systemd/resolve", "/run/systemd/userdb", "/run/systemd/journal", "/dev/log", "/run/nscd", "/var/run/nscd", "/var/lib/sss/pipes"}

// defaultDevices are the host device nodes of the private /dev.
var defaultDevices = []string{"null", "zero", "full", "random", "urandom", "tty"}

// hideSystem are system directories covered with a tmpfs besides $HOME
// and /tmp. All of /run is covered: it holds root daemon sockets that
// group membership opens (docker.sock, libvirt, snapd), the system bus
// (polkit actions allowed to active sessions), screen's sockets, smart
// card and removable media paths; before Landlock ABI 9 nothing else
// would stop a connect() to them. runKeep is put back.
var hideSystem = []string{"/var/tmp", "/run"}

// hideSockets are directories outside /run and /tmp that hold pathname
// sockets of system services: group membership (incus, lxd, libvirt) or
// peer credentials (MySQL unix_socket auth, the nix daemon) can make a
// connect worth as much as root or a login. Before Landlock ABI 9 only the
// mount view keeps an agent away from them, so they are covered with an
// empty tmpfs when they exist (on every ABI: the agent does not need
// them). The journal and the mail spool hold other programs' output and
// the person's mail; readable for adm or wheel members, covered too.
var hideSockets = []string{
	"/var/lib/incus", "/var/lib/lxd", "/var/snap/lxd/common", "/var/lib/libvirt", "/var/lib/mysql",
	"/var/lib/mysqld", "/var/lib/postgresql", "/var/lib/docker", "/var/lib/containers", "/var/lib/containerd",
	"/var/lib/podman", "/var/lib/waydroid", "/var/lib/tailscale", "/var/lib/clamav", "/var/lib/samba",
	"/var/lib/sss/pipes/private", "/var/lib/systemd", "/var/lib/snapd", "/var/spool/postfix", "/var/spool/cups",
	"/var/log/journal", "/var/spool/mail", "/var/mail", "/nix/var/nix/daemon-socket", "/opt/containerd",
	"/var/lib/kubelet", "/var/lib/rancher",
}

// runKeep are paths under /run that stay visible (when they exist): DNS
// resolver configuration (the target of /etc/resolv.conf on most
// distributions), logging, name service caches, NixOS system paths.
var runKeep = []string{
	"/run/systemd/resolve", "/run/systemd/journal", "/run/systemd/userdb", "/run/NetworkManager/resolv.conf",
	"/run/NetworkManager/no-stub-resolv.conf", "/run/resolvconf", "/run/nscd", "/run/current-system",
	"/run/booted-system", "/run/opengl-driver", "/run/wrappers",
}

// BuildPlan computes the launch for opts in environment env. self is the
// path of the running cotty binary.
func BuildPlan(opts Options, env []string, self string) (*Plan, error) {
	home := GetEnv(env, "HOME")
	if home == "" || !filepath.IsAbs(home) {
		return nil, errors.New("HOME is not set to an absolute path")
	}
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return nil, fmt.Errorf("HOME: %w", err)
	}
	profName := opts.Profile
	if profName == "" {
		if len(opts.Argv) == 0 {
			return nil, errors.New("give a command after -- or a --profile")
		}
		profName = GuessProfile(opts.Argv[0])
	}
	prof, err := LoadProfile(profName)
	if err != nil {
		return nil, err
	}
	pl := &Plan{Profile: prof}
	note := func(f string, a ...any) { pl.Notes = append(pl.Notes, fmt.Sprintf(f, a...)) }

	project := opts.Project
	if project == "" {
		if project, err = os.Getwd(); err != nil {
			return nil, err
		}
	}
	project, err = filepath.Abs(project)
	if err != nil {
		return nil, err
	}
	if project, err = filepath.EvalSymlinks(project); err != nil {
		return nil, fmt.Errorf("project: %w", err)
	}
	if fi, err := os.Stat(project); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("project %s is not a directory", project)
	}
	sockRoots := socketRoots(env)
	if err := checkProject(project, realHome); err != nil {
		return nil, err
	}
	if err := checkSocketRoots(project, sockRoots); err != nil {
		return nil, err
	}
	prot := protectedPaths(env, realHome)
	if err := checkProtected(project, prot); err != nil {
		return nil, err
	}

	uid, gid := os.Getuid(), os.Getgid()
	runtime := GetEnv(env, "XDG_RUNTIME_DIR")
	if runtime == "" {
		if d := "/run/user/" + strconv.Itoa(uid); isDir(d) {
			runtime = d
		}
	}
	if runtime != "" {
		if r, err := filepath.EvalSymlinks(runtime); err == nil {
			runtime = r
		} else {
			runtime = ""
		}
	}
	insideRuntime := runtime
	if insideRuntime == "" {
		// No runtime directory: give the agent one in its private /tmp.
		insideRuntime = "/tmp/cotty-runtime-" + strconv.Itoa(uid)
	}

	// The agent endpoint directory: every broker serves its session's
	// agent socket there while the session is shared. The directory (not
	// a socket) is bound in, so sessions shared or restarted after the
	// agent started appear inside too. It is created here when missing.
	sdir, err := session.DirFor(GetEnv(env, "XDG_RUNTIME_DIR"))
	defaultAgentDir := ""
	if err == nil {
		defaultAgentDir, err = session.AgentDir(sdir)
	}
	if err != nil {
		defaultAgentDir = ""
		if opts.AgentDir == "" {
			note("no cotty agent endpoint directory (%v): the agent cannot reach cotty", err)
		}
	}
	agentDir := defaultAgentDir
	if opts.AgentDir != "" {
		// The directory is bound into the confinement: it must be cotty's
		// own endpoint directory, never one that holds other sockets.
		r, err := filepath.EvalSymlinks(opts.AgentDir)
		if err != nil {
			return nil, fmt.Errorf("--agent-dir %s: %w", opts.AgentDir, err)
		}
		if err := checkAgentDir(r, defaultAgentDir, uid); err != nil {
			return nil, err
		}
		agentDir = r
	}
	if agentDir != "" {
		if r, err := filepath.EvalSymlinks(agentDir); err == nil && isDir(r) {
			agentDir = r
		} else {
			note("cotty agent endpoint directory %s is missing: the agent cannot reach cotty", agentDir)
			agentDir = ""
		}
	}
	insideAgentDir := ""
	if agentDir != "" {
		insideAgentDir = filepath.Join(insideRuntime, "cotty", session.AgentSubdir)
	}

	sp := &pl.Spec
	sp.Profile, sp.Project, sp.Home, sp.RuntimeDir, sp.AgentDir = prof.Name, project, realHome, runtime, insideAgentDir
	sp.UID, sp.GID = uid, gid
	sp.SelfBin = filepath.Join(insideRuntime, "cotty", "bin", "cotty")
	sp.Seccomp = true
	sp.PTY = opts.PTY == "always"

	sp.Hide = []string{realHome, "/tmp"}
	if runtime != "" && !underAny(runtime, hideSystem) {
		sp.Hide = append(sp.Hide, runtime)
	}
	sp.Hide = append(sp.Hide, hideSystem...)
	for _, h := range hideSockets {
		if fi, err := os.Lstat(h); err == nil && fi.IsDir() {
			sp.Hide = append(sp.Hide, h)
		}
	}

	// Binds. The project first, then home entries, flags, git protection.
	binds := []Bind{{Source: project, Target: project, RW: true, Dir: true, Why: "project"}}
	type homeLink struct {
		path, content, real string
		rw                  bool
		why                 string
	}
	var links []homeLink
	var homeErr error
	// visibleRW are the writable profile directories (relative to $HOME)
	// that are bound or recreated inside. An entry below one that is not
	// (missing, or a link to a place no agent may see) is skipped: its
	// placeholder or hidden directory would be made through the link, in
	// the place the link leads to (review round 4).
	visibleRW := map[string]bool{}
	rwRoot := func(rel string) (string, bool) {
		root := ""
		for _, w := range prof.HomeRW {
			w = strings.TrimSuffix(w, "/")
			if strings.HasPrefix(rel, w+"/") && len(w) > len(root) {
				root = w
			}
		}
		return root, root != "" && visibleRW[root]
	}
	// checkHomeTarget runs the checks of --ro/--rw paths on where a home
	// entry really leads when a link is on the way: a link the agent left
	// in a writable directory on an earlier run (~/.claude/local ->
	// ~/.ssh) must not get its target bound (review C0).
	checkHomeTarget := func(real string) error {
		if err := checkExtra(real, realHome); err != nil {
			return err
		}
		if err := checkProtected(real, prot); err != nil {
			return err
		}
		if err := checkSocketRoots(real, sockRoots); err != nil {
			return err
		}
		return checkHiddenSockets(real)
	}
	addHome := func(rel string, rw bool, why string) bool {
		create := strings.HasSuffix(rel, "/")
		rel = strings.TrimSuffix(rel, "/")
		if root, ok := rwRoot(rel); root != "" && !ok {
			return false // below a writable directory that is not visible inside
		}
		src := filepath.Join(realHome, rel)
		fi, err := os.Stat(src)
		if err != nil && create && rw && !opts.DryRun {
			if err := os.MkdirAll(src, 0o700); err != nil {
				note("cannot create ~/%s: %v", rel, err)
				return false
			}
			fi, err = os.Stat(src)
		}
		if err != nil && why == "protect" && errors.Is(err, os.ErrNotExist) {
			// "protect" means always read-only: a missing file or directory
			// under a writable profile directory is created now, outside
			// and empty, and bound read-only, so the agent cannot create
			// it with content the person's own CLI would run later.
			if _, ok := rwRoot(rel); !ok {
				return false // its directory is not visible inside
			}
			if !opts.DryRun {
				if err := makePlaceholder(src, create, placeholderContent(rel)); err != nil {
					note("cannot create ~/%s to protect it: %v", rel, err)
					return false
				}
			}
			pl.Placeholders = append(pl.Placeholders, src)
			binds = append(binds, Bind{Source: src, Target: src, RW: false, Dir: create, Why: why, NoFollow: true})
			return true
		}
		if err != nil {
			return false // a profile lists every usual location; missing ones are fine
		}
		real, err := filepath.EvalSymlinks(src)
		if err != nil {
			return false
		}
		if real != src {
			if err := checkHomeTarget(real); err != nil {
				if why == "protect" {
					// The path must stay read-only and cannot, safely: the
					// person removes the link (see the message).
					if homeErr == nil {
						homeErr = fmt.Errorf("~/%s is a link to a place no agent may see; remove it before starting an agent (%w)", rel, err)
					}
					return false
				}
				note("~/%s leads to a place no agent may see; not bound: %v", rel, err)
				return false
			}
		}
		if li, err := os.Lstat(src); err == nil && li.Mode()&os.ModeSymlink != 0 {
			if _, under := rwRoot(rel); why == "protect" && fi.IsDir() && under {
				// A link cannot be covered by a directory mount, and a link in
				// a writable directory can be replaced by the agent with a
				// directory of its own, which the person's CLI would load
				// later (review round 4).
				if homeErr == nil {
					homeErr = fmt.Errorf("~/%s is a link to a directory (%s); cotty keeps that path read-only and cannot keep a link to a directory so. Replace the link with the directory itself (with GNU stow: --no-folding) before starting an agent", rel, real)
				}
				return false
			}
			// Decided once every bind is known: a link whose target is
			// visible anyway is recreated as a link, so programs that find
			// their files relative to their own path keep working.
			if content, err := os.Readlink(src); err == nil {
				links = append(links, homeLink{path: src, content: content, real: real, rw: rw, why: why})
				return true
			}
		}
		if !strings.HasPrefix(real+"/", realHome+"/") {
			// A link out of $HOME: expose the real file at the link's place.
			note("~/%s points outside $HOME (%s); bound at its place", rel, real)
		}
		binds = append(binds, Bind{Source: real, Target: src, RW: rw, Dir: fi.IsDir(), Why: why, NoFollow: why == "protect"})
		return true
	}
	for _, r := range prof.HomeRW {
		if addHome(r, true, "profile") {
			visibleRW[strings.TrimSuffix(r, "/")] = true
		}
	}
	for _, sd := range prof.HomeSeed {
		if opts.DryRun {
			break
		}
		if root, ok := rwRoot(sd[1]); root != "" && !ok {
			continue // would be written through a link to a place no agent may see
		}
		if err := seedFile(filepath.Join(realHome, sd[0]), filepath.Join(realHome, sd[1])); err != nil {
			note("seed ~/%s from ~/%s: %v", sd[1], sd[0], err)
		}
	}
	for _, r := range commonHomeRO {
		addHome(r, false, "common")
	}
	for _, r := range prof.HomeRO {
		addHome(r, false, "profile")
	}
	for _, r := range prof.HomeProtect {
		addHome(r, false, "protect")
	}
	if homeErr != nil {
		return nil, homeErr
	}
	// Directories between a writable profile directory and a protected
	// path become mount points too, so the agent cannot rename them away
	// with the protected path inside and put a new one in their place.
	for _, r := range prof.HomeProtect {
		rel := strings.TrimSuffix(r, "/")
		root, ok := rwRoot(rel)
		if !ok {
			continue
		}
		for _, d := range pinDirs(filepath.Join(realHome, root), filepath.Dir(filepath.Join(realHome, rel))) {
			if fi, err := os.Lstat(d); err == nil && fi.IsDir() {
				binds = append(binds, Bind{Source: d, Target: d, RW: true, Dir: true, Why: "pin"})
			}
		}
	}
	addAbs := func(p string, rw bool, why string) error {
		ap, err := filepath.Abs(p)
		if err != nil {
			return err
		}
		real, err := filepath.EvalSymlinks(ap)
		if err != nil {
			if why == "flag" {
				return fmt.Errorf("--%s %s: %w", map[bool]string{true: "rw", false: "ro"}[rw], p, err)
			}
			return nil
		}
		if err := checkExtra(real, realHome); err != nil {
			return err
		}
		if err := checkProtected(real, prot); err != nil {
			return err
		}
		if err := checkSocketRoots(real, sockRoots); err != nil {
			return err
		}
		if err := checkHiddenSockets(real); err != nil {
			return err
		}
		fi, err := os.Stat(real)
		if err != nil {
			return err
		}
		binds = append(binds, Bind{Source: real, Target: real, RW: rw, Dir: fi.IsDir(), Why: why})
		return nil
	}
	for _, p := range prof.PathRO {
		_ = addAbs(p, false, "profile")
	}
	for _, p := range prof.PathRW {
		_ = addAbs(p, true, "profile")
	}
	for _, p := range opts.ExtraRO {
		if err := addAbs(p, false, "flag"); err != nil {
			return nil, err
		}
	}
	for _, p := range opts.ExtraRW {
		if err := addAbs(p, true, "flag"); err != nil {
			return nil, err
		}
	}
	recreated := map[string]string{} // link path -> real path, for links recreated inside
	for _, l := range links {
		visible, writable := false, false
		for _, b := range binds {
			if b.Dir && underAny(l.real, []string{b.Source}) && b.Source == b.Target {
				visible = true
				writable = writable || b.RW
			}
		}
		fi, err := os.Stat(l.real)
		if l.why == "protect" {
			if err != nil {
				continue
			}
			// A protected path that is a link (a dotfiles layout: stow,
			// chezmoi's symlink mode) stays read-only where it is: the
			// real file is mounted read-only over the link itself (a mount
			// is not followed through it), so the agent can neither write
			// through the link nor replace it; and at its own path when it
			// is visible there, so writing it from the other side (the
			// dotfiles repository as the project) fails too (review round 4).
			binds = append(binds, Bind{Source: l.real, Target: l.path, RW: false, Dir: fi.IsDir(), Why: l.why, NoFollow: true})
			if visible && writable {
				binds = append(binds, Bind{Source: l.real, Target: l.real, RW: false, Dir: fi.IsDir(), Why: l.why, NoFollow: true})
			}
			continue
		}
		if visible {
			sp.Links = append(sp.Links, Link{Path: l.path, Target: l.content})
			recreated[l.path] = l.real
			continue
		}
		if err != nil {
			continue
		}
		binds = append(binds, Bind{Source: l.real, Target: l.path, RW: l.rw, Dir: fi.IsDir(), Why: l.why})
	}
	// A home link recreated inside is made after the mounts and resolves
	// to its target, which is visible at its own path: a mount point below
	// the link (a protected file, a pinned directory in ~/.claude when
	// ~/.claude is a link into a dotfiles repository) is made at the
	// target, or it would land in a directory created in the link's place
	// (review round 4).
	inside := func(p string) string {
		for d := filepath.Dir(p); d != "/" && d != "."; d = filepath.Dir(d) {
			if r, ok := recreated[d]; ok {
				return filepath.Join(r, strings.TrimPrefix(p, d+"/"))
			}
		}
		return p
	}
	for i := range binds {
		binds[i].Target = inside(binds[i].Target)
	}
	binds = append(binds, linkedTargetBinds(binds)...)
	// What git runs with the person's rights the next time the person
	// uses git in the project, outside, stays read-only inside (git.go).
	gg := newGitGuard(project, realHome, binds, opts.DryRun)
	gg.allowLinks = opts.AllowGitLinks
	writable := gg.writable
	var globalGit []string
	for _, f := range []string{"/etc/gitconfig", filepath.Join(realHome, ".gitconfig"), filepath.Join(realHome, ".config/git/config")} {
		if fi, err := os.Stat(f); err == nil && fi.Mode().IsRegular() {
			globalGit = append(globalGit, f)
		}
	}
	if x := GetEnv(env, "XDG_CONFIG_HOME"); filepath.IsAbs(x) {
		globalGit = append(globalGit, filepath.Join(x, "git/config"))
	}
	pl.GitEntries = gg.protectProject(opts.AllowGitInit, globalGit)
	if len(gg.refusals) > 0 {
		return nil, fmt.Errorf("refusing to start: %s. Replace the link with what it points to, or start with --allow-git-links to accept it", strings.Join(gg.refusals, "; "))
	}
	pl.GitInitGuard = gg.initGuard
	binds = append(binds, gg.binds...)
	pl.GitWatch = gg.watch
	pl.Placeholders = append(pl.Placeholders, gg.created...)
	pl.Notes = append(pl.Notes, gg.notes...)
	// Scripts named by the protected settings files (hooks, status line,
	// key helpers) that live in a writable profile directory.
	gs := newGitGuard(project, realHome, binds, opts.DryRun)
	for _, b := range binds {
		if b.Why == "protect" && !b.Dir {
			for _, p := range commandPathsIn(b.Source, realHome) {
				if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
					gs.protect(p, false, false, "")
				}
			}
		}
	}
	binds = append(binds, gs.binds...)
	selfReal, err := filepath.EvalSymlinks(self)
	if err != nil {
		return nil, fmt.Errorf("cotty binary: %w", err)
	}
	if underAny(selfReal, writable) {
		note("the cotty binary %s lies in a directory the agent can write: the agent could replace it, and you would run its version afterwards; install cotty outside the project (as root, in /usr/local/bin)", selfReal)
	}
	binds = append(binds, Bind{Source: selfReal, Target: sp.SelfBin, RW: false, Dir: false, Why: "self"})
	if agentDir != "" {
		// Read-only: the agent may connect to the sockets (connect needs no
		// write access to the mount) but cannot plant a socket there that
		// another agent would take for a session.
		binds = append(binds, Bind{Source: agentDir, Target: insideAgentDir, RW: false, Dir: true, Why: "socket"})
	}
	for _, s := range prof.Sockets {
		if fi, err := os.Stat(s); err == nil && fi.Mode()&os.ModeSocket != 0 && underAny(s, sp.Hide) {
			binds = append(binds, Bind{Source: s, Target: s, RW: true, Why: "socket"})
		}
	}
	for _, r := range runKeep {
		// Only real directories and files: a link could point anywhere.
		if fi, err := os.Lstat(r); err == nil && fi.Mode()&os.ModeSymlink == 0 {
			binds = append(binds, Bind{Source: r, Target: r, RW: false, Dir: fi.IsDir(), Why: "run"})
		}
	}
	sp.Binds = sortBinds(binds)
	// A bind of a parent (--ro /var/lib) is a recursive copy taken before
	// the socket directories are covered: cover them again on top of it.
	sp.Rehide = rehideUnder(sp.Hide, sp.Binds)
	// Profile directories the agent sees empty (review C1: the IDE lock
	// files in ~/.claude/ide hold the IDE's auth token, and a lock planted
	// there would point the person's next IDE-started claude at the
	// agent's server). Created empty outside when missing, so the agent
	// cannot create them with content; a link there is refused like a
	// link at a protected path.
	for _, r := range prof.HomeHide {
		if opts.ShowHidden {
			note("~/%s is visible inside (--show-hidden)", r)
			break
		}
		h := filepath.Join(realHome, r)
		if _, ok := rwRoot(r); !ok {
			continue // not visible inside anyway
		}
		fi, err := os.Lstat(h)
		if errors.Is(err, os.ErrNotExist) {
			if opts.DryRun {
				continue
			}
			if err := os.MkdirAll(h, 0o700); err != nil {
				note("cannot create ~/%s to hide it: %v", r, err)
				continue
			}
			fi, err = os.Lstat(h)
		}
		if err != nil {
			continue
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("~/%s is not a directory (a link or a file); remove it before starting an agent, cotty keeps it hidden", r)
		}
		// Covered after the links are made, and the start fails if the
		// place is not a plain directory then (init: HideDirs).
		sp.HideDirs = append(sp.HideDirs, inside(h))
	}

	sp.Devices = append(append([]string(nil), defaultDevices...), prof.Devices...)

	// Landlock.
	ll := &sp.Landlock
	ll.RO = append(ll.RO, systemRO...)
	ll.RW = []string{project, realHome, "/tmp", "/var/tmp", "/dev/shm", "/proc", insideRuntime}
	for _, b := range sp.Binds {
		if underAny(b.Target, ll.RW) {
			continue // covered; read-only binds stay read-only through the mount flag
		}
		if b.RW {
			ll.RW = append(ll.RW, b.Target)
		} else {
			ll.RO = append(ll.RO, b.Target)
		}
	}
	ll.Dev = []string{"/dev"}
	ll.Sockets = append(append([]string(nil), systemSockets...), prof.Sockets...)
	if insideAgentDir != "" {
		ll.Sockets = append(ll.Sockets, insideAgentDir)
	}

	// Command line.
	argv := append([]string(nil), opts.Argv...)
	if len(argv) == 0 {
		if prof.Command == "" {
			return nil, fmt.Errorf("profile %s has no command: give one after --", prof.Name)
		}
		argv = []string{prof.Command}
	}
	if len(prof.Args) > 0 {
		argv = append(append([]string{argv[0]}, prof.Args...), argv[1:]...)
	}

	// Environment.
	agentEnv := ScrubEnv(env, prof.ScrubKeep, prof.ScrubDrop)
	agentEnv = dropEnv(agentEnv, "TMPDIR", "OLDPWD", "PWD")
	set := map[string]string{
		"HOME":            home,
		"XDG_RUNTIME_DIR": insideRuntime,
		"PATH":            filepath.Dir(sp.SelfBin) + ":" + orDefault(GetEnv(env, "PATH"), "/usr/local/bin:/usr/bin:/bin"),
		"COTTY_AGENT":     prof.Name,
	}
	if insideAgentDir != "" {
		set["COTTY_AGENT_DIR"] = insideAgentDir
	}
	for k, v := range prof.Env {
		set[k] = expandHome(v, home)
	}
	if !opts.NoMCP && insideAgentDir != "" {
		var injected bool
		argv, set, injected = injectMCP(prof.MCPStyle, argv, set, sp.SelfBin)
		pl.MCP = injected
	}
	sp.Env = SetEnv(agentEnv, set)
	sp.Argv = argv

	sp.Workdir = project
	if wd, err := os.Getwd(); err == nil {
		if r, err := filepath.EvalSymlinks(wd); err == nil && underAny(r, []string{project}) {
			sp.Workdir = r
		}
	}
	return pl, nil
}

// checkProject refuses projects that would expose the person's home or the
// whole system.
func checkProject(project, home string) error {
	if project == "/" {
		return errors.New("refusing / as the project")
	}
	if project == home || strings.HasPrefix(home+"/", project+"/") {
		return fmt.Errorf("refusing %s as the project: it contains your home directory; use the project's own directory", project)
	}
	return checkExtra(project, home)
}

// checkExtra refuses credential stores in the person's home.
func checkExtra(p, home string) error {
	if rel, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(rel, "..") && rel != "." {
		if err := checkRel(rel); err != nil {
			return err
		}
	}
	if p == "/" || p == home || strings.HasPrefix(home+"/", p+"/") {
		return fmt.Errorf("refusing %s: it contains your home directory", p)
	}
	return nil
}

// protectedPaths are absolute paths no agent may see, besides the
// credential stores checkRel names: cotty's own configuration (the
// secret sources, profiles) and state (the audit log, session history),
// at their default places and where $XDG_CONFIG_HOME and $XDG_STATE_HOME
// put them.
func protectedPaths(env []string, home string) []string {
	var out []string
	for _, rel := range protectedHomeRel {
		out = append(out, filepath.Join(home, rel))
	}
	for _, v := range []string{"XDG_CONFIG_HOME", "XDG_STATE_HOME"} {
		if d := GetEnv(env, v); filepath.IsAbs(d) {
			p := filepath.Join(d, "cotty")
			if r, err := filepath.EvalSymlinks(p); err == nil {
				p = r
			}
			out = append(out, p)
		}
	}
	return out
}

// checkProtected refuses a path that is a protected path, lies below
// one, or contains one.
func checkProtected(p string, prot []string) error {
	for _, q := range prot {
		if underAny(p, []string{q}) || underAny(q, []string{p}) {
			return fmt.Errorf("refusing %s: it is or contains %s, which no agent may see", p, q)
		}
	}
	return nil
}

// sortBinds orders binds so that a parent is mounted before its children
// and drops exact duplicates (the later one wins, except that a read-only
// bind is never replaced by a read-write one).
func sortBinds(bs []Bind) []Bind {
	byTarget := map[string]int{}
	var out []Bind
	for _, b := range bs {
		if i, ok := byTarget[b.Target]; ok {
			if out[i].RW || !b.RW {
				out[i] = b
			}
			continue
		}
		byTarget[b.Target] = len(out)
		out = append(out, b)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.Count(out[i].Target, "/") < strings.Count(out[j].Target, "/")
	})
	return out
}

// underAny reports whether p is one of roots or below one.
func underAny(p string, roots []string) bool {
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, strings.TrimSuffix(r, "/")+"/") {
			return true
		}
	}
	return false
}

func dropEnv(env []string, keys ...string) []string {
	out := env[:0:0]
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, d := range keys {
			if k == d {
				drop = true
			}
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}

// seedFile copies src to dst (0600, parents 0700) when dst does not exist
// and src is a regular file (not a link). Nothing happens otherwise. A
// JSON file is copied without its secrets (sanitizeSeedJSON).
func seedFile(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil || !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	fi, err := os.Lstat(src)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if strings.HasSuffix(dst, ".json") {
		if b, err = sanitizeSeedJSON(b); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// expandHome replaces a leading "~/" (or a lone "~") in a profile [env]
// value with the person's $HOME, as the agent sees it.
func expandHome(v, home string) string {
	switch {
	case v == "~":
		return home
	case strings.HasPrefix(v, "~/"):
		return filepath.Join(home, v[2:])
	}
	return v
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// injectMCP points the agent at `cotty mcp` in the way its CLI accepts
// without touching its settings files.
func injectMCP(style string, argv []string, env map[string]string, bin string) ([]string, map[string]string, bool) {
	switch style {
	case "claude":
		if hasSubcommand(argv, claudeSubcommands) {
			return argv, env, false
		}
		cfg, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"cotty": map[string]any{"command": bin, "args": []string{"mcp"}}}})
		// --mcp-config takes several values, so it goes last (before a
		// literal "--" if the command line has one) where it cannot
		// swallow the prompt.
		extra := []string{"--mcp-config", string(cfg)}
		for i, a := range argv {
			if i > 0 && a == "--" {
				out := append(append(append([]string(nil), argv[:i]...), extra...), argv[i:]...)
				return out, env, true
			}
		}
		return append(argv, extra...), env, true
	case "codex":
		q, _ := json.Marshal(bin)
		extra := []string{"-c", "mcp_servers.cotty.command=" + string(q), "-c", `mcp_servers.cotty.args=["mcp"]`}
		return append(append([]string{argv[0]}, extra...), argv[1:]...), env, true
	case "opencode":
		cfg, _ := json.Marshal(map[string]any{"mcp": map[string]any{"cotty": map[string]any{"type": "local", "command": []string{bin, "mcp"}, "enabled": true}}})
		env["OPENCODE_CONFIG_CONTENT"] = string(cfg)
		return argv, env, true
	}
	return argv, env, false
}

// claudeSubcommands are Claude Code subcommands that do not take
// --mcp-config (only a session, interactive or with -p, does).
var claudeSubcommands = map[string]bool{
	"mcp": true, "config": true, "update": true, "doctor": true, "install": true, "setup-token": true,
	"migrate-installer": true, "plugin": true, "plugins": true, "agents": true, "auth": true,
}

// hasSubcommand reports whether the first word after the program that is
// not an option is one of subs.
func hasSubcommand(argv []string, subs map[string]bool) bool {
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return subs[a]
	}
	return false
}

// socketRoots are directories that hold the person's and the system's
// sockets: refused as the project or an extra path, together with their
// parents (which contain them) and, except for /tmp and /var/tmp, anything
// below them.
func socketRoots(env []string) []string {
	roots := []string{"/tmp", "/var/tmp", "/dev/shm", "/run", "/var/run", "/dev", "/proc", "/sys"}
	if rt := GetEnv(env, "XDG_RUNTIME_DIR"); filepath.IsAbs(rt) {
		roots = append(roots, filepath.Clean(rt))
	}
	roots = append(roots, "/run/user/"+strconv.Itoa(os.Getuid()))
	var out []string
	for _, r := range roots {
		out = append(out, r)
		if real, err := filepath.EvalSymlinks(r); err == nil && real != r {
			out = append(out, real)
		}
	}
	return out
}

// tmpSocketNames are entries directly in /tmp and /var/tmp that hold
// sockets of other programs (X11, ICE, tmux, ssh-agent, screen, kitty,
// systemd private tmp, ...): refused as projects too.
var tmpSocketPrefixes = []string{".", "tmux-", "ssh-", "screen", "S-", "systemd-private-", "kitty", "wezterm", "pulse-",
	"dbus-", "gpg-", "emacs", "nvim", "vscode-", "mozilla", "zellij", "orbit-", "pyright", "cotty"}

// checkSocketRoots refuses p when it is one of roots, a parent of one, a
// path below one of them other than an ordinary directory in /tmp or
// /var/tmp, or a socket directory in /tmp or /var/tmp.
func checkSocketRoots(p string, roots []string) error {
	for _, r := range roots {
		if p == r || underAny(r, []string{p}) {
			return fmt.Errorf("refusing %s: it is or contains %s, where your sessions, desktop and services keep their sockets", p, r)
		}
		if !underAny(p, []string{r}) {
			continue
		}
		if r != "/tmp" && r != "/var/tmp" {
			return fmt.Errorf("refusing %s: it lies in %s, where your sessions, desktop and services keep their sockets", p, r)
		}
		first, _, _ := strings.Cut(strings.TrimPrefix(p, r+"/"), "/")
		for _, pre := range tmpSocketPrefixes {
			if strings.HasPrefix(first, pre) {
				return fmt.Errorf("refusing %s: %s holds sockets of other programs", p, filepath.Join(r, first))
			}
		}
	}
	return nil
}

// checkHiddenSockets refuses p when it is or lies in a directory cotty
// hides because it holds service sockets (hideSockets): a bind there would
// put the sockets back in view.
func checkHiddenSockets(p string) error {
	for _, h := range hideSockets {
		if underAny(p, []string{h}) {
			return fmt.Errorf("refusing %s: it lies in %s, which holds service sockets that cotty keeps hidden from agents", p, h)
		}
	}
	return nil
}

// rehideUnder returns, for each hidden socket directory (an entry of hide
// that is in hideSockets) that lies strictly inside the source of a bind,
// where it appears inside the confinement: those places are covered with
// an empty tmpfs again after the binds are in place.
func rehideUnder(hide []string, binds []Bind) []string {
	sockDirs := map[string]bool{}
	for _, h := range hideSockets {
		sockDirs[h] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, h := range hide {
		if !sockDirs[h] {
			continue
		}
		for _, b := range binds {
			if !b.Dir || h == b.Source || !underAny(h, []string{b.Source}) {
				continue
			}
			t := filepath.Join(b.Target, strings.TrimPrefix(h, strings.TrimSuffix(b.Source, "/")+"/"))
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// checkAgentDir accepts dir (a real path) as the agent endpoint directory
// only when it is the session package's own one, or has its shape: a
// directory named agent in a cotty runtime directory, owned by the person
// and closed to others.
func checkAgentDir(dir, def string, uid int) error {
	if def != "" {
		if r, err := filepath.EvalSymlinks(def); err == nil && r == dir {
			return nil
		}
	}
	bad := fmt.Errorf("refusing --agent-dir %s: it must be a cotty agent endpoint directory (%s)", dir, orDefault(def, "$XDG_RUNTIME_DIR/cotty/agent"))
	parent := filepath.Base(filepath.Dir(dir))
	if filepath.Base(dir) != session.AgentSubdir || (parent != "cotty" && parent != "cotty-"+strconv.Itoa(uid)) {
		return bad
	}
	for _, d := range []string{dir, filepath.Dir(dir)} {
		fi, err := os.Lstat(d)
		if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
			return bad
		}
		if st, ok := fileOwner(fi); !ok || st != uid {
			return bad
		}
	}
	return nil
}

// maxProtectScan bounds how many entries of the protected directories
// linkedTargetBinds looks at.
const maxProtectScan = 20000

// linkedTargetBinds returns read-only binds for the targets of the links
// inside protected directories (GNU stow --no-folding links each file of
// ~/.claude/skills into a dotfiles repository) when those targets are in
// a directory the agent may write: the link cannot be replaced (its
// directory is read-only inside), but what it leads to could be changed
// from the other side (review round 4).
func linkedTargetBinds(binds []Bind) []Bind {
	var writable []string
	for _, b := range binds {
		if b.RW && b.Dir && b.Source == b.Target {
			writable = append(writable, b.Source)
		}
	}
	var out []Bind
	seen := map[string]bool{}
	n := 0
	for _, b := range binds {
		if b.Why != "protect" || !b.Dir || b.RW {
			continue
		}
		_ = filepath.WalkDir(b.Source, func(p string, d os.DirEntry, err error) error {
			if n++; n > maxProtectScan {
				return filepath.SkipAll
			}
			if err != nil || d.Type()&os.ModeSymlink == 0 {
				return nil
			}
			real, err := filepath.EvalSymlinks(p)
			if err != nil || seen[real] || !underAny(real, writable) {
				return nil
			}
			fi, err := os.Stat(real)
			if err != nil {
				return nil
			}
			seen[real] = true
			out = append(out, Bind{Source: real, Target: real, RW: false, Dir: fi.IsDir(), Why: "protect", NoFollow: true})
			return nil
		})
	}
	return out
}

// placeholderContent is what a protected file created empty holds: valid
// for its format, so the person's own CLI still reads it.
func placeholderContent(rel string) string {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".json", ".jsonc":
		return "{}\n"
	}
	return ""
}

// fileOwner returns the uid that owns fi.
func fileOwner(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// sanitizeSeedJSON removes what a seeded settings file must not carry
// into the confinement: MCP server definitions (their env, headers and
// arguments often hold tokens, and their commands run programs of the
// person's), and every key whose name says it holds a credential (API
// keys, tokens, secrets, passwords). A file that is not a JSON object is
// refused.
func sanitizeSeedJSON(b []byte) ([]byte, error) {
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("not a JSON object, not copied: %w", err)
	}
	out, err := json.MarshalIndent(scrubJSON(v), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

var secretKeyRe = regexp.MustCompile(`(?i)(api_?key|token|secret|passw|credential|mcpservers|auth_?header|private_?key)`)

func scrubJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if secretKeyRe.MatchString(k) {
				delete(t, k)
				continue
			}
			t[k] = scrubJSON(x)
		}
	case []any:
		for i, x := range t {
			t[i] = scrubJSON(x)
		}
	}
	return v
}
