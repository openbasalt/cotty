package confine

// The launcher runs in three stages, like bubblewrap but in Go:
//
//	outside  `cotty agent`: computes the plan, moves itself into a new
//	         cgroup (a systemd user scope, or a delegated child cgroup),
//	         then starts the init stage in new user, mount, pid, ipc and
//	         cgroup namespaces (uid and gid mapped to themselves). With a
//	         terminal it relays the person's terminal to a pty that the
//	         init stage allocates in the agent's own devpts instance, so
//	         the agent never holds the person's terminal.
//	init     pid 1 of the new pid namespace: builds the mount view
//	         (tmpfs over $HOME, /tmp, the runtime dir; a private /dev,
//	         /proc and cgroup view; binds of the project and the
//	         profile's paths), allocates the pty, drops every capability,
//	         starts the exec stage, reaps and forwards signals.
//	exec     the agent's own process: checks it holds no capability, sets
//	         RLIMIT_CORE 0, no_new_privs, Landlock, seccomp (last), marks
//	         every fd above stdio close-on-exec and executes the agent.
//
// The spec goes from stage to stage on a pipe (fd 3), never in the
// environment or argv.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/openbasalt/cotty/internal/guard"
	"github.com/openbasalt/cotty/internal/session"
)

// Hidden subcommands of the cotty binary for the inner stages.
const (
	StageInit  = "__cotty-confine-init"
	StageExec  = "__cotty-confine-exec"
	StageProbe = "__cotty-userns-probe"
)

const scopePrefix = "cotty-agent-"

// LaunchArgs is what `cotty agent` passes to Launch: the parsed options,
// the original arguments (to re-run inside the scope) and whether this
// run is already inside the scope systemd-run created.
type LaunchArgs struct {
	Opts    Options
	RawArgs []string
	InScope string // unit name, set by the re-run under systemd-run
}

// Launch runs `cotty agent`. It returns the exit code.
func Launch(la LaunchArgs) int {
	self, err := os.Executable()
	if err != nil {
		return fail("cannot find the cotty binary: %v", err)
	}
	env := os.Environ()
	pl, err := BuildPlan(la.Opts, env, self)
	if err != nil {
		return fail("%v", err)
	}

	// Cgroup first, while still outside: systemd-run re-executes cotty
	// inside a new scope; that run continues below.
	cg := ""
	if la.InScope != "" {
		cg = currentCgroup()
		if !strings.HasSuffix(cg, "/"+la.InScope) {
			warn("expected to run in %s, but the cgroup is %s", la.InScope, cg)
		}
	} else if path, err := systemTool("systemd-run"); err == nil && os.Getenv("XDG_RUNTIME_DIR") != "" {
		unit := scopePrefix + randomHex(6) + ".scope"
		argv := []string{"systemd-run", "--user", "--scope", "--quiet", "--collect", "--unit=" + unit,
			"--description=cotty agent (" + pl.Profile.Name + ")", "--", self, "agent", "--in-scope=" + unit}
		argv = append(argv, la.RawArgs...)
		if err := probeScope(path); err == nil {
			err = syscall.Exec(path, argv, env)
			warn("systemd-run: %v", err)
		}
	}
	if cg == "" || !strings.Contains(cg, scopePrefix) {
		if c, err := delegatedCgroup(); err == nil {
			cg = c
		} else {
			warn("no cgroup of its own for the agent (%v): a later attach cannot tell the agent's processes apart by cgroup", err)
			cg = ""
		}
	}
	// Layer 3: with cotty-guard running, the agent's cgroup is registered
	// before anything of the agent runs, with the sockets it may reach
	// (by their real paths); a refusal stops the launch.
	socks := append([]string(nil), pl.Spec.Landlock.Sockets...)
	for _, b := range pl.Spec.Binds {
		if b.Why == "socket" {
			socks = append(socks, b.Source)
		}
	}
	// The cotty runtime directory (the person's session sockets) is
	// guarded: the agent can neither plant nor move a socket there, nor
	// rename it away.
	var guarded []string
	if d, err := session.DirFor(GetEnv(env, "XDG_RUNTIME_DIR")); err == nil {
		guarded = append(guarded, d)
	}
	if _, _, err := guard.ForAgent(cg, socks, guarded); err != nil {
		return fail("cotty-guard refused to register the agent: %v", err)
	}
	return runOutside(pl, la.Opts, cg)
}

// probeScope checks that the user manager answers before cotty replaces
// itself with systemd-run (an exec cannot be undone).
func probeScope(systemdRun string) error {
	sc, err := systemTool("systemctl")
	if err != nil {
		return err
	}
	out, _ := exec.Command(sc, "--user", "is-system-running").Output()
	switch strings.TrimSpace(string(out)) {
	case "running", "degraded", "starting", "initializing":
		return nil
	}
	return fmt.Errorf("user manager state %q", strings.TrimSpace(string(out)))
}

// Features are what the launcher found it could use.
type Features struct {
	LandlockABI int
	Seccomp     bool
	Cgroup      string
	PTY         bool
}

func runOutside(pl *Plan, opts Options, cg string) int {
	sp := &pl.Spec
	stdioTTY := term.IsTerminal(0) || term.IsTerminal(1) || term.IsTerminal(2)
	sp.PTY = sp.PTY || stdioTTY
	f := Features{LandlockABI: LandlockABI(), Seccomp: SeccompSupported(), Cgroup: cg, PTY: sp.PTY}
	level, gaps := Assess(f, true)
	if err := landlockGate(f.LandlockABI, opts.AllowNoLandlock); err != nil {
		return fail("%v", err)
	}
	sp.Landlock.NoLandlockOK = f.LandlockABI == 0
	sp.Env = SetEnv(sp.Env, map[string]string{"COTTY_ASSURANCE": level})
	// Without Landlock scoping (ABI < 6) abstract sockets are reachable:
	// refuse when a display, bus or input method listens on one, unless
	// the person accepted that explicitly. The exec stage checks the same
	// decision again, so Landlock's best effort never drops the scoping
	// silently.
	// A display or bus configured in the environment counts even when
	// nothing listens yet: Xwayland or a bus can start while the agent runs.
	if f.LandlockABI < 6 {
		risky := append(abstractSocketsAtRisk(), configuredDisplays(os.Environ())...)
		if len(risky) > 0 && !opts.AllowAbstractSockets {
			return fail("Landlock ABI %d (< 6) cannot keep the agent away from abstract sockets, and this session has: %s. "+
				"An agent could reach your display (keystrokes) or session bus. Use a kernel with Landlock ABI 6 (Linux 6.12), "+
				"or start with --allow-abstract-sockets to accept it", f.LandlockABI, strings.Join(risky, ", "))
		}
		sp.Landlock.NoScopesOK = true
	}
	// Gaps are printed even with --quiet: they say what is not enforced.
	for _, g := range gaps {
		fmt.Fprintf(os.Stderr, "cotty agent: gap: %s\n", g)
	}
	if pl.GitInitGuard != "" {
		release, err := holdGitInitGuard(pl.GitInitGuard)
		if err != nil {
			return fail("cannot keep the project's empty .git in place: %v", err)
		}
		defer release()
	}
	specR, specW, err := os.Pipe()
	if err != nil {
		return fail("%v", err)
	}
	cmd := exec.Command("/proc/self/exe", StageInit)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWCGROUP,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: sp.UID, HostID: sp.UID, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: sp.GID, HostID: sp.GID, Size: 1}},
		GidMappingsEnableSetgroups: false,
		// The init stage runs as the person's uid inside the namespace,
		// so execve would clear its capabilities: keep the two it needs.
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP},
		Pdeathsig:   syscall.SIGKILL,
	}
	cmd.ExtraFiles = []*os.File{specR}

	var parentSock *os.File
	var stderrR *os.File
	if sp.PTY {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return fail("socketpair: %v", err)
		}
		parentSock = os.NewFile(uintptr(fds[0]), "cotty-pty-parent")
		childSock := os.NewFile(uintptr(fds[1]), "cotty-pty-child")
		defer childSock.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, childSock)
		// The person's terminal never enters the namespaces: the init
		// stage gets /dev/null and a pipe for its own error messages.
		devnull, err := os.Open(os.DevNull)
		if err != nil {
			return fail("%v", err)
		}
		defer devnull.Close()
		cmd.Stdin, cmd.Stdout = devnull, devnull
		var stderrW *os.File
		if stderrR, stderrW, err = os.Pipe(); err != nil {
			return fail("%v", err)
		}
		cmd.Stderr = stderrW
		defer stderrW.Close()
	} else {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	}

	if err := cmd.Start(); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EINVAL) {
			return fail("cannot create the agent's namespaces (%v); run `cotty doctor` to see why", err)
		}
		return fail("start: %v", err)
	}
	specR.Close()
	// Announced once the namespaces exist, so a failed start never claims
	// an assurance level.
	if !opts.Quiet {
		fmt.Fprintf(os.Stderr, "cotty agent: profile %s, project %s, assurance %s (landlock ABI %d", pl.Profile.Name, sp.Project, level, f.LandlockABI)
		if cg != "" {
			fmt.Fprintf(os.Stderr, ", cgroup %s", filepath.Base(cg))
		}
		if pl.MCP {
			fmt.Fprintf(os.Stderr, ", mcp")
		}
		fmt.Fprintln(os.Stderr, ")")
		for _, n := range pl.Notes {
			fmt.Fprintf(os.Stderr, "cotty agent: note: %s\n", n)
		}
	}
	// A commondir file created in a git directory that had none would
	// point the person's git at a config the agent wrote: stop the agent.
	tripped := make(chan string, 1)
	stopWatch, err := watchGitDirs(pl.GitWatch, func(p string) {
		select {
		case tripped <- p:
		default:
		}
		_ = cmd.Process.Kill()
	})
	if err != nil {
		_ = cmd.Process.Kill()
		return fail("cannot watch the project's git directories: %v", err)
	}
	defer stopWatch()
	if err := json.NewEncoder(specW).Encode(sp); err != nil {
		_ = cmd.Process.Kill()
		return fail("spec: %v", err)
	}
	specW.Close()

	// Forward termination requests to the init stage, which passes them
	// to the agent's process group.
	sigs := make(chan os.Signal, 4)
	fwd := []os.Signal{syscall.SIGTERM, syscall.SIGHUP}
	if sp.PTY {
		fwd = append(fwd, syscall.SIGINT, syscall.SIGQUIT)
	}
	signal.Notify(sigs, fwd...)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()

	if sp.PTY {
		if c, ok := cmd.Stderr.(*os.File); ok {
			c.Close() // our copy of the write end
		}
		errDone := make(chan struct{})
		go func() { _, _ = io.Copy(os.Stderr, stderrR); close(errDone) }()
		master, err := recvFd(parentSock)
		if err != nil {
			_ = cmd.Wait()
			<-errDone
			return exitCode(cmd.ProcessState)
		}
		restore := relay(master, parentSock)
		_ = cmd.Wait()
		restore()
		<-errDone
	} else {
		_ = cmd.Wait()
	}
	if cg != "" && !strings.HasSuffix(cg, ".scope") {
		_ = os.Remove(filepath.Join("/sys/fs/cgroup", cg))
	}
	select {
	case p := <-tripped:
		return fail("the agent created %s, which would point git at a config of its choosing; cotty removed it and stopped the agent", p)
	default:
	}
	if fresh := NewGitEntries(sp.Project, pl.GitEntries); len(fresh) > 0 {
		warn("the agent created git repositories: %s. Their hooks and config run with your rights when you use git there "+
			"(and `git status` in the project enters submodules); review them before using git in them", strings.Join(fresh, ", "))
	}
	return exitCode(cmd.ProcessState)
}

// relay connects the person's terminal to the agent's pty master and
// returns a function that restores the terminal. It acknowledges the
// master on sock once the window size is set, so the agent starts with
// the right size.
func relay(master *os.File, sock *os.File) func() {
	restore := func() {}
	inFd := int(os.Stdin.Fd())
	if term.IsTerminal(inFd) {
		if st, err := term.MakeRaw(inFd); err == nil {
			restore = func() { _ = term.Restore(inFd, st) }
		}
	}
	resize := func() {
		for _, fd := range []int{0, 1, 2} {
			if ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ); err == nil {
				_ = unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, ws)
				return
			}
		}
	}
	resize()
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			resize()
		}
	}()
	_, _ = sock.Write([]byte{1})
	sock.Close()

	go func() {
		_, _ = io.Copy(master, os.Stdin)
		// No more input: an end-of-file for a reader in canonical mode.
		if !term.IsTerminal(inFd) {
			_, _ = master.Write([]byte{4})
		}
	}()
	// The copy ends with EIO when the last slave closes. Escape sequences
	// that act on the person's terminal emulator (clipboard, remote
	// control, file transfer) are dropped on the way (termfilter.go).
	_ = copyFiltered(os.Stdout, master)
	return restore
}

func recvFd(sock *os.File) (*os.File, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return nil, errors.New("no pty from the init stage")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return nil, errors.New("bad pty message")
	}
	return os.NewFile(uintptr(fds[0]), "cotty-pty-master"), nil
}

func exitCode(ps *os.ProcessState) int {
	if ps == nil {
		return 1
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

// currentCgroup returns this process's cgroup v2 path.
func currentCgroup() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			return p
		}
	}
	return ""
}

// delegatedCgroup moves the launcher into a new child of its own cgroup,
// when that cgroup is the person's (delegated) and has no controllers
// enabled for children. It returns the new cgroup path.
func delegatedCgroup() (string, error) {
	cur := currentCgroup()
	if cur == "" {
		return "", errors.New("no cgroup v2")
	}
	dir := filepath.Join("/sys/fs/cgroup", cur)
	if sc, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control")); err == nil && strings.TrimSpace(string(sc)) != "" {
		return "", errors.New("the current cgroup has controllers enabled for children")
	}
	name := scopePrefix + randomHex(6)
	nd := filepath.Join(dir, name)
	if err := os.Mkdir(nd, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(nd, "cgroup.procs"), []byte("0"), 0); err != nil {
		_ = os.Remove(nd)
		return "", err
	}
	return filepath.Join(cur, name), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func fail(f string, a ...any) int {
	fmt.Fprintf(os.Stderr, "cotty agent: "+f+"\n", a...)
	return 125
}

func warn(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "cotty agent: warning: "+f+"\n", a...)
}
