package peer

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// InitStage is the hidden subcommand of the cotty binary that runs as pid
// 1 of a confined agent's pid namespace (confine.StageInit; a test keeps
// the two equal).
const InitStage = "__cotty-confine-init"

// verifyLaunch reports whether an agent peer runs inside a confinement
// that the cotty binary itself built (`cotty agent`), from what the
// kernel shows about it. It returns "" when it does, else why not.
//
// Review COT-2: being in a user namespace of its own, in a cgroup named
// cotty-agent*, or tagged by the guard proves nothing, since any process
// can give itself each of those (`unshare -U`, a cgroup it creates in its
// delegated subtree, the guard's tag-self). What a process cannot give
// itself is a pid namespace whose pid 1 is the cotty binary the broker
// trusts (root-owned, not replaceable by the user) running the init
// stage: that binary builds the agent's mount view, drops every
// capability and starts the agent with no_new_privs, seccomp and
// Landlock. The peer must be in that namespace and in its mount view,
// with no_new_privs and a seccomp filter in place.
//
// Not covered, and documented (docs/security.md, Assurance levels): this
// describes the process that connected, the agent's MCP server, not what
// talks to it over its stdio. A program that already runs with all of the
// person's rights can start a confined MCP server for itself (`cotty agent
// -- cotty mcp`), or feed the init stage a plan of its own, and is then
// reported confined.
func (c *Classifier) verifyLaunch(in Info) string {
	if !c.ExeTrusted {
		return "the cotty binary can be replaced by the user (" + c.ExeReason + "), so a confinement it reports proves nothing"
	}
	if c.LandlockABI <= 0 {
		return "the kernel has no Landlock, so cotty agent cannot restrict the agent's files"
	}
	if in.PID <= 0 {
		return "its pid is not visible from the session, so its confinement cannot be checked"
	}
	if in.UserNS == "" || in.PidNS == "" || in.UserNS == c.SelfUserNS || in.PidNS == c.SelfPidNS {
		return "not in a user and pid namespace of its own"
	}
	self, err := readTask(in.PID)
	if err != nil {
		return "cannot read its process: " + err.Error()
	}
	if self.stat.StartTime != in.StartTime {
		return "the process exited during classification"
	}
	if self.noNewPrivs != 1 {
		return "no_new_privs is not set"
	}
	if c.SeccompFilter && self.seccomp != 2 {
		return "no seccomp filter"
	}
	// pid 1 of the peer's pid namespace: the last ancestor in it.
	initPID := 0
	for _, p := range in.ChainPIDs {
		ns, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(p), "ns", "pid"))
		if err != nil {
			return fmt.Sprintf("cannot read the pid namespace of its ancestor %d: %v", p, err)
		}
		if ns != in.PidNS {
			break
		}
		initPID = p
	}
	if initPID == 0 {
		return "its parent is outside its pid namespace (the namespace was entered from outside)"
	}
	init, err := readTask(initPID)
	if err != nil {
		return fmt.Sprintf("cannot read pid 1 of its namespace (%d): %v", initPID, err)
	}
	switch {
	case init.nsPID != 1:
		return fmt.Sprintf("its oldest ancestor in its pid namespace (%d) is not that namespace's pid 1", initPID)
	case init.exe == "" || init.exe != c.SelfExe:
		return fmt.Sprintf("pid 1 of its namespace runs %q, not the cotty binary %q", init.exe, c.SelfExe)
	case len(init.argv) < 2 || init.argv[1] != InitStage:
		return "pid 1 of its namespace is not cotty agent's init stage"
	case init.userNS != in.UserNS:
		return "pid 1 of its namespace is in another user namespace"
	case init.mntNS == "" || init.mntNS != self.mntNS:
		return "not in the mount view cotty agent built"
	case init.stat.StartTime > in.StartTime:
		return "pid 1 of its namespace started after it (pid reused)"
	}
	// The ancestor read above is still the one in the chain (no pid
	// reuse between the reads).
	if st, err := ReadStat(initPID); err != nil || st.StartTime != init.stat.StartTime {
		return "pid 1 of its namespace exited during classification"
	}
	return ""
}

// task is what verifyLaunch reads about one process.
type task struct {
	stat       Stat
	exe        string
	argv       []string
	userNS     string
	mntNS      string
	nsPID      int // pid in the innermost pid namespace (NSpid's last field)
	noNewPrivs int
	seccomp    int
}

func readTask(pid int) (task, error) {
	var t task
	p := filepath.Join(procRoot, strconv.Itoa(pid))
	st, err := ReadStat(pid)
	if err != nil {
		return t, err
	}
	t.stat = st
	if exe, err := os.Readlink(filepath.Join(p, "exe")); err == nil {
		t.exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if b, err := os.ReadFile(filepath.Join(p, "cmdline")); err == nil {
		t.argv = strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	}
	t.userNS, _ = os.Readlink(filepath.Join(p, "ns", "user"))
	t.mntNS, _ = os.Readlink(filepath.Join(p, "ns", "mnt"))
	b, err := os.ReadFile(filepath.Join(p, "status"))
	if err != nil {
		return t, err
	}
	t.nsPID, t.noNewPrivs, t.seccomp = -1, -1, -1
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		switch k {
		case "NSpid":
			t.nsPID, _ = strconv.Atoi(f[len(f)-1])
		case "NoNewPrivs":
			t.noNewPrivs, _ = strconv.Atoi(f[0])
		case "Seccomp":
			t.seccomp, _ = strconv.Atoi(f[0])
		}
	}
	return t, nil
}
