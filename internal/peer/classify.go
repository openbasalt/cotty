package peer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/openbasalt/cotty/internal/proto"
)

// Guard is the layer 3 interface (cotty-guard, WP-F). Until the guard
// exists the broker uses NoGuard.
type Guard interface {
	// Loaded reports whether the guard's BPF LSM programs are active.
	Loaded() bool
	// Tag returns the guard's tag for a pid ("agent:<id>"), "" if none.
	Tag(pid int) (string, error)
}

// NoGuard is the stub used while layer 3 is absent.
type NoGuard struct{}

// Loaded is always false.
func (NoGuard) Loaded() bool { return false }

// Tag is always "".
func (NoGuard) Tag(int) (string, error) { return "", nil }

// AgentCgroupPrefix marks an agent cgroup: `cotty agent` (WP-C) puts the
// agent in a scope or cgroup whose name starts with this prefix, and any
// process in it or below is an agent.
const AgentCgroupPrefix = "cotty-agent"

// DefaultAgentDomains are SELinux types of agent processes (Basalt).
var DefaultAgentDomains = []string{"basalt_agent_t", "container_t"}

// Classifier holds what the broker knows about itself and its session.
type Classifier struct {
	UID        int
	SelfPID    int
	SelfUserNS string
	SelfPidNS  string
	// SelfExe is the broker's executable; a person peer runs the same one.
	SelfExe string
	// ExeTrusted is true when SelfExe is root-owned and not writable by
	// the user (ExeTrust). Otherwise persons are only weakly assured.
	ExeTrusted  bool
	ExeReason   string
	ShellPID    int
	ShellSID    int
	SessionTTY  uint64
	OtherTTYs   func() []uint64 // pts of other live cotty sessions
	Guard       Guard
	Insecure    bool
	AgentDomain func(typ string) bool
	// SeccompFilter: `cotty agent` installs its seccomp filter on this
	// system (confine.SeccompSupported), so a confined agent shows one.
	SeccompFilter bool
	// LandlockABI is the kernel's Landlock ABI (confine.LandlockABI). At
	// 0, cotty agent runs the agent without Landlock (only on
	// --allow-no-landlock), which is not confined (review COT-4).
	LandlockABI int
}

// Verdict is the result of classifying one peer.
type Verdict struct {
	Person          bool     `json:"person"`
	Failed          []string `json:"failed,omitempty"`
	Assurance       string   `json:"assurance"`
	AssuranceReason string   `json:"assurance_reason,omitempty"`
}

// Self returns a classifier for the calling process (the broker). The
// session fields are filled by the broker once the shell runs.
func Self() *Classifier {
	c := &Classifier{UID: os.Getuid(), SelfPID: os.Getpid(), Guard: NoGuard{}}
	c.SelfUserNS, _ = os.Readlink("/proc/self/ns/user")
	c.SelfPidNS, _ = os.Readlink("/proc/self/ns/pid")
	if exe, err := os.Readlink("/proc/self/exe"); err == nil {
		c.SelfExe = strings.TrimSuffix(exe, " (deleted)")
	}
	c.ExeTrusted, c.ExeReason = ExeTrust(c.SelfExe, c.UID)
	c.AgentDomain = func(typ string) bool {
		for _, d := range DefaultAgentDomains {
			if typ == d {
				return true
			}
		}
		return strings.HasPrefix(typ, "basalt_agent")
	}
	return c
}

// ExeTrust reports whether a binary is root-owned and not writable by
// the given uid (through its mode bits, its group or its directories).
func ExeTrust(path string, uid int) (bool, string) {
	if path == "" {
		return false, "executable unknown"
	}
	for p := path; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return false, err.Error()
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return false, "no stat"
		}
		if st.Uid != 0 {
			return false, fmt.Sprintf("%s is not owned by root", p)
		}
		if fi.Mode().Perm()&0o022 != 0 && !(fi.IsDir() && fi.Mode()&os.ModeSticky != 0) {
			return false, fmt.Sprintf("%s is writable by group or others", p)
		}
		if p == "/" {
			break
		}
	}
	_ = uid
	return true, ""
}

// Classify decides the role a peer may take. The default is agent: every
// check must pass for a person.
func (c *Classifier) Classify(in Info) Verdict {
	v := Verdict{}
	if c.Insecure {
		if in.UID == c.UID {
			v.Person = true
		} else {
			v.Failed = append(v.Failed, "uid differs")
		}
		v.Assurance, v.AssuranceReason = proto.AssuranceInsecure, "broker started with --dev-insecure (development only)"
		return v
	}
	fail := func(f string, a ...any) { v.Failed = append(v.Failed, fmt.Sprintf(f, a...)) }
	if in.UID != c.UID {
		fail("uid %d is not the session owner's", in.UID)
	}
	if in.PID <= 0 {
		fail("pid not visible (other pid namespace)")
	}
	if in.Gone {
		fail("process exited during classification")
	}
	if in.UserNS == "" || in.UserNS != c.SelfUserNS {
		fail("user namespace %q differs from the broker's", in.UserNS)
	}
	if in.PidNS == "" || in.PidNS != c.SelfPidNS {
		fail("pid namespace %q differs from the broker's", in.PidNS)
	}
	if IsAgentCgroup(in.Cgroup) {
		fail("in agent cgroup %s", in.Cgroup)
	}
	tag := ""
	if c.Guard != nil {
		if t, err := c.Guard.Tag(in.PID); err != nil {
			fail("guard lookup failed: %v", err)
		} else if t != "" {
			tag = t
			fail("tagged by the guard as %s", t)
		}
	}
	if c.ShellPID > 0 {
		for _, p := range in.ChainPIDs {
			if p == c.ShellPID {
				fail("descendant of the session shell")
				break
			}
		}
		if in.PID == c.ShellPID {
			fail("is the session shell")
		}
	}
	if c.ShellSID > 0 && in.SID == c.ShellSID {
		fail("in the session shell's kernel session")
	}
	switch {
	case in.TTYNr == 0:
		fail("no controlling terminal")
	case c.SessionTTY != 0 && in.TTYNr == c.SessionTTY:
		fail("controlling terminal is this session's pts")
	case c.isOtherSessionTTY(in.TTYNr):
		fail("controlling terminal is another cotty session's pts")
	case c.sessionLeaderIsCotty(in.SID):
		fail("its kernel session runs inside a cotty session")
	}
	if in.Exe == "" || in.Exe != c.SelfExe {
		fail("executable %q is not the cotty binary %q", in.Exe, c.SelfExe)
	}
	if in.Type != "" && c.AgentDomain != nil && c.AgentDomain(in.Type) {
		fail("SELinux domain %s is an agent domain", in.Type)
	}
	v.Person = len(v.Failed) == 0
	if v.Person {
		switch {
		case !c.ExeTrusted:
			v.Assurance, v.AssuranceReason = proto.AssuranceWeak, "the cotty binary can be replaced by the user: "+c.ExeReason
		case c.Guard != nil && c.Guard.Loaded():
			v.Assurance = proto.AssuranceStrong
		default:
			v.Assurance = proto.AssuranceConfined
		}
		return v
	}
	v.Assurance, v.AssuranceReason = c.agentAssurance(in, tag)
	return v
}

// agentAssurance tells how well an agent peer is kept away from what cotty
// hides. Only a confinement the trusted cotty binary built counts
// (verifyLaunch); a guard tag adds layer 3 on top of it but never raises
// an agent on its own, since any process may ask the guard to tag itself
// (review COT-2). Anything that cannot be verified is weak.
func (c *Classifier) agentAssurance(in Info, tag string) (string, string) {
	why := c.verifyLaunch(in)
	loaded := c.Guard != nil && c.Guard.Loaded()
	switch {
	case why == "" && tag != "" && loaded:
		return proto.AssuranceStrong, ""
	case why == "" && loaded:
		return proto.AssuranceConfined, "agent started by cotty agent but not tagged by the guard (started before the guard ran)"
	case why == "":
		return proto.AssuranceConfined, "agent started by cotty agent (layer 2), no guard"
	case tag != "":
		return proto.AssuranceWeak, "tagged by the guard but not confined by cotty agent (" + why + "): the person's files stay reachable"
	}
	return proto.AssuranceWeak, "agent not confined by cotty agent: " + why
}

func (c *Classifier) isOtherSessionTTY(nr uint64) bool {
	if c.OtherTTYs == nil {
		return false
	}
	for _, t := range c.OtherTTYs() {
		if t == nr {
			return true
		}
	}
	return false
}

// sessionLeaderIsCotty reports whether the leader of a kernel session is
// a shell started by a cotty broker: the controlling terminal of every
// process in such a session is a cotty pts, whatever the registry files
// say.
func (c *Classifier) sessionLeaderIsCotty(sid int) bool {
	if sid <= 0 || c.SelfExe == "" {
		return false
	}
	st, err := ReadStat(sid)
	if err != nil {
		return false
	}
	// Brokers are non-dumpable, so their exe link is unreadable; comm and
	// cmdline stay readable. Both can be faked only in the restrictive
	// direction (a process that names itself a broker makes its own
	// session's processes agents).
	pst, err := ReadStat(st.PPID)
	if err != nil || pst.Comm != filepath.Base(c.SelfExe) {
		return false
	}
	cmd, _ := os.ReadFile(filepath.Join(procRoot, fmt.Sprint(st.PPID), "cmdline"))
	return strings.Contains(string(cmd), "\x00__broker")
}

// IsAgentCgroup reports whether a cgroup path is in an agent cgroup.
func IsAgentCgroup(path string) bool {
	for _, el := range strings.Split(path, "/") {
		if strings.HasPrefix(el, AgentCgroupPrefix) {
			return true
		}
	}
	return false
}

// Rank orders assurance levels from weakest to strongest.
func Rank(a string) int {
	switch a {
	case proto.AssuranceStrong:
		return 3
	case proto.AssuranceConfined:
		return 2
	case proto.AssuranceWeak:
		return 1
	}
	return 0
}
