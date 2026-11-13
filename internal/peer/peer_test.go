package peer

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/proto"
)

func TestParseStat(t *testing.T) {
	s := "1234 (my (odd) prog) S 1 1234 1234 34816 1234 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 100 18446744073709551615"
	st, err := parseStat(s)
	if err != nil {
		t.Fatal(err)
	}
	if st.Comm != "my (odd) prog" || st.PPID != 1 || st.PGID != 1234 || st.SID != 1234 || st.TTYNr != 34816 || st.StartTime != 98765 {
		t.Fatalf("%+v", st)
	}
	if TTYName(34816) != "pts/0" || TTYName(unix.Mkdev(137, 5)) != "pts/261" || TTYName(0) != "" {
		t.Fatalf("tty names: %s %s", TTYName(34816), TTYName(unix.Mkdev(137, 5)))
	}
}

func TestSelfDescribe(t *testing.T) {
	in := Describe(os.Getpid())
	if in.Exe == "" || in.UserNS == "" || in.PidNS == "" || in.PPID == 0 || len(in.Chain) == 0 {
		t.Fatalf("incomplete: %+v", in)
	}
}

func TestCgroup(t *testing.T) {
	if got := parseCgroup("0::/user.slice/user-1000.slice/cotty-agent-claude.scope\n"); !IsAgentCgroup(got) {
		t.Fatalf("agent cgroup not seen: %q", got)
	}
	if IsAgentCgroup("/user.slice/user-1000.slice/session-2.scope") {
		t.Fatal("ordinary cgroup taken for an agent's")
	}
}

type fakeGuard struct{ tags map[int]string }

func (g fakeGuard) Loaded() bool                { return true }
func (g fakeGuard) Tag(pid int) (string, error) { return g.tags[pid], nil }

func person() Info {
	return Info{UID: 1000, PID: 500, PPID: 400, SID: 400, TTYNr: unix.Mkdev(136, 3), Exe: "/usr/bin/cotty",
		UserNS: "user:[1]", PidNS: "pid:[2]", Cgroup: "/user.slice/session-2.scope",
		ChainPIDs: []int{400, 1}}
}

func classifier() *Classifier {
	return &Classifier{UID: 1000, SelfPID: 300, SelfUserNS: "user:[1]", SelfPidNS: "pid:[2]",
		SelfExe: "/usr/bin/cotty", ExeTrusted: true, ShellPID: 310, ShellSID: 310,
		SessionTTY: unix.Mkdev(136, 7), Guard: NoGuard{}, LandlockABI: 6,
		OtherTTYs: func() []uint64 { return []uint64{unix.Mkdev(136, 9)} }}
}

func TestClassify(t *testing.T) {
	c := classifier()
	if v := c.Classify(person()); !v.Person || v.Assurance != proto.AssuranceConfined {
		t.Fatalf("person refused: %+v", v)
	}
	cases := map[string]func(*Info){
		"uid":        func(i *Info) { i.UID = 1001 },
		"user ns":    func(i *Info) { i.UserNS = "user:[9]" },
		"pid ns":     func(i *Info) { i.PidNS = "pid:[9]" },
		"cgroup":     func(i *Info) { i.Cgroup = "/user.slice/cotty-agent-x.scope" },
		"descendant": func(i *Info) { i.ChainPIDs = []int{400, 310, 300, 1} },
		"shell sid":  func(i *Info) { i.SID = 310 },
		"no tty":     func(i *Info) { i.TTYNr = 0 },
		"own pts":    func(i *Info) { i.TTYNr = unix.Mkdev(136, 7) },
		"other pts":  func(i *Info) { i.TTYNr = unix.Mkdev(136, 9) },
		"exe":        func(i *Info) { i.Exe = "/home/u/cotty" },
		"gone":       func(i *Info) { i.Gone = true },
		"no pid":     func(i *Info) { i.PID = 0 },
		"selinux":    func(i *Info) { i.Type = "basalt_agent_t" },
	}
	c.AgentDomain = Self().AgentDomain
	for name, mut := range cases {
		in := person()
		mut(&in)
		v := c.Classify(in)
		if v.Person {
			t.Errorf("%s: classified as person", name)
		}
		if len(v.Failed) == 0 {
			t.Errorf("%s: no failed check reported", name)
		}
	}
	// Agent assurance: properties any process can give itself prove
	// nothing (review COT-2); TestLaunch covers the verified cases.
	for name, mut := range map[string]func(*Info){
		"own user ns (unshare -U)": func(i *Info) { i.UserNS = "user:[9]" },
		"own user and pid ns":      func(i *Info) { i.UserNS, i.PidNS = "user:[9]", "pid:[9]" },
		"agent cgroup it made":     func(i *Info) { i.Cgroup = "/user.slice/cotty-agent-x" },
		"pid not visible":          func(i *Info) { i.PID = 0 },
		"plain agent":              func(i *Info) { i.Exe = "/usr/bin/claude" },
	} {
		in := person()
		mut(&in)
		if v := c.Classify(in); v.Person || v.Assurance != proto.AssuranceWeak {
			t.Errorf("%s: %+v", name, v)
		}
	}
	// A guard tag (tag-self) never raises an agent on its own.
	c.Guard = fakeGuard{tags: map[int]string{500: "agent:7"}}
	for _, mut := range []func(*Info){func(*Info) {}, func(i *Info) { i.UserNS, i.PidNS = "user:[9]", "pid:[9]" }} {
		in := person()
		mut(&in)
		if v := c.Classify(in); v.Person || v.Assurance != proto.AssuranceWeak {
			t.Errorf("self-tagged agent: %+v", v)
		}
	}
	// A cotty binary the user can replace makes persons weak.
	c = classifier()
	c.ExeTrusted, c.ExeReason = false, "test"
	if v := c.Classify(person()); !v.Person || v.Assurance != proto.AssuranceWeak {
		t.Errorf("untrusted exe: %+v", v)
	}
	// Insecure mode.
	c = classifier()
	c.Insecure = true
	in := person()
	in.Exe = "/tmp/x"
	if v := c.Classify(in); !v.Person || v.Assurance != proto.AssuranceInsecure {
		t.Errorf("insecure: %+v", v)
	}
}

func TestExeTrust(t *testing.T) {
	if ok, _ := ExeTrust("/usr/bin/env", 1000); !ok {
		t.Skip("/usr/bin/env not root-owned here")
	}
	f, err := os.CreateTemp(t.TempDir(), "cotty")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if ok, why := ExeTrust(f.Name(), os.Getuid()); ok || !strings.Contains(why, "not owned by root") {
		if os.Getuid() != 0 {
			t.Errorf("user file trusted: %v %s", ok, why)
		}
	}
}
