package peer

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/openbasalt/cotty/internal/proto"
)

// fakeTask is one process of a fake /proc tree.
type fakeTask struct {
	pid, ppid int
	start     uint64
	exe       string
	argv      []string
	user, pns string
	mnt       string
	nspid     string // NSpid field
	nnp, secc int
}

func writeProc(t *testing.T, root string, tasks []fakeTask) {
	t.Helper()
	for _, k := range tasks {
		d := filepath.Join(root, strconv.Itoa(k.pid))
		if err := os.MkdirAll(filepath.Join(d, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		stat := strconv.Itoa(k.pid) + " (x) S " + strconv.Itoa(k.ppid) + " 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 " +
			strconv.FormatUint(k.start, 10) + " 0 0"
		status := "Name:\tx\nNSpid:\t" + k.nspid + "\nNoNewPrivs:\t" + strconv.Itoa(k.nnp) + "\nSeccomp:\t" + strconv.Itoa(k.secc) + "\n"
		for name, body := range map[string]string{"stat": stat, "status": status, "cmdline": strings.Join(k.argv, "\x00") + "\x00"} {
			if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for name, target := range map[string]string{"exe": k.exe, "ns/user": k.user, "ns/pid": k.pns, "ns/mnt": k.mnt} {
			if target != "" {
				if err := os.Symlink(target, filepath.Join(d, name)); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

// launchTree is a cotty agent run as the broker sees it: the launcher
// (outside), pid 1 of the agent's namespace (the init stage), the agent
// CLI and its MCP server, the peer.
func launchTree() []fakeTask {
	return []fakeTask{
		{pid: 700, ppid: 600, start: 100, exe: "/usr/bin/cotty", argv: []string{"/usr/bin/cotty", "agent", "--", "claude"},
			user: "user:[1]", pns: "pid:[2]", mnt: "mnt:[3]", nspid: "700", nnp: 0, secc: 0},
		{pid: 701, ppid: 700, start: 110, exe: "/usr/bin/cotty", argv: []string{"/proc/self/exe", InitStage},
			user: "user:[9]", pns: "pid:[9]", mnt: "mnt:[9]", nspid: "701\t1", nnp: 0, secc: 0},
		{pid: 702, ppid: 701, start: 120, exe: "/usr/bin/claude", argv: []string{"claude"},
			user: "user:[9]", pns: "pid:[9]", mnt: "mnt:[9]", nspid: "702\t2", nnp: 1, secc: 2},
		{pid: 703, ppid: 702, start: 130, exe: "/usr/bin/cotty", argv: []string{"cotty", "mcp"},
			user: "user:[9]", pns: "pid:[9]", mnt: "mnt:[9]", nspid: "703\t3", nnp: 1, secc: 2},
	}
}

func peerOf(k fakeTask) Info {
	return Info{UID: 1000, PID: k.pid, PPID: k.ppid, StartTime: k.start, UserNS: k.user, PidNS: k.pns,
		Cgroup: "/user.slice/cotty-agent-1.scope", ChainPIDs: []int{702, 701, 700, 600, 1}}
}

func useProc(t *testing.T, tasks []fakeTask) {
	t.Helper()
	root := t.TempDir()
	writeProc(t, root, tasks)
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

func TestLaunchVerified(t *testing.T) {
	tasks := launchTree()
	useProc(t, tasks)
	c := classifier()
	c.SeccompFilter = true
	in := peerOf(tasks[3])
	if why := c.verifyLaunch(in); why != "" {
		t.Fatalf("cotty agent run refused: %s", why)
	}
	if v := c.Classify(in); v.Person || v.Assurance != proto.AssuranceConfined {
		t.Errorf("no guard: %+v", v)
	}
	c.Guard = fakeGuard{tags: map[int]string{703: "agent:7"}}
	if v := c.Classify(in); v.Assurance != proto.AssuranceStrong {
		t.Errorf("guard and tag: %+v", v)
	}
	c.Guard = fakeGuard{}
	if v := c.Classify(in); v.Assurance != proto.AssuranceConfined {
		t.Errorf("guard without tag: %+v", v)
	}
}

func TestLaunchForgeries(t *testing.T) {
	cases := map[string]func(ts []fakeTask, in *Info, c *Classifier){
		// unshare -Upf: pid 1 of the namespace is not cotty's init stage.
		"unshare init": func(ts []fakeTask, _ *Info, _ *Classifier) {
			ts[1].exe, ts[1].argv = "/usr/bin/unshare", []string{"unshare", "-Upf", "cotty", "mcp"}
		},
		// The real binary run as init by another program, under a name.
		"init stage argv": func(ts []fakeTask, _ *Info, _ *Classifier) { ts[1].argv = []string{"cotty", "mcp"} },
		// A copy of cotty the user can write.
		"init exe copy": func(ts []fakeTask, _ *Info, _ *Classifier) { ts[1].exe = "/home/u/bin/cotty" },
		// nsenter into a real agent's namespaces from outside: the parent
		// is outside the namespace.
		"entered namespace": func(ts []fakeTask, in *Info, _ *Classifier) { in.ChainPIDs = []int{650, 600, 1} },
		// Entered and then orphaned (reparented to pid 1), but outside
		// the agent's mount view.
		"other mount view": func(ts []fakeTask, _ *Info, _ *Classifier) { ts[3].mnt = "mnt:[3]" },
		"no no_new_privs":  func(ts []fakeTask, _ *Info, _ *Classifier) { ts[3].nnp = 0 },
		"no seccomp":       func(ts []fakeTask, _ *Info, _ *Classifier) { ts[3].secc = 0 },
		"oldest not pid 1": func(ts []fakeTask, _ *Info, _ *Classifier) { ts[1].nspid = "701\t4" },
		"init user ns":     func(ts []fakeTask, _ *Info, _ *Classifier) { ts[1].user = "user:[8]" },
		"pid reused":       func(ts []fakeTask, in *Info, _ *Classifier) { in.StartTime = 999 },
		"init newer":       func(ts []fakeTask, _ *Info, _ *Classifier) { ts[1].start = 200 },
		"same namespaces": func(ts []fakeTask, in *Info, _ *Classifier) {
			in.UserNS, in.PidNS = "user:[1]", "pid:[2]"
		},
		"untrusted binary": func(ts []fakeTask, _ *Info, c *Classifier) { c.ExeTrusted, c.ExeReason = false, "test" },
		"init unreadable":  func(ts []fakeTask, _ *Info, _ *Classifier) { ts[1].exe = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			ts := launchTree()
			c := classifier()
			c.SeccompFilter = true
			in := peerOf(ts[3])
			mut(ts, &in, c)
			useProc(t, ts)
			if why := c.verifyLaunch(in); why == "" {
				t.Fatal("verified")
			}
			c.Guard = fakeGuard{tags: map[int]string{703: "agent:7"}}
			if v := c.Classify(in); v.Person || v.Assurance != proto.AssuranceWeak {
				t.Errorf("not weak: %+v", v)
			}
		})
	}
}
