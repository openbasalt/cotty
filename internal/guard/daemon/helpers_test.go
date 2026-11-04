//go:build linux && (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64)

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/openbasalt/cotty/internal/session"
)

func TestCgroupLevel(t *testing.T) {
	for p, want := range map[string]int{
		"/": 0, "": 0, "/user.slice": 1,
		"/user.slice/user-1000.slice/user@1000.service/app.slice/cotty-agent-x.scope": 5,
		"/a/b/": 2,
	} {
		if got := cgroupLevel(p); got != want {
			t.Errorf("cgroupLevel(%q) = %d, want %d", p, got, want)
		}
	}
}

// The start time is what the programs compare a protection's owner with:
// stable for a running process, absent for a gone one.
func TestStartTicks(t *testing.T) {
	a, err := startTicks(os.Getpid())
	if err != nil || a == 0 {
		t.Fatalf("start of self: %d %v", a, err)
	}
	b, _ := startTicks(os.Getpid())
	if a != b {
		t.Fatalf("start time changed: %d %d", a, b)
	}
	if !ownerAlive(guardbpfPtsOwner{Tgid: uint32(os.Getpid()), Start: a}) {
		t.Fatal("self not alive")
	}
	if ownerAlive(guardbpfPtsOwner{Tgid: uint32(os.Getpid()), Start: a + 1}) {
		t.Fatal("a different start time counted as the same process")
	}
	if ownerAlive(guardbpfPtsOwner{Tgid: 1 << 30, Start: a}) {
		t.Fatal("a missing pid counted as alive")
	}
}

// The test binary is neither root-owned nor a broker: never accepted.
func TestInstalledBrokerRefusesOthers(t *testing.T) {
	if _, err := installedBroker(os.Getpid(), uint32(os.Getuid()), nil, nil); err == nil {
		t.Fatal("the test process passed as an installed cotty broker")
	}
	if _, err := installedBroker(1<<30, 0, nil, nil); err == nil {
		t.Fatal("a missing pid passed")
	}
	// Even with its own path configured, the test binary is no broker.
	exe, _ := os.Executable()
	if _, err := installedBroker(os.Getpid(), uint32(os.Getuid()), []string{exe}, nil); err == nil {
		t.Fatal("the test process passed with its own path configured")
	}
	// A recorded executable skips only the path checks (review G3): the
	// test binary, recorded as if it had registered, still is no broker.
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/exe", &st); err != nil {
		t.Fatal(err)
	}
	if _, err := installedBroker(os.Getpid(), uint32(os.Getuid()), nil, &exeID{Dev: st.Dev, Ino: st.Ino}); err == nil {
		t.Fatal("the test process passed with its executable recorded")
	}
}

// -dev-insecure in every spelling the flag package accepts is seen; a
// value after the "--" (the shell's argv) is not a flag.
func TestInsecureArgs(t *testing.T) {
	yes := [][]string{
		{"-dev-insecure"}, {"--dev-insecure"}, {"-name", "x", "-dev-insecure=true"}, {"--dev-insecure=1"},
		{"-dev-insecure=T"},
		// A flag whose value is "--" does not end the flags (review G1).
		{"-name", "--", "-dev-insecure", "--", "bash"},
		{"-policy", "--", "--dev-insecure"},
		// Arguments the broker would not parse are refused.
		{"-no-such-flag"},
	}
	no := [][]string{
		{"-name", "x", "--", "-dev-insecure"}, {"-dev-insecure=false"}, {"--dev-insecure=0"}, {"-name", "dev-insecure"},
		{},
	}
	for _, a := range yes {
		if !insecureArgs(a) {
			t.Errorf("%q: not seen as insecure", a)
		}
	}
	for _, a := range no {
		if insecureArgs(a) {
			t.Errorf("%q: seen as insecure", a)
		}
	}
}

// N1: a session name belongs to its first live registrant; a second
// broker with the same name is refused; a gone holder frees the name.
func TestNameHolder(t *testing.T) {
	cur := guardbpfBrokerReg{Tgid: 100, Start: 5}
	if err := nameHolder(cur, false, false, 200, 7); err != nil {
		t.Errorf("free name refused: %v", err)
	}
	if err := nameHolder(cur, true, true, 200, 7); err == nil {
		t.Error("a second live broker took the name")
	}
	if err := nameHolder(cur, true, true, 100, 6); err == nil {
		t.Error("a reused pid (other start time) took the name")
	}
	if err := nameHolder(cur, true, true, 100, 5); err != nil {
		t.Errorf("the holder could not register again: %v", err)
	}
	if err := nameHolder(cur, true, false, 200, 7); err != nil {
		t.Errorf("the name of a gone broker stayed taken: %v", err)
	}
}

// N1/N25: verify-broker vouches only for the live broker that holds the
// session name, not for any registered broker of the user.
func TestVouch(t *testing.T) {
	reg := guardbpfBrokerReg{Tgid: 100, Start: 5}
	if err := vouch(reg, true, true, 100, 5); err != nil {
		t.Errorf("the session's broker refused: %v", err)
	}
	for _, c := range []struct {
		name        string
		have, alive bool
		pid         int
		start       uint64
	}{
		{"no registration", false, false, 100, 5},
		{"holder gone", true, false, 100, 5},
		{"another broker", true, true, 200, 5},
		{"reused pid", true, true, 100, 6},
	} {
		if err := vouch(reg, c.have, c.alive, c.pid, c.start); err == nil {
			t.Errorf("%s: vouched", c.name)
		}
	}
}

func TestValidSessionName(t *testing.T) {
	for _, n := range []string{"1", "work", "a.b_c-d", strings.Repeat("x", 32)} {
		if !session.ValidName(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", ".", "..", "-x", "--", "a/b", "a b", strings.Repeat("x", 33), "ä"} {
		if session.ValidName(n) {
			t.Errorf("%q accepted", n)
		}
	}
	k := nameKey(1000, "work")
	if keyName(k) != "work" || k.Uid != 1000 {
		t.Errorf("name key round trip: %+v", k)
	}
}

// The record of registered executables survives a restart of the daemon,
// and is trusted only from a root-owned file closed to others.
func TestExesRecord(t *testing.T) {
	dir := t.TempDir()
	d := &daemon{opts: Options{SocketPath: filepath.Join(dir, "guard.sock")}, exes: map[exeKey]exeID{}}
	k := exeKey{Tgid: 42, Start: 7}
	d.exes[k] = exeID{Dev: 3, Ino: 99}
	d.saveExesLocked()
	got := loadExes(d.exesPath())
	if os.Getuid() == 0 {
		if got[k] != (exeID{Dev: 3, Ino: 99}) {
			t.Fatalf("record lost: %v", got)
		}
		return
	}
	if len(got) != 0 {
		t.Fatalf("a file of uid %d was trusted: %v", os.Getuid(), got)
	}
}
