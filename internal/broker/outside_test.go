package broker

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/guard"
	"github.com/openbasalt/cotty/internal/peer"
)

// holderFile is a file that stands in for the session pts in these tests
// (no PTY on the host): the scanner looks at descriptors of any path.
func holderFile(t *testing.T) (string, *holderScanner) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	h := newHolderScanner(uint64(st.Dev), uint64(st.Ino))
	h.anyPath = true
	return path, h
}

// orphanHolder starts a process that holds path open and is not a
// descendant of the test (its parent shell exits at once), as a
// pinentry started by gpg-agent is not a descendant of the broker.
func orphanHolder(t *testing.T, path string) int {
	t.Helper()
	out, err := exec.Command("sh", "-c", `sleep 30 <"$1" >/dev/null 2>&1 & echo $!`, "sh", path).Output()
	if err != nil {
		t.Skip("sh:", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	// The child opens the file right after the fork.
	for i := 0; i < 100; i++ {
		if _, h := holderFileOf(pid, path); h {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return pid
}

func holderFileOf(pid int, path string) (string, bool) {
	l, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/fd/0")
	return l, err == nil && l == path
}

func notSession(int) bool { return false }

// The scan finds a process holding the file; a process of the session
// (here: a child of the broker, the test) is not a holder.
func TestHolderScan(t *testing.T) {
	path, h := holderFile(t)
	pid := orphanHolder(t, path)
	got, ok := h.scan(true, notSession)
	if !ok || got.pid != pid {
		t.Fatalf("scan found %+v %v, want pid %d", got, ok, pid)
	}
	if !procStarted(got.pid, got.start) {
		t.Fatal("holder start time does not match the process")
	}
	// The same process is in the session when the test is the broker and
	// it descends from it: a direct child of the test.
	child := exec.Command("sleep", "30")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	child.Stdin = f
	if err := child.Start(); err != nil {
		t.Skip(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	_, h2 := holderFile(t)
	h2.dev, h2.ino = h.dev, h.ino
	_ = syscall.Kill(pid, syscall.SIGKILL)
	time.Sleep(50 * time.Millisecond)
	if got, ok := h2.scan(true, inSessionOf(os.Getpid(), 0)); ok {
		t.Fatalf("a descendant of the broker was taken for an outside holder: %+v", got)
	}
}

// A process seen before and not young is skipped by the cheap pass and
// looked at again by the full pass.
func TestHolderScanCheapPass(t *testing.T) {
	path, h := holderFile(t)
	pid := orphanHolder(t, path)
	h.seen[pid] = time.Time{} // seen, and old
	h.fullAt = time.Now()
	if _, ok := h.scan(true, notSession); ok {
		t.Fatal("the cheap pass looked at a process it had seen before")
	}
	h.fullAt = time.Time{}
	// Person input never runs the full pass.
	if _, ok := h.scan(true, notSession); ok {
		t.Fatal("person input ran the full pass")
	}
	if got, ok := h.scan(false, notSession); !ok || got.pid != pid {
		t.Fatalf("full pass found %+v %v, want pid %d", got, ok, pid)
	}
}

// Without the guard, a process outside the session holding the pts while
// a job runs with echo off lights the lock for it (outside, not a system
// program, named with its parent); the lock ends when the job no longer
// has the terminal. With the guard answering, nothing is scanned.
func TestOutsideHolderLightsLock(t *testing.T) {
	path, h := holderFile(t)
	pid := orphanHolder(t, path)
	b := testBroker(t)
	b.classifier.ShellPID = 0
	b.holders = h
	raw := ttyState{ok: true, echo: false, icanon: false, pgid: os.Getpid()}
	b.mu.Lock()
	b.fgPgid = raw.pgid
	b.mu.Unlock()

	// Echo on: not looked at.
	on := raw
	on.echo = true
	b.refreshException(on, true)
	if b.exc != nil {
		t.Fatal("scanned with echo on")
	}

	// The guard answers that there is none: the broker trusts it.
	f := &fakeException{}
	b.cfg.PTSException = f.ask
	b.refreshException(raw, true)
	if f.asked != 1 || b.exc != nil {
		t.Fatalf("guard answer: asked %d, exc %+v", f.asked, b.exc)
	}

	// The guard cannot answer (no daemon, or an older one): the scan.
	f.err = &guard.RefusedError{Msg: `unknown operation "pts-exception"`}
	time.Sleep(2 * excAskInput)
	b.refreshException(raw, true)
	b.mu.Lock()
	lit := b.applyTTYLocked(raw)
	prog := b.secretProg
	logged := b.excErrLogged
	b.mu.Unlock()
	if !lit || prog == nil || prog.PID != pid {
		t.Fatalf("outside holder: lit %v, program %+v, want pid %d", lit, prog, pid)
	}
	if !prog.Outside || prog.Exception || prog.Trust != "other" || prog.Parent == "" {
		t.Fatalf("outside program %+v", prog)
	}
	if !logged {
		t.Fatal("the guard's failure was not logged")
	}

	// The job ends (another group has the terminal): the lock ends.
	next := raw
	next.pgid = raw.pgid + 1
	b.refreshException(next, false)
	if b.exc != nil {
		t.Fatal("outside holder kept after its job left the terminal")
	}
}

// Without any guard (no PTSException) the scan runs only while a job,
// not the shell at its line editor, has the terminal.
func TestOutsideHolderNotAtShellPrompt(t *testing.T) {
	path, h := holderFile(t)
	orphanHolder(t, path)
	b := testBroker(t)
	b.holders = h
	b.classifier.ShellPID = os.Getpid()
	raw := ttyState{ok: true, echo: false, icanon: false, pgid: os.Getpid()}
	b.refreshException(raw, true)
	if b.exc != nil {
		t.Fatal("scanned while the shell had the terminal")
	}
}

// The lock names the parent of an exception process (the test's parent
// here); the guard's no-connection answer is not an error to log.
func TestExceptionProgramParent(t *testing.T) {
	p := exceptionProgram(os.Getpid(), "/usr/bin/pinentry-curses", os.Getuid())
	want := describeProgram(os.Getppid(), os.Getuid()).Name
	if !p.Exception || p.Parent == "" || p.Parent != want {
		t.Fatalf("exception program %+v, want parent %q", p, want)
	}
	b := testBroker(t)
	b.noteExceptionErr(guard.ErrNotRunning)
	if b.excErrLogged {
		t.Fatal("no connection was logged as a failure")
	}
	b.noteExceptionErr(errors.New("boom"))
	if !b.excErrLogged {
		t.Fatal("a failure was not noted")
	}
}

// sessionAncestorPgids follows the parents within the shell's session.
func TestSessionAncestorPgids(t *testing.T) {
	st, err := peer.ReadStat(os.Getpid())
	if err != nil {
		t.Skip(err)
	}
	got := sessionAncestorPgids(os.Getpid(), st.SID)
	if len(got) == 0 || got[0] != st.PGID {
		t.Fatalf("pgids %v, want first %d", got, st.PGID)
	}
	if len(sessionAncestorPgids(os.Getpid(), -5)) != 0 {
		t.Fatal("pgids outside the session")
	}
}

// A process that just started is young; pid 1 is not.
func TestYoungUntil(t *testing.T) {
	now := time.Now()
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if y := youngUntil(cmd.Process.Pid, uptimeTicks(), now); !y.After(now) {
		t.Fatalf("a new process is not young: %v", y)
	}
	if y := youngUntil(1, uptimeTicks(), now); !y.IsZero() {
		t.Fatalf("pid 1 is young: %v", y)
	}
}
