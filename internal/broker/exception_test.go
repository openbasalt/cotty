package broker

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/peer"
)

// fakeException answers the broker's pts-exception question like
// guard.Session.PTSException, counting the questions.
type fakeException struct {
	pid   int
	start uint64
	exe   string
	err   error
	asked int
}

func (f *fakeException) ask() (int, uint64, string, error) {
	f.asked++
	return f.pid, f.start, f.exe, f.err
}

func selfStart(t *testing.T) uint64 {
	t.Helper()
	st, err := peer.ReadStat(os.Getpid())
	if err != nil {
		t.Skip(err)
	}
	return st.StartTime
}

// A process outside the foreground job that opened the session pts
// through the guard's exception list lights the lock while echo is off,
// named as an exception; the foreground job alone (the test binary, raw
// mode, echo off: an editor) would not.
func TestExceptionLightsLock(t *testing.T) {
	f := &fakeException{pid: os.Getpid(), start: selfStart(t), exe: "/usr/bin/pinentry-curses"}
	b := testBroker(t)
	b.classifier.ShellPID = 0
	b.cfg.PTSException = f.ask
	raw := ttyState{ok: true, echo: false, icanon: false, pgid: os.Getpid()}

	// Echo on: nobody reads a password, the guard is not asked.
	on := raw
	on.echo = true
	b.refreshException(on, true)
	b.mu.Lock()
	lit := b.applyTTYLocked(on)
	b.mu.Unlock()
	if lit || f.asked != 0 {
		t.Fatalf("echo on: lit %v, asked %d", lit, f.asked)
	}

	b.refreshException(raw, true)
	b.mu.Lock()
	lit = b.applyTTYLocked(raw)
	prog := b.secretProg
	b.mu.Unlock()
	if !lit || f.asked != 1 {
		t.Fatalf("exception not detected: lit %v, asked %d", lit, f.asked)
	}
	if prog == nil || !prog.Exception || prog.PID != os.Getpid() {
		t.Fatalf("lock program %+v, want the exception process", prog)
	}
	// Known and still running: no further question.
	b.refreshException(raw, true)
	if f.asked != 1 {
		t.Fatalf("asked again while the exception process runs (%d)", f.asked)
	}
	// It exits (here: its start time no longer matches): the lock ends.
	b.mu.Lock()
	b.exc.start++
	b.mu.Unlock()
	b.refreshException(raw, false)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.exc != nil {
		t.Fatal("exception process kept after it exited")
	}
	if b.applyTTYLocked(raw) {
		t.Fatal("lock still lit after the exception process exited")
	}
}

// An answer naming a process that is not the one that ran (reused pid),
// or an error, lights nothing; the questions are spaced out outside
// person input.
func TestExceptionStaleOrError(t *testing.T) {
	f := &fakeException{pid: os.Getpid(), start: selfStart(t) + 1, exe: "/usr/bin/pinentry-curses"}
	b := testBroker(t)
	b.classifier.ShellPID = 0
	b.cfg.PTSException = f.ask
	raw := ttyState{ok: true, echo: false, icanon: false, pgid: os.Getpid()}
	b.mu.Lock()
	b.fgPgid = raw.pgid
	b.mu.Unlock()
	b.refreshException(raw, true)
	b.mu.Lock()
	lit := b.applyTTYLocked(raw)
	b.mu.Unlock()
	if lit {
		t.Fatal("a stale exception answer lit the lock")
	}
	f.err, f.start = errors.New("daemon gone"), selfStart(t)
	time.Sleep(2 * excAskInput)
	n := f.asked
	b.refreshException(raw, true)
	if f.asked != n+1 {
		t.Fatal("person input did not ask the guard")
	}
	if b.exc != nil {
		t.Fatal("an error answer recorded an exception")
	}
	n = f.asked
	b.refreshException(raw, false)
	if f.asked != n {
		t.Fatal("asked again right away outside person input")
	}
}
