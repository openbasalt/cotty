package broker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

// startGroup starts sh -c script in a process group of its own.
func startGroup(t *testing.T, script string) *exec.Cmd {
	t.Helper()
	job := exec.Command("sh", "-c", script)
	job.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := job.Start(); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = job.Process.Kill(); _ = job.Wait() })
	return job
}

// promptCopy copies sleep to a file named like a listed prompt program.
func promptCopy(t *testing.T) string {
	t.Helper()
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	data, err := os.ReadFile(sleepBin)
	if err != nil {
		t.Skip(err)
	}
	p := filepath.Join(t.TempDir(), "pinentry-tty")
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestIdleRawGroupNoProcWalk (review round 4, T3 cost): readline keeps
// the terminal raw with echo off at every idle prompt, so the raw-mode
// re-check runs for most of a session. While the group does not change,
// it must not walk /proc on every poll.
func TestIdleRawGroupNoProcWalk(t *testing.T) {
	job := startGroup(t, "exec sleep 30")
	b := testBroker(t)
	b.classifier.ShellPID = 0
	raw := ttyState{ok: true, echo: false, icanon: false, pgid: job.Process.Pid}
	// Wait for the exec, so the member does not change during the count.
	for i := 0; ; i++ {
		exe, _ := os.Readlink("/proc/" + strconv.Itoa(job.Process.Pid) + "/exe")
		if filepath.Base(exe) == "sleep" {
			break
		}
		if i > 200 {
			t.Fatal("job never execed sleep")
		}
		time.Sleep(10 * time.Millisecond)
	}
	b.observeTTY(raw)
	b.mu.Lock()
	b.fgAt = time.Now().Add(-time.Minute) // past the young window
	b.mu.Unlock()
	before := procWalks.Load()
	const polls = 40
	for range polls {
		b.mu.Lock()
		b.fgCheckedAt = time.Time{} // every poll is due for a re-check
		b.mu.Unlock()
		if b.observeTTY(raw) {
			t.Fatal("idle group taken for a prompt")
		}
	}
	if n := procWalks.Load() - before; n > 0 {
		t.Fatalf("%d walks of /proc in %d polls of an unchanged raw group", n, polls)
	}
	// A full description still happens at the safety interval.
	b.mu.Lock()
	b.fgCheckedAt, b.fgDescribedAt = time.Time{}, time.Now().Add(-2*fullDescribeEvery)
	b.mu.Unlock()
	b.observeTTY(raw)
	if procWalks.Load() == before {
		t.Fatal("no full description after fullDescribeEvery")
	}
}

// TestShortHelperDoesNotStickLock (review round 4): a listed prompt
// program (or a setuid helper) that runs briefly late in a raw, echo-off
// group lights the lock; once it has exited, the lock goes off although
// the group and termios stay as they were.
func TestShortHelperDoesNotStickLock(t *testing.T) {
	prompt := promptCopy(t)
	job := startGroup(t, "sleep 0.3; "+prompt+" 0.4; exec sleep 30")
	b := testBroker(t)
	b.classifier.ShellPID = 0
	b.cfg.SecretPrograms = []string{"pinentry-tty"}
	raw := ttyState{ok: true, echo: false, icanon: false, pgid: job.Process.Pid}
	poll := func(want bool, within time.Duration) {
		t.Helper()
		end := time.Now().Add(within)
		for time.Now().Before(end) {
			if b.observeTTY(raw) == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		t.Fatalf("lock still %v after %v; members %v", !want, within, programNames(b.fgMembers))
	}
	poll(true, 3*time.Second)
	poll(false, 2*time.Second)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.secretRaw {
		t.Fatal("secretRaw left on")
	}
}

// TestSpentCodeNeverHandedOut (review round 4): from the moment a code
// admits a person until the next code is ready, the code and detach ops
// never return the spent code (a person detaching then could not come
// back).
func TestSpentCodeNeverHandedOut(t *testing.T) {
	b := testBroker(t)
	old := b.code
	c := testConn(os.Getpid(), 0x8881)
	_, perr := b.admit(c, proto.Hello{Role: proto.RolePerson, Auth: proto.AuthCode, Nonce: proto.NewNonce()})
	h, _, _ := prove(t, b, c, proto.AuthCode, old, perr.Challenge)
	done := make(chan *proto.Error, 1)
	go func() {
		_, perr := b.admit(c, h)
		done <- perr
	}()
	// Wait until the code is spent; the next one is still being derived.
	for i := 0; ; i++ {
		b.mu.Lock()
		spent := b.codeSpent
		b.mu.Unlock()
		if spent {
			break
		}
		select {
		case perr := <-done:
			t.Fatalf("admitted before the code was seen spent: %+v", perr)
		default:
		}
		if i > 5000 {
			t.Fatal("code never spent")
		}
		time.Sleep(100 * time.Microsecond)
	}
	person := testConn(os.Getpid(), 0x8882)
	person.role = proto.RolePerson
	for _, op := range []string{"detach", "code"} {
		res, perr := b.op(person, proto.Request{Op: op})
		if perr != nil {
			t.Fatalf("%s: %+v", op, perr)
		}
		if got := res.(map[string]string)["code"]; got == old || got == "" {
			t.Fatalf("%s handed out the spent code %q", op, got)
		}
	}
	if perr := <-done; perr != nil {
		t.Fatalf("admission: %+v", perr)
	}
}

// TestHiddenRowZeroWrapFlag (review round 4, T1 test gap): the wrap flag
// of the last committed line must not tell whether a hidden live row 0
// below it is blank.
func TestHiddenRowZeroWrapFlag(t *testing.T) {
	flags := map[string]bool{}
	// Both rows hold private mode text; on "blank" the text is then
	// overwritten with spaces, so the row is blank but still marked (the
	// columns after the text were never rewritten).
	for name, after := range map[string]string{"blank": "\x1b[2;1H       ", "text": ""} {
		m := NewModel(3, 20, nil)
		write(t, m, strings.Repeat("A", 20)) // a full line that wraps
		m.SetPrivate(true)
		write(t, m, "hunter2")
		m.SetPrivate(false)
		write(t, m, after)
		write(t, m, "\x1b[3;1H\r\n") // scroll the full line into the committed lines
		lines, wrapped, _, _, _ := m.Since(0, 0)
		v := m.AgentView(0)
		m.Close()
		if len(lines) == 0 || lines[len(lines)-1] != strings.Repeat("A", 20) {
			t.Fatalf("%s: setup: committed %q", name, lines)
		}
		if v.Rows[0] != privateText {
			t.Fatalf("%s: setup: row 0 %q not hidden", name, v.Rows[0])
		}
		flags[name] = wrapped[len(wrapped)-1]
	}
	if flags["blank"] != flags["text"] {
		t.Fatalf("wrap flag tells a blank hidden row from a non-blank one: %v", flags)
	}
}
