package broker

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// TestPTYWriteDeadline (review N8): a program that does not read its input
// cannot block a PTY write past ptyWriteTimeout, also after the window
// size was set and termios read (calls that used to put the master in
// blocking mode, where the deadline is ignored).
func TestPTYWriteDeadline(t *testing.T) {
	old := ptyWriteTimeout
	ptyWriteTimeout = 200 * time.Millisecond
	defer func() { ptyWriteTimeout = old }()
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer tty.Close() // the slave stays open and nobody reads it
	// Raw mode, like a full screen program: in canonical mode the line
	// discipline drops what does not fit in a line instead of blocking.
	tio, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if err != nil {
		t.Skip(err)
	}
	tio.Lflag &^= unix.ICANON | unix.ECHO
	if err := unix.IoctlSetTermios(int(tty.Fd()), unix.TCSETS, tio); err != nil {
		t.Skip(err)
	}
	b := testBroker(t)
	b.ptmx = ptmx
	if err := b.pollablePTY(); err != nil {
		t.Fatal(err)
	}
	defer b.ptmx.Close()
	b.setPTYSize(30, 100)
	b.pollTTY()
	if _, cols, err := pty.Getsize(tty); err != nil || cols != 100 {
		t.Fatalf("window size not set: %d %v", cols, err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = 'x'
		}
		for range 64 { // far more than the pty buffers hold
			if _, err := b.writePTY(chunk); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("4 MiB written to a pty nobody reads")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("write returned after %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PTY write blocked past its deadline")
	}
}

// TestAgentEnterHoldsTypeahead (review N15): an agent Enter at the shell
// prompt starts the typeahead hold, so the person's next keys wait for a
// password prompt the agent's command may open.
func TestAgentEnterHoldsTypeahead(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer tty.Close()
	// A stand-in shell: session leader with the pts as its terminal, so
	// it is the foreground job.
	cmd := exec.Command("sleep", "30")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	b := testBroker(t)
	b.ptmx = ptmx
	if err := b.pollablePTY(); err != nil {
		t.Fatal(err)
	}
	defer b.ptmx.Close()
	b.classifier.ShellPID = cmd.Process.Pid
	b.pollTTY()
	b.mu.Lock()
	ok := b.atPromptLocked(false)
	b.mu.Unlock()
	if !ok {
		t.Fatalf("setup: the stand-in shell is not the foreground job (fg %d, shell %d)", b.fgPgid, cmd.Process.Pid)
	}
	c := testConn(os.Getpid(), 0)
	c.b = b
	if _, perr := b.agentType(c, "echo hi", true, nil); perr != nil {
		t.Fatal(perr)
	}
	b.mu.Lock()
	at := b.enterAtPrompt
	b.mu.Unlock()
	if at.IsZero() || time.Since(at) > time.Second {
		t.Fatalf("no typeahead hold after an agent Enter (%v)", at)
	}
	// The person's next keys wait for the hold.
	start := time.Now()
	b.holdTypeahead()
	if d := time.Since(start); d < typeaheadHold/2 {
		t.Fatalf("person keys not held: %v", d)
	}
}
