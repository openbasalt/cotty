package broker

import (
	"encoding/json"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

// TestPrivateOSC133 (review B1): a command run in private mode never
// reaches last_command or exit_code, during or after private mode, and
// wait prompt does not move while it is on.
func TestPrivateOSC133(t *testing.T) {
	m := NewModel(5, 60, nil)
	defer m.Close()
	write(t, m, "\x1b]133;A\x07$ \x1b]133;B\x07ls\r\n\x1b]133;C\x07\x1b]133;D;0\x07\x1b]133;A\x07$ ")
	_, _, last, _, marks := m.ShellState()
	if last != "ls" {
		t.Fatalf("before private: %q", last)
	}
	// The command line starts before private mode and runs during it.
	write(t, m, "\x1b]133;B\x07export TOK")
	m.SetPrivate(true)
	write(t, m, "EN=hunter2-secret\r\n\x1b]133;C\x07\x1b]133;D;3\x07\x1b]133;A\x07$ \x1b]133;B\x07mysql -pSECRET\r\n\x1b]133;C\x07")
	_, _, l2, _, m2 := m.ShellState()
	if l2 != "ls" || m2 != marks {
		t.Fatalf("during private: last %q marks %d (want ls, %d)", l2, m2, marks)
	}
	if m.CursorSince() != 0 && m.CursorSince() != m.frozen.since {
		t.Fatalf("cursor_since moved during private")
	}
	m.SetPrivate(false)
	_, _, l3, code, _ := m.ShellState()
	if strings.Contains(l3, "SECRET") || strings.Contains(l3, "hunter2") || l3 != "" {
		t.Fatalf("after private: last_command %q", l3)
	}
	if code != nil {
		t.Fatalf("after private: exit code of a private command %d", *code)
	}
	// A command after private mode is recorded again.
	write(t, m, "\x1b]133;D;0\x07\x1b]133;A\x07$ \x1b]133;B\x07pwd\r\n\x1b]133;C\x07")
	if _, _, l4, _, _ := m.ShellState(); l4 != "pwd" {
		t.Fatalf("after private, new command: %q", l4)
	}
}

// TestPrivateStateFrozen (review B1): agents see the state of the moment
// private mode began.
func TestPrivateStateFrozen(t *testing.T) {
	b := testBroker(t)
	b.fg = &proto.Program{PID: 10, Name: "bash", Trust: proto.TrustSystem}
	b.model.SetPrivate(true)
	b.mu.Lock()
	b.setPrivateLocked(true)
	b.fg = &proto.Program{PID: 11, Name: "mysql", Trust: proto.TrustSystem}
	b.lastPersonInput = time.Now()
	st := b.stateLocked()
	live := b.liveStateLocked()
	b.mu.Unlock()
	if st.Foreground == nil || st.Foreground.Name != "bash" || st.PersonTyping || !st.Private {
		t.Fatalf("agent state moved during private mode: %+v", st)
	}
	if live.Foreground.Name != "mysql" {
		t.Fatalf("the person's state must stay live: %+v", live.Foreground)
	}
	b.model.SetPrivate(false)
	b.mu.Lock()
	seq := b.agentSeq
	b.setPrivateLocked(false)
	st = b.stateLocked()
	after := b.agentSeq
	b.mu.Unlock()
	if st.Foreground.Name != "mysql" || after != seq+1 {
		t.Fatalf("after private: %+v seq %d -> %d", st.Foreground, seq, after)
	}
}

// TestSecretInputOneEvent (review B2): an agent subscribed to state gets
// no event per keystroke while secret input is active.
func TestSecretInputOneEvent(t *testing.T) {
	b := testBroker(t)
	c := &conn{b: b, role: proto.RoleAgent, out: make(chan outFrame, 1024), done: make(chan struct{}),
		events: map[string]bool{proto.EventState: true, proto.EventOutput: true}}
	b.conns[c] = true
	go b.notifier()
	defer func() {
		b.mu.Lock()
		b.ended = true
		b.bumpLocked()
		b.mu.Unlock()
	}()
	b.mu.Lock()
	b.secretRaw, b.secretReported = true, true
	b.secretProg = &proto.Program{Name: "sudo", Trust: proto.TrustSystem}
	b.secretTyping = false
	b.bumpLocked()
	b.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	drain := func() int {
		n := 0
		for {
			select {
			case f := <-c.out:
				var ev proto.Event
				if json.Unmarshal(f.b, &ev) == nil {
					n++
				}
			default:
				return n
			}
		}
	}
	if n := drain(); n != 1 {
		t.Fatalf("secret start: %d events, want 1", n)
	}
	// Twenty keystrokes, each a bump, as personInput does.
	for i := 0; i < 20; i++ {
		b.mu.Lock()
		b.lastPersonInput = time.Now()
		b.secretKeys++
		b.bumpLocked()
		b.mu.Unlock()
		time.Sleep(40 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if n := drain(); n != 0 {
		t.Fatalf("%d events during secret input, want 0", n)
	}
}

// TestEmulatorReplyNeverBlocks (review S3): the model's answers to a flood
// of queries never block the model, even with nobody forwarding them.
func TestEmulatorReplyNeverBlocks(t *testing.T) {
	b := testBroker(t)
	done := make(chan struct{})
	go func() {
		_ = b.model.Write([]byte(strings.Repeat("\x1b[c\x1b[6n\x1b[5n", 200)))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("model write blocked on query replies")
	}
	b.mu.Lock()
	_ = b.liveStateLocked()
	b.mu.Unlock()
}

// TestAgentWindow (review B6): every job that takes the terminal after an
// agent Enter is the agent's until the shell is back at its line editor,
// also after a first job (`sleep 3; fake-prompt`).
func TestAgentWindow(t *testing.T) {
	b := testBroker(t)
	shell := 1000
	b.classifier.ShellPID = shell
	b.mu.Lock()
	defer b.mu.Unlock()
	b.openAgentWindowLocked()
	editor := ttyState{ok: true, echo: false, icanon: false, pgid: shell}
	cooked := ttyState{ok: true, echo: true, icanon: true, pgid: shell}
	// Polled before the shell read the Enter: still in the editor.
	b.agentWindowLocked(editor)
	if !b.agentWindow {
		t.Fatal("window closed before the line ran")
	}
	b.agentWindowLocked(ttyState{ok: true, echo: true, icanon: true, pgid: 2001})  // sleep 3
	b.agentWindowLocked(cooked)                                                    // shell between jobs
	b.agentWindowLocked(ttyState{ok: true, echo: false, icanon: true, pgid: 2005}) // the fake prompt
	if !b.agentPgids[2001] || !b.agentPgids[2005] {
		t.Fatalf("jobs not marked: %v", b.agentPgids)
	}
	b.agentWindowLocked(editor)
	if b.agentWindow {
		t.Fatal("window still open at the prompt")
	}
	b.agentWindowLocked(ttyState{ok: true, echo: true, icanon: true, pgid: 3001})
	if b.agentPgids[3001] {
		t.Fatal("a job after the prompt was marked")
	}
}

// TestDescribeJobPipeline (review B6): a pipeline is judged by all its
// members; an interpreter anywhere makes it untrusted.
func TestDescribeJobPipeline(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 | sleep 31")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	}()
	var job *proto.Program
	var members []*proto.Program
	for i := 0; i < 50; i++ {
		job, members = describeJob(cmd.Process.Pid, 0, syscall.Getuid())
		if len(members) >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(members) < 2 || len(job.Pipeline) != len(members) || !strings.Contains(job.Name, " | ") {
		t.Fatalf("pipeline not described: %+v %d members", job, len(members))
	}
	if job.Trust != proto.TrustOther {
		t.Fatalf("a job with a shell member is trusted: %+v", job)
	}
}
