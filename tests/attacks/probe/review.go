package main

// Attacks added after the final review (docs/security.md, "Rows added
// after the review"): state events during a secret prompt, a fake
// session socket, the session pts taken without open(), and the cgroup,
// signal and rlimit paths around the guard's task_kill rule. Same exit
// codes as every attack: 0 escaped, 1 denied, 2 does not apply.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/proto"
)

func reviewCommand(name string, args []string) bool {
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch name {
	case "agent-events":
		agentEvents(arg(0), atoi(arg(1)))
	case "fake-broker":
		fakeBroker(arg(0), arg(1), atoi(arg(2)))
	case "pidfd-getfd":
		pidfdGetfd(atoi(arg(0)), arg(1))
	case "clone-into-cgroup":
		cloneIntoCgroup(arg(0))
	case "prlimit":
		prlimitOther(atoi(arg(0)))
	case "sigio":
		sigioKill(atoi(arg(0)))
	default:
		return false
	}
	return true
}

// agentEvents: agent-events SOCK SECS subscribes to state events as an
// agent for SECS seconds and counts the events that arrive while a
// secret prompt is active. PLAN 5.2 allows the agent to learn only that
// secret input started and ended: one event for the start (and one for
// the end, which reads none). More than two events while active means
// the agent sees the person's keystrokes (count and timing). Exit 0
// (escaped) then, 1 when at most two arrived, 2 when no secret prompt
// was seen at all.
func agentEvents(sock string, secs int) {
	cl, err := proto.Dial(sock)
	if err != nil {
		skip("connect: %v", err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs+5)*time.Second)
	defer cancel()
	if _, err := cl.Hello(ctx, proto.Hello{Role: proto.RoleAgent, Client: "probe"}); err != nil {
		skip("hello agent: %v", err)
	}
	if err := cl.Call(ctx, "subscribe", map[string]any{"events": []string{"state"}}, nil); err != nil {
		skip("subscribe: %v", err)
	}
	deadline := time.After(time.Duration(secs) * time.Second)
	total, active, typing := 0, 0, 0
	for {
		select {
		case ev, ok := <-cl.Events():
			if !ok {
				goto done
			}
			if ev.Event != proto.EventState {
				continue
			}
			total++
			var st struct {
				SecretInput  string `json:"secret_input"`
				PersonTyping bool   `json:"person_typing"`
			}
			_ = json.Unmarshal(ev.Data, &st)
			if st.SecretInput == proto.SecretActive {
				active++
				if st.PersonTyping {
					typing++
				}
			}
		case <-deadline:
			goto done
		}
	}
done:
	if active == 0 {
		skip("no state event with a secret prompt active (%d events in %d s)", total, secs)
	}
	if active > 2 {
		escaped("%d state events while the secret prompt was active (%d with person_typing): the agent sees each keystroke", active, typing)
	}
	denied("%d state event(s) while the secret prompt was active, %d in total", active, total)
}

// fakeBroker: fake-broker SOCK LOG SECS listens on SOCK as a fake broker:
// it answers every hello with code_required and waits for a hello that
// carries a reattach code or a proof of one. Exit 0 (escaped) when a
// client sent one: the attach client trusted a socket it did not verify. 1 when no code came
// within SECS seconds.
func fakeBroker(sock, logFile string, secs int) {
	l, err := net.Listen("unix", sock)
	if err != nil {
		skip("listen %s: %v", sock, err)
	}
	defer os.Remove(sock)
	logf, _ := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	got := make(chan string, 1)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Duration(secs) * time.Second))
				for {
					f, err := proto.ReadFrame(c)
					if err != nil || f.Type != proto.FrameJSON {
						return
					}
					var req proto.Request
					if json.Unmarshal(f.Payload, &req) != nil || req.Op != "hello" {
						return
					}
					var h proto.Hello
					_ = json.Unmarshal(req.Args, &h)
					var legacy struct {
						Code string `json:"reattach_code"`
					}
					_ = json.Unmarshal(req.Args, &legacy)
					if legacy.Code != "" || h.Proof != "" {
						// Never log the code or the proof: only that one arrived.
						fmt.Fprintf(logf, "code or code proof received from a %s client\n", h.Role)
						got <- h.Role
						return
					}
					fmt.Fprintf(logf, "hello %s without a code: answered code_required\n", h.Role)
					// Pose as a broker: ask for the code with a challenge, as
					// the real one does.
					_ = proto.WriteJSON(c, proto.RawResponse{ID: req.ID, OK: false,
						Error: &proto.Error{Code: proto.ErrCodeRequired, Message: "reattach code required",
							Challenge: &proto.Challenge{Kind: proto.AuthCode, Nonce: strings.Repeat("00", proto.NonceLen),
								Salt: strings.Repeat("11", 16), Iterations: proto.CodeKDFIterations}}})
				}
			}(c)
		}
	}()
	select {
	case role := <-got:
		_ = l.Close()
		escaped("a %s client sent its reattach code to a fake socket", role)
	case <-time.After(time.Duration(secs) * time.Second):
		_ = l.Close()
		denied("no reattach code reached the fake socket in %d s", secs)
	}
}

// pidfdGetfd: pidfd-getfd PID PATH takes the descriptors of PID with
// pidfd_getfd(2), without opening anything, and looks for the terminal
// PATH among them. Exit 0 (escaped) when a copy of PATH was obtained.
func pidfdGetfd(pid int, path string) {
	if pid <= 0 {
		skip("no target pid")
	}
	pfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		denied("pidfd_open %d: %v", pid, err)
	}
	defer unix.Close(pfd)
	// Inside a private devpts the path may name another terminal or none:
	// then any pts (major 136 to 143) obtained counts.
	var want unix.Stat_t
	known := unix.Stat(path, &want) == nil
	var lastErr error
	for fd := 0; fd < 64; fd++ {
		nfd, err := unix.PidfdGetfd(pfd, fd, 0)
		if err != nil {
			if !errors.Is(err, unix.EBADF) {
				lastErr = err
			}
			continue
		}
		var st unix.Stat_t
		_ = unix.Fstat(nfd, &st)
		unix.Close(nfd)
		isPts := st.Mode&unix.S_IFMT == unix.S_IFCHR && unix.Major(st.Rdev) >= 136 && unix.Major(st.Rdev) <= 143
		if isPts && (!known || st.Rdev == want.Rdev) {
			escaped("pidfd_getfd(%d, fd %d) gave a copy of %s", pid, fd, path)
		}
	}
	if lastErr != nil {
		denied("pidfd_getfd on %d: %v", pid, lastErr)
	}
	denied("no descriptor of %d is %s", pid, path)
}

// cloneIntoCgroup: clone-into-cgroup DIR starts a child with
// clone3(CLONE_INTO_CGROUP) into the cgroup directory DIR (outside the
// agent's own), which writes no cgroup.procs file. Exit 0 (escaped) when
// the child ran in DIR.
func cloneIntoCgroup(dir string) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		denied("open %s: %v", dir, err)
	}
	defer unix.Close(fd)
	c := exec.Command("/bin/cat", "/proc/self/cgroup")
	c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	out, err := c.CombinedOutput()
	if err != nil {
		denied("clone3 into %s: %v %s", dir, err, bytes.TrimSpace(out))
	}
	rel := strings.TrimPrefix(filepath.Clean(dir), "/sys/fs/cgroup")
	got := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "0::"))
	if got == rel {
		escaped("a child started in %s, outside the agent's cgroup", rel)
	}
	denied("the child ran in %s, not %s", got, rel)
}

// prlimitOther: prlimit PID sets RLIMIT_CORE of another process (a
// lower RLIMIT_CPU would kill it). Exit 0 (escaped) when it changed.
func prlimitOther(pid int) {
	if pid <= 0 {
		skip("no target pid")
	}
	if err := unix.Prlimit(pid, unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}, nil); err != nil {
		denied("prlimit %d: %v", pid, err)
	}
	escaped("changed RLIMIT_CORE of pid %d", pid)
}

// sigioKill: sigio PID makes the kernel send SIGKILL to PID through
// F_SETOWN and F_SETSIG on a pipe (send_sigio, not kill(2)). Exit 0
// (escaped) when PID died.
func sigioKill(pid int) {
	if pid <= 0 {
		skip("no target pid")
	}
	if err := unix.Kill(pid, 0); errors.Is(err, unix.ESRCH) {
		// Another pid namespace, or the target is gone: nothing to signal
		// from here.
		denied("pid %d is not visible from here", pid)
	}
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		skip("pipe: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(p[0]), unix.F_SETOWN, pid); err != nil {
		denied("F_SETOWN %d: %v", pid, err)
	}
	if _, err := unix.FcntlInt(uintptr(p[0]), unix.F_SETSIG, int(unix.SIGKILL)); err != nil {
		denied("F_SETSIG: %v", err)
	}
	fl, _ := unix.FcntlInt(uintptr(p[0]), unix.F_GETFL, 0)
	if _, err := unix.FcntlInt(uintptr(p[0]), unix.F_SETFL, fl|unix.O_ASYNC); err != nil {
		denied("O_ASYNC: %v", err)
	}
	_, _ = unix.Write(p[1], []byte("x"))
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		if err := unix.Kill(pid, 0); errors.Is(err, unix.ESRCH) {
			escaped("pid %d killed by SIGIO (SIGKILL)", pid)
		}
		// A zombie child of someone else still answers kill(0): look at
		// its state.
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			if f := strings.Fields(string(b)); len(f) > 2 && f[2] == "Z" {
				escaped("pid %d killed by SIGIO (SIGKILL), now a zombie", pid)
			}
		}
	}
	denied("pid %d is still alive", pid)
}
