package main

// Broker-targeted attacks and helpers (tests/attacks/broker.sh): taking
// the person role on a session socket, attaching through a fresh terminal
// (as `systemd-run --user --pty` would give one), guessing the reattach
// code, and the scripted person that denies attach requests and types a
// secret at the lock.

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/openbasalt/cotty/internal/proto"
)

func brokerCommand(name string, args []string) bool {
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch name {
	case "hello":
		helloRole(arg(0), arg(1))
	case "agent-type":
		agentType(arg(0), arg(1))
	case "agent-read":
		agentRead(arg(0), arg(1))
	case "agent-state":
		agentState(arg(0))
	case "open-tty":
		openTTY(arg(0))
	case "in-pty":
		inPty(args)
	case "brute":
		brute(arg(0), arg(1), atoi(arg(2)))
	case "person":
		person(args)
	default:
		return guardCommand(name, args)
	}
	return true
}

// helloRole connects to SOCK and asks for ROLE. Exit 0 (escaped) when the
// broker grants it, 1 when it refuses or the socket is unreachable.
func helloRole(sock, role string) {
	cl, err := proto.Dial(sock)
	if err != nil {
		denied("connect %s: %v", sock, err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	h, err := cl.Hello(ctx, proto.Hello{Role: role, Client: "probe"})
	if err != nil {
		denied("hello %s refused: %v", role, err)
	}
	escaped("hello %s granted: assurance %s (%s)", role, h.Assurance, h.AssuranceReason)
}

// agentType types TEXT (with Enter) as an agent on SOCK; a helper, exit 0
// on success.
func agentType(sock, text string) {
	cl, err := proto.Dial(sock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h, err := cl.Hello(ctx, proto.Hello{Role: proto.RoleAgent, Client: "probe"})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for i := 0; ; i++ {
		err = cl.Call(ctx, "type", map[string]any{"text": text, "enter": true}, nil)
		if proto.ErrorCode(err) == proto.ErrPersonTyping && i < 5 {
			time.Sleep(1600 * time.Millisecond)
			continue
		}
		break
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("typed as agent (assurance %s)\n", h.Assurance)
}

// agentRead reads everything an agent can read on SOCK (screen with
// context, all committed lines, state) and looks for MARKER. Exit 0
// (escaped) when found.
func agentRead(sock, marker string) {
	cl, err := proto.Dial(sock)
	if err != nil {
		denied("connect: %v", err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := cl.Hello(ctx, proto.Hello{Role: proto.RoleAgent, Client: "probe"}); err != nil {
		denied("hello agent: %v", err)
	}
	var sc, sn, st map[string]any
	_ = cl.Call(ctx, "screen", map[string]any{"context": 200}, &sc)
	_ = cl.Call(ctx, "since", map[string]any{"cursor": 0, "limit": 5000}, &sn)
	_ = cl.Call(ctx, "state", nil, &st)
	all := fmt.Sprint(sc, sn, st)
	if strings.Contains(all, marker) {
		escaped("the marker is in what the agent reads")
	}
	denied("marker absent from screen, scrollback and state (%d bytes read)", len(all))
}

// agentState connects to SOCK as an agent and prints the session's
// assurance and the agent's own (a helper, exit 0 on success). Run it as
// a guard-tagged agent so the agent itself does not lower the session's
// level.
func agentState(sock string) {
	cl, err := proto.Dial(sock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h, err := cl.Hello(ctx, proto.Hello{Role: proto.RoleAgent, Client: "probe"})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var st proto.State
	if err := cl.Call(ctx, "state", nil, &st); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("session=%s agent=%s reason=%s\n", st.Assurance, h.Assurance, h.AssuranceReason)
}

// openTTY opens a terminal device read-write without blocking and without
// making it the controlling terminal. Exit 0 (escaped) when it opens: the
// opener could then read the keys typed there (competing with the shell)
// and write text that looks like the session's output.
func openTTY(p string) {
	fd, err := syscall.Open(p, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		denied("open %s: %v", p, err)
	}
	_ = syscall.Close(fd)
	escaped("opened %s read-write", p)
}

var escRE = regexp.MustCompile(`\x1b(\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)|[@-Z\\-_])`)

// stripEsc drops escape sequences from terminal output.
func stripEsc(b []byte) string {
	return escRE.ReplaceAllString(string(b), "")
}

// ptyRun runs argv in a new kernel session whose controlling terminal is
// a fresh pty, as a terminal emulator or `systemd-run --pty` would.
type ptyRun struct {
	cmd  *exec.Cmd
	f    *os.File
	mu   sync.Mutex
	out  bytes.Buffer
	done chan struct{}
}

func startPty(argv []string) (*ptyRun, error) {
	c := exec.Command(argv[0], argv[1:]...)
	c.Env = append(os.Environ(), "TERM=xterm-256color")
	f, err := pty.StartWithSize(c, &pty.Winsize{Rows: 30, Cols: 100})
	if err != nil {
		return nil, err
	}
	r := &ptyRun{cmd: c, f: f, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		buf := make([]byte, 8192)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				r.mu.Lock()
				r.out.Write(buf[:n])
				r.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return r, nil
}

func (r *ptyRun) text() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return stripEsc(r.out.Bytes())
}

func (r *ptyRun) waitFor(s string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(r.text(), s) {
			return true
		}
		select {
		case <-r.done:
			return strings.Contains(r.text(), s)
		case <-time.After(50 * time.Millisecond):
		}
	}
	return false
}

func (r *ptyRun) stop() {
	_ = r.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-r.done:
	case <-time.After(2 * time.Second):
		_ = r.cmd.Process.Kill()
	}
	_ = r.cmd.Wait()
	_ = r.f.Close()
}

func lastLines(s string, n int) string {
	var ls []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ls = append(ls, l)
		}
	}
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, " | ")
}

// inPty: in-pty SECS SUCCESS CMD ARGS... runs CMD in a fresh terminal for
// at most SECS seconds. Exit 0 (escaped) when its output shows SUCCESS,
// 1 otherwise, with the last lines of output.
func inPty(args []string) {
	if len(args) < 3 {
		skip("usage: in-pty SECS SUCCESS CMD...")
	}
	secs := atoi(args[0])
	r, err := startPty(args[2:])
	if err != nil {
		skip("start: %v", err)
	}
	ok := r.waitFor(args[1], time.Duration(secs)*time.Second)
	r.stop()
	out := lastLines(r.text(), 3)
	if ok {
		escaped("%q shown: %s", args[1], out)
	}
	denied("%s", out)
}

// brute: brute COTTY SESSION N types N random reattach codes through
// `cotty attach` in fresh terminals (only possible while no person is
// attached). Exit 0 if a guess was admitted.
func brute(cotty, sessionName string, n int) {
	start := time.Now()
	tries, invalid, limited := 0, 0, 0
	for tries < n {
		r, err := startPty([]string{cotty, "attach", sessionName})
		if err != nil {
			skip("start: %v", err)
		}
		seen := 0
		for tries < n {
			if !r.waitForCount("Reattach code", seen+1, 5*time.Second) {
				break
			}
			seen++
			tries++
			_, _ = r.f.Write([]byte(randomCode() + "\r"))
		}
		r.waitFor("\x00never", 1500*time.Millisecond)
		t := r.text()
		invalid += strings.Count(t, "wrong code")
		if strings.Contains(t, "rate_limited") || strings.Contains(t, "too many wrong codes") {
			limited++
		}
		success := strings.Contains(t, "cotty:"+sessionName+" ")
		r.stop()
		if success {
			escaped("a guessed code was admitted after %d tries", tries)
		}
		if seen == 0 {
			// No code prompt at all: the attach failed before admission.
			denied("no code prompt (%d guesses typed): %s", tries, lastLines(t, 2))
		}
		if limited > 0 && tries >= 4 {
			// Locked out: the remaining guesses would only wait.
			break
		}
	}
	denied("%d guesses in %.1fs, %d answered wrong code, rate limit reached %d times; code space 32^10 (2^50), 3 guesses per 30 s",
		tries, time.Since(start).Seconds(), invalid, limited)
}

func (r *ptyRun) waitForCount(s string, count int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Count(r.text(), s) >= count {
			return true
		}
		select {
		case <-r.done:
			return strings.Count(r.text(), s) >= count
		case <-time.After(50 * time.Millisecond):
		}
	}
	return false
}

func randomCode() string {
	const alpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [10]byte
	_, _ = rand.Read(b[:])
	out := make([]byte, 0, 11)
	for i, c := range b {
		if i == 5 {
			out = append(out, '-')
		}
		out = append(out, alpha[int(c)%32])
	}
	return string(out)
}

// person: person COTTY SESSION CODEFILE LOG [SECRETFILE] is the scripted
// person: it attaches with the reattach code in CODEFILE, denies every
// attach request (^] x), types the content of SECRETFILE one key at a
// time whenever the lock lights (and logs the lock's text, which names
// the program the person is told to check), on SIGUSR2 types the bytes
// of LOG.cmd (hotkeys included), and on SIGUSR1 detaches and writes the
// new reattach code to CODEFILE. Events go to LOG, one per line.
func person(args []string) {
	if len(args) < 4 {
		skip("usage: person COTTY SESSION CODEFILE LOG [SECRETFILE]")
	}
	cotty, name, codeFile, logFile := args[0], args[1], args[2], args[3]
	secret := ""
	if len(args) > 4 {
		b, err := os.ReadFile(args[4])
		if err != nil {
			skip("%v", err)
		}
		secret = strings.TrimSpace(string(b))
	}
	logf, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		skip("%v", err)
	}
	logEv := func(f string, a ...any) { fmt.Fprintf(logf, f+"\n", a...) }
	code, _ := os.ReadFile(codeFile)
	r, err := startPty([]string{cotty, "attach", name})
	if err != nil {
		skip("%v", err)
	}
	if r.waitFor("Reattach code", 5*time.Second) {
		_, _ = r.f.Write([]byte(strings.TrimSpace(string(code)) + "\r"))
	}
	if !r.waitFor("cotty:"+name+" ", 10*time.Second) {
		logEv("attach-failed %s", lastLines(r.text(), 3))
		os.Exit(1)
	}
	logEv("attached")
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGTERM)
	lockOn, reqAt := false, time.Time{}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	codeRE := regexp.MustCompile(`reattach code ([0-9A-Z]{5}-[0-9A-Z]{5})`)
	marker := "cotty:" + name + " "
	for {
		select {
		case s := <-usr1:
			if s == syscall.SIGTERM {
				r.stop()
				os.Exit(0)
			}
			if s == syscall.SIGUSR2 {
				b, err := os.ReadFile(logFile + ".cmd")
				if err != nil {
					logEv("cmd-failed %v", err)
					continue
				}
				_, _ = r.f.Write(b)
				logEv("cmd-sent %d bytes", len(b))
				continue
			}
			_, _ = r.f.Write([]byte("\x1dd"))
			r.waitFor("[detached", 5*time.Second)
			if m := codeRE.FindStringSubmatch(r.text()); m != nil {
				_ = os.WriteFile(codeFile, []byte(m[1]+"\n"), 0o600)
				logEv("detached")
			} else {
				logEv("detach-failed %s", lastLines(r.text(), 2))
			}
			r.stop()
			os.Exit(0)
		case <-r.done:
			logEv("ended")
			os.Exit(0)
		case <-tick.C:
			// The latest status line: the text after its last redraw.
			t := r.text()
			status := t
			if i := strings.LastIndex(t, marker); i >= 0 {
				// Segments such as an attach request are drawn before the
				// session marker: read from the previous draw's marker on (the
				// text is stripped of escapes, and what follows a marker in a
				// draw never holds a request).
				start := max(0, i-300)
				if j := strings.LastIndex(t[:i], marker); j >= 0 {
					start = j + len(marker)
				}
				status = t[start:]
			}
			if strings.Contains(status, "attach request: pid") {
				if time.Since(reqAt) > 3*time.Second {
					reqAt = time.Now()
					_, _ = r.f.Write([]byte("\x1dx"))
					logEv("request-denied")
				}
			}
			on := strings.Contains(status, " LOCK ")
			if on && !lockOn {
				// The lock segment of the status line, up to the next
				// separator: what the person reads before typing.
				lock := status[strings.Index(status, " LOCK ")+1:]
				if i := strings.Index(lock, "\n"); i >= 0 {
					lock = lock[:i]
				}
				if len(lock) > 80 {
					lock = lock[:80]
				}
				logEv("lock-shown %s", strings.TrimSpace(lock))
			}
			if on && !lockOn && secret != "" {
				time.Sleep(200 * time.Millisecond)
				// One key at a time, as a person types: the broker sees
				// one input batch per key.
				for _, ch := range []byte(secret) {
					_, _ = r.f.Write([]byte{ch})
					time.Sleep(60 * time.Millisecond)
				}
				_, _ = r.f.Write([]byte("\r"))
				logEv("typed-secret")
			}
			lockOn = on
		}
	}
}
