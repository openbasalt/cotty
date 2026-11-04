package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/attach"
	"github.com/openbasalt/cotty/internal/guard"
	"github.com/openbasalt/cotty/internal/proto"
	"github.com/openbasalt/cotty/internal/session"
)

func init() {
	register(command{name: "new", usage: "[--name N] [--ai] [--require-confined] [--policy confirm] [-d] [-- shell argv]",
		summary: "start a shared session and attach to it", run: runNew})
}

func runNew(args []string) int {
	var bf brokerFlags
	fs := flag.NewFlagSet("new", flag.ContinueOnError)
	bf.Define(fs)
	detached := fs.Bool("d", false, "start the session without attaching (prints the reattach code)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir, err := session.Dir()
	if err != nil {
		return fail("%v", err)
	}
	if bf.Name == "" {
		if bf.Name, err = session.FreeName(dir); err != nil {
			return fail("%v", err)
		}
	}
	if !session.ValidName(bf.Name) {
		return fail("invalid session name %q (letters, digits, . _ -, not starting with . or -; up to 32)", bf.Name)
	}
	verifier, err := brokerVerifier()
	if err != nil {
		return fail("%v", err)
	}
	if bf.Insecure && verifier != nil {
		return fail("--dev-insecure is refused while cotty-guard is loaded: an insecure broker admits any process of the user")
	}
	paths := session.PathsFor(dir, bf.Name)
	if c, err := net.DialTimeout("unix", paths.Socket, time.Second); err == nil {
		_ = c.Close()
		return fail("session %q already exists", bf.Name)
	}
	_ = os.Remove(paths.Socket)

	rows, cols := 24, 80
	if ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ); err == nil && ws.Row > 2 {
		rows, cols = int(ws.Row)-1, int(ws.Col) // the last row is cotty's status line
	}
	var tokenRaw [32]byte
	if _, err := rand.Read(tokenRaw[:]); err != nil {
		return fail("%v", err)
	}
	token := hex.EncodeToString(tokenRaw[:])

	exe, err := os.Executable()
	if err != nil {
		return fail("%v", err)
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return fail("%v", err)
	}
	tokR, tokW, err := os.Pipe()
	if err != nil {
		return fail("%v", err)
	}
	logf, err := os.OpenFile(paths.Log, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fail("%v", err)
	}
	bargs := []string{"__broker", "-name", bf.Name, "-policy", bf.Policy,
		"-rows", strconv.Itoa(rows), "-cols", strconv.Itoa(cols)}
	if bf.AI {
		bargs = append(bargs, "-ai")
	}
	if bf.Insecure {
		bargs = append(bargs, "-dev-insecure")
	}
	if bf.CountSecret {
		bargs = append(bargs, "-count-secret-keys")
	}
	if bf.RequireConf {
		bargs = append(bargs, "-require-confined")
	}
	bargs = append(bargs, "--")
	bargs = append(bargs, fs.Args()...)
	cmd := exec.Command(exe, bargs...)
	cmd.Stderr = logf
	cmd.ExtraFiles = []*os.File{readyW, tokR} // fd 3 and fd 4
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fail("starting the broker: %v", err)
	}
	_ = readyW.Close()
	_ = tokR.Close()
	_ = logf.Close()
	_, _ = tokW.Write([]byte(token + "\n"))
	_ = tokW.Close()
	brokerPID := cmd.Process.Pid
	_ = cmd.Process.Release()

	type readyMsg struct {
		line string
		err  error
	}
	got := make(chan readyMsg, 1)
	go func() {
		l, err := bufio.NewReader(readyR).ReadString('\n')
		got <- readyMsg{strings.TrimSpace(l), err}
	}()
	// The broker reads the masking list before it listens; a secret
	// source may ask to unlock a keyring, so allow for that.
	slow := time.NewTimer(3 * time.Second)
	defer slow.Stop()
	timeout := time.NewTimer(90 * time.Second)
	defer timeout.Stop()
wait:
	for {
		select {
		case m := <-got:
			if m.line != "ready" {
				return fail("the broker did not start: %s (see %s)", strings.TrimPrefix(m.line, "error "), paths.Log)
			}
			break wait
		case <-slow.C:
			fmt.Fprintln(os.Stderr, "cotty: reading the masking list (secrets.conf)...")
		case <-timeout.C:
			return fail("the broker did not start in time (see %s)", paths.Log)
		}
	}
	_ = readyR.Close()

	if *detached {
		cl, _, err := attach.Connect(attach.ConnectOptions{Socket: paths.Socket, Session: bf.Name,
			Hello: proto.Hello{Role: proto.RoleControl, Client: "cotty-new"}, CreatorToken: token, BrokerPID: brokerPID,
			Verifier: verifier})
		if err != nil {
			return fail("%v", err)
		}
		defer cl.Close()
		ctx := context.Background()
		var r struct {
			Code string `json:"code"`
		}
		if err := cl.Call(ctx, "code", nil, &r); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("cotty: session %s started; attach with `cotty attach %s` and reattach code %s\n", bf.Name, bf.Name, r.Code)
		return 0
	}
	return attachAndReport(attach.Options{Session: bf.Name, Socket: paths.Socket, CreatorToken: token,
		BrokerPID: brokerPID, Client: "cotty-new", Verifier: verifier})
}

// brokerVerifier is the guard's check of a session listener when the guard
// is loaded (it vouches that the listener is the session's registered
// broker), nil when no guard is installed (the attach client's own checks
// only), and an error when the guard enforces but its daemon does not
// answer: the client then refuses to attach instead of skipping the check.
func brokerVerifier() (attach.BrokerVerifier, error) {
	v, err := guard.ClientVerifier()
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	return v, nil
}

// attachAndReport runs the attach client and prints how it ended.
func attachAndReport(opts attach.Options) int {
	res, err := attach.Run(opts)
	if err != nil {
		return fail("%v", err)
	}
	switch {
	case res.Detached:
		fmt.Printf("[detached from cotty session %s; reattach code %s]\n", opts.Session, res.Code)
		return 0
	case res.Ended:
		fmt.Printf("[cotty session %s ended]\n", opts.Session)
		return res.ExitCode
	}
	return 0
}
