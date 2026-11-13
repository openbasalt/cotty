// Command guardprobe is the escape matrix's helper for cotty-guard
// (layer 3, tests/attacks/guard.sh). It talks to the daemon the way
// `cotty agent` and the broker do.
//
//	guardprobe run-registered [--allow PATH]... [--guard DIR]... -- CMD...
//	        register the current cgroup (it must be a cotty-agent* scope)
//	        as an agent, then exec CMD: the guard-only test mode (the agent
//	        runs without layer 2 but under the guard)
//	guardprobe tag-of PID      print the guard's tag of a pid
//	guardprobe verify SOCK NAME
//	        ask the guard whether the listener of SOCK is the registered
//	        broker of session NAME (exit 0 yes, 1 no)
//	guardprobe status          print the daemon's status
//
// Attack subcommands (exit 0: escaped, 1: denied, 2: does not apply):
//
//	guardprobe untag           ask the daemon to remove our tag
//	guardprobe register-again  ask the daemon to register our cgroup again
//	                           (an agent must not be able to register)
//	guardprobe tag-self        ask to be tagged (allowed: it only restricts)
//	guardprobe tag-self-then CMD...
//	                           ask to be tagged, then exec CMD (a tag must
//	                           never raise an agent's assurance, review
//	                           COT-2)
//	guardprobe steal-pts PTS   protect a pts somebody else protects, with
//	                           ourselves as its owner (must be refused)
//	guardprobe protect-pts     protect a pty of our own (we hold its
//	                           master) without being a registered broker
//	                           (must be refused)
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/guard"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: guardprobe run-registered|protect-pts|tag-of|status|untag|register-again|tag-self")
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "run-registered":
		runRegistered(args)
	case "protect-pts":
		protectPTS(args)
	case "tag-of":
		tagOf(args)
	case "status":
		withConn(func(c *guard.Conn) {
			st, err := c.Status()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Printf("loaded=%v programs=%d agents=%d ptys=%d denials=%d dropped=%d\n", st.Loaded, len(st.Programs), st.Agents, st.Ptys, st.Denials, st.Dropped)
		})
	case "untag":
		attack(func(c *guard.Conn) error { _, err := rawOp(c, guard.OpUntag); return err })
	case "register-again":
		attack(func(c *guard.Conn) error { _, _, err := c.Register(nil, nil); return err })
	case "steal-pts":
		stealPTS(args)
	case "verify":
		verifyBroker(args)
	case "tag-self":
		withConn(func(c *guard.Conn) {
			tag, err := c.TagSelf()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println(tag)
		})
	case "tag-self-then":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: guardprobe tag-self-then CMD...")
			os.Exit(2)
		}
		withConn(func(c *guard.Conn) {
			if _, err := c.TagSelf(); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		})
		path, err := exec.LookPath(args[0])
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}
		err = syscall.Exec(path, args, os.Environ())
		fmt.Println(err)
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %s\n", os.Args[1])
		os.Exit(2)
	}
}

func withConn(f func(c *guard.Conn)) {
	c, err := guard.Dial()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer c.Close()
	f(c)
}

// attack runs an operation that must be refused: a refusal by the daemon
// or a connect denied by the guard both count as denied.
func attack(f func(c *guard.Conn) error) {
	c, err := guard.Dial()
	if err != nil {
		fmt.Printf("cannot reach the guard: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()
	if err := f(c); err != nil {
		fmt.Printf("refused: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("accepted")
	os.Exit(0)
}

// rawOp sends an operation the client library does not offer.
func rawOp(c *guard.Conn, op string) (string, error) {
	return guard.RawOp(c, op)
}

func currentCgroup() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			return p
		}
	}
	return ""
}

func runRegistered(args []string) {
	var allow, guarded []string
	for len(args) > 0 && args[0] != "--" {
		if args[0] == "--allow" && len(args) > 1 {
			allow = append(allow, args[1])
			args = args[2:]
			continue
		}
		if args[0] == "--guard" && len(args) > 1 {
			guarded = append(guarded, args[1])
			args = args[2:]
			continue
		}
		fmt.Fprintf(os.Stderr, "guardprobe: unknown flag %s\n", args[0])
		os.Exit(2)
	}
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "guardprobe: run-registered [--allow PATH]... -- CMD...")
		os.Exit(2)
	}
	argv := args[1:]
	cg := currentCgroup()
	tag, notes, err := guard.ForAgent(cg, allow, guarded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "guardprobe: register: %v\n", err)
		os.Exit(125)
	}
	if tag == "" {
		fmt.Fprintln(os.Stderr, "guardprobe: no guard running; refusing to run the guard-only mode unprotected")
		os.Exit(125)
	}
	fmt.Fprintf(os.Stderr, "guardprobe: agent registered as %s (cgroup %s)\n", tag, cg)
	for _, n := range notes {
		fmt.Fprintf(os.Stderr, "guardprobe: note: %s\n", n)
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "guardprobe: %v\n", err)
		os.Exit(127)
	}
	err = syscall.Exec(path, argv, os.Environ())
	fmt.Fprintf(os.Stderr, "guardprobe: exec: %v\n", err)
	os.Exit(126)
}

func tagOf(args []string) {
	if len(args) != 1 {
		os.Exit(2)
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		os.Exit(2)
	}
	withConn(func(c *guard.Conn) {
		tag, err := c.TagOf(pid)
		if err != nil {
			if errors.Is(err, guard.ErrNotRunning) {
				os.Exit(2)
			}
			fmt.Println(err)
			os.Exit(1)
		}
		if tag == "" {
			tag = "(none)"
		}
		fmt.Println(tag)
	})
}

// protectPTS: protect-pts opens a new pty of its own and asks the guard to
// protect it, as a process that holds the master but is no registered
// broker: refused (review N2: before, any process of the user could
// protect any of its terminals, a session's pts first, so the session's
// broker could not, or the person's other terminals).
func protectPTS(args []string) {
	if len(args) != 0 {
		os.Exit(2)
	}
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		fmt.Printf("open /dev/ptmx: %v\n", err)
		os.Exit(2)
	}
	defer m.Close()
	pfd, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCGPTPEER), uintptr(unix.O_PATH|unix.O_NOCTTY|unix.O_CLOEXEC))
	if errno != 0 {
		fmt.Printf("TIOCGPTPEER: %v\n", errno)
		os.Exit(2)
	}
	defer unix.Close(int(pfd))
	attack(func(c *guard.Conn) error {
		_, err := c.ProtectPTS(int(pfd), int(m.Fd()))
		return err
	})
}

// stealPTS: steal-pts PTS opens a pts with O_PATH (no file_open check)
// and asks the daemon to protect it for us, with the master of a pty of
// our own: refused, the caller being no registered broker and the master
// not the terminal's (with another live owner it would also be refused,
// or the caller would become the one process allowed to open it).
func stealPTS(args []string) {
	if len(args) != 1 {
		os.Exit(2)
	}
	f, err := os.OpenFile(args[0], unix.O_PATH, 0)
	if err != nil {
		fmt.Printf("open O_PATH: %v\n", err)
		os.Exit(2)
	}
	defer f.Close()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		fmt.Printf("open /dev/ptmx: %v\n", err)
		os.Exit(2)
	}
	defer m.Close()
	attack(func(c *guard.Conn) error {
		if _, err := c.ProtectPTS(int(f.Fd()), int(m.Fd())); err != nil {
			return err
		}
		// Accepted: show that the pts now opens for us.
		g, err := os.OpenFile(args[0], os.O_WRONLY|unix.O_NOCTTY, 0)
		if err != nil {
			return fmt.Errorf("protected for us, yet the open failed: %w", err)
		}
		g.Close()
		return nil
	})
}

// verifyBroker: verify SOCK NAME connects to SOCK and asks the guard
// whether its listener is the registered broker of session NAME, as the
// attach client does. Exit 0 when the guard vouches for it, 1 when it
// refuses, 2 when SOCK cannot be reached.
func verifyBroker(args []string) {
	if len(args) != 2 {
		os.Exit(2)
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: args[0], Net: "unix"})
	if err != nil {
		fmt.Printf("connect: %v\n", err)
		os.Exit(2)
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		os.Exit(2)
	}
	pid := 0
	_ = raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			pid = int(cred.Pid)
		}
	})
	if err := (guard.BrokerVerifier{}).VerifyBroker(conn, args[1], pid); err != nil {
		fmt.Printf("refused: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("verified: pid %d is the broker of session %s\n", pid, args[1])
}
