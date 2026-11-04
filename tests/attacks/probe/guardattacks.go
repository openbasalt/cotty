package main

// Attacks on rules cotty-guard (layer 3) adds for the review's guard
// findings, besides those in review.go (tests/attacks/guard-inside.sh,
// broker.sh): descriptor passing of a session pts, scheduling of outside
// processes, SIGIO owners, cgroup control files, and planting sockets in
// guarded directories. Every
// attempt is harmless when it works: limits and priorities are set to
// their current values, cgroup files are opened and closed unwritten.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func guardCommand(name string, args []string) bool {
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch name {
	case "setnice":
		setNice(atoi(arg(0)))
	case "setown":
		setOwn(atoi(arg(0)))
	case "cgroup-open-write":
		cgroupOpenWrite(arg(0))
	case "bind-in":
		bindIn(arg(0))
	case "send-tty":
		sendTTY(arg(0), arg(1))
	case "recv-fd":
		recvFD(arg(0), arg(1))
	default:
		return false
	}
	return true
}

// setNice sets the nice value of PID to its current value.
func setNice(pid int) {
	prio, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
	if err != nil {
		skip("getpriority %d: %v", pid, err)
	}
	// The raw syscall returns 20 - nice.
	if err := unix.Setpriority(unix.PRIO_PROCESS, pid, 20-prio); err != nil {
		denied("setpriority %d: %v", pid, err)
	}
	escaped("set the nice value of pid %d (to its current value)", pid)
}

// setOwn makes PID the SIGIO owner of a pipe (F_SETOWN): with O_ASYNC,
// every write would signal it, without task_kill.
func setOwn(pid int) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		skip("pipe: %v", err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	if _, err := unix.FcntlInt(uintptr(p[0]), unix.F_SETOWN, pid); err != nil {
		denied("F_SETOWN %d: %v", pid, err)
	}
	escaped("pid %d is now the SIGIO owner of a pipe", pid)
}

// cgroupOpenWrite opens a cgroup control file for writing and closes it
// without writing.
func cgroupOpenWrite(path string) {
	if _, err := os.Stat(path); err != nil {
		skip("%v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		denied("open %s for writing: %v", path, err)
	}
	f.Close()
	escaped("opened %s for writing (nothing written)", path)
}

// bindIn binds a Unix socket in DIR. Exit 0 when the socket was created.
func bindIn(dir string) {
	if _, err := os.Stat(dir); err != nil {
		skip("%v", err)
	}
	p := filepath.Join(dir, fmt.Sprintf("planted-%d.sock", os.Getpid()))
	l, err := net.Listen("unix", p)
	if err != nil {
		denied("bind %s: %v", p, err)
	}
	l.Close()
	_ = os.Remove(p)
	escaped("bound %s", p)
}

// sendTTY opens TTY (the controlling terminal, /dev/tty, from inside a
// session) and sends it over SOCK with SCM_RIGHTS: run inside a session,
// it is the helper of recv-fd.
func sendTTY(sock, tty string) {
	f, err := os.OpenFile(tty, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		skip("open %s: %v", tty, err)
	}
	defer f.Close()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		skip("connect %s: %v", sock, err)
	}
	defer c.Close()
	if _, _, err := c.WriteMsgUnix([]byte("tty"), unix.UnixRights(int(f.Fd())), nil); err != nil {
		skip("send: %v", err)
	}
	fmt.Println("sent")
}

// recvFD listens on SOCK, writes READY when listening, and waits for one
// descriptor (from send-tty in a session). Exit 0 when a usable
// descriptor arrived.
func recvFD(sock, ready string) {
	_ = os.Remove(sock)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		skip("listen: %v", err)
	}
	defer l.Close()
	_ = os.WriteFile(ready, []byte("ready\n"), 0o644)
	_ = l.SetDeadline(deadline(30))
	c, err := l.AcceptUnix()
	if err != nil {
		skip("no sender: %v", err)
	}
	defer c.Close()
	buf := make([]byte, 16)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, flags, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		skip("recvmsg: %v", err)
	}
	if flags&syscall.MSG_CTRUNC != 0 || oobn == 0 {
		denied("the descriptor was refused (MSG_CTRUNC, no SCM_RIGHTS)")
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		denied("no descriptor received")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		denied("no descriptor received")
	}
	link, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fds[0]))
	for _, fd := range fds {
		unix.Close(fd)
	}
	escaped("received a descriptor of %s", link)
}

func deadline(seconds int) time.Time { return time.Now().Add(time.Duration(seconds) * time.Second) }
