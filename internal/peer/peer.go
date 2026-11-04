// Package peer classifies the other end of a broker connection as a
// person or an agent from what the kernel says about it, never from what
// the client claims (PLAN section 3).
//
// Provenance: the SO_PEERCRED / SO_PEERSEC reading and the SELinux
// context parsing follow basalt-shell internal/shell/peer.go
// (github.com/basalt-os/basalt-shell, commit 47b7463), same owner,
// Apache-2.0. The namespace, cgroup, ancestry, controlling terminal and
// executable checks are new.
package peer

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// soPeerSec is SO_PEERSEC on Linux.
const soPeerSec = 31

// soPeerPidfd is SO_PEERPIDFD (Linux 6.5).
const soPeerPidfd = 77

// Info is what the kernel tells about a peer process.
type Info struct {
	UID       int      `json:"uid"`
	PID       int      `json:"pid"`
	PPID      int      `json:"ppid"`
	PGID      int      `json:"pgid"`
	SID       int      `json:"sid"`
	TTYNr     uint64   `json:"tty_nr"`
	TTY       string   `json:"tty"`
	StartTime uint64   `json:"start_time"`
	Exe       string   `json:"exe"`
	Comm      string   `json:"comm"`
	Context   string   `json:"context,omitempty"` // SELinux context (SO_PEERSEC)
	Type      string   `json:"type,omitempty"`    // the context's type (domain)
	UserNS    string   `json:"user_ns"`
	PidNS     string   `json:"pid_ns"`
	Cgroup    string   `json:"cgroup"`
	Chain     []string `json:"chain"` // "pid name" from the parent up to init
	ChainPIDs []int    `json:"-"`
	// Gone is true when the process exited while it was being read (the
	// pid may have been reused): such a peer is never a person.
	Gone bool `json:"gone,omitempty"`
	// Errors lists /proc reads that failed (for diagnostics).
	Errors []string `json:"errors,omitempty"`
}

// FromConn reads the peer of a Unix connection. SO_PEERCRED and SO_PEERSEC
// are taken by the kernel at connect time; when the kernel supports
// SO_PEERPIDFD the /proc reads are checked against a pidfd so a reused
// pid cannot pass for the peer.
func FromConn(c *net.UnixConn) (Info, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Info{}, err
	}
	var in Info
	var cerr error
	pidfd := -1
	if err := raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			cerr = err
			return
		}
		in.UID, in.PID = int(cred.Uid), int(cred.Pid)
		buf := make([]byte, 256)
		n := uint32(len(buf))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_SOCKET, soPeerSec,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
		if e == 0 && n > 0 && int(n) <= len(buf) {
			in.Context = string(bytes.TrimRight(buf[:n], "\x00"))
		}
		if v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, soPeerPidfd); err == nil {
			pidfd = v
		}
	}); err != nil {
		return Info{}, err
	}
	if cerr != nil {
		return Info{}, cerr
	}
	in.Type = contextType(in.Context)
	if in.PID <= 0 {
		// The peer is in a pid namespace we cannot see into.
		in.Errors = append(in.Errors, "pid not visible from the broker's pid namespace")
		return in, nil
	}
	fill(&in)
	if pidfd >= 0 {
		// Signal 0 through the pidfd fails once the process is gone.
		if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
			in.Gone = true
		}
		_ = unix.Close(pidfd)
	}
	return in, nil
}

// Describe reads what /proc tells about a pid (used for the session's
// foreground process and in tests).
func Describe(pid int) Info {
	in := Info{PID: pid, UID: -1}
	fill(&in)
	return in
}

// procRoot is where procfs is mounted (a variable for tests).
var procRoot = "/proc"

func fill(in *Info) {
	p := filepath.Join(procRoot, strconv.Itoa(in.PID))
	st, err := ReadStat(in.PID)
	if err != nil {
		in.Errors = append(in.Errors, "stat: "+err.Error())
	} else {
		in.PPID, in.PGID, in.SID, in.TTYNr, in.StartTime, in.Comm = st.PPID, st.PGID, st.SID, st.TTYNr, st.StartTime, st.Comm
		in.TTY = TTYName(st.TTYNr)
	}
	if exe, err := os.Readlink(filepath.Join(p, "exe")); err == nil {
		in.Exe = strings.TrimSuffix(exe, " (deleted)")
	} else {
		in.Errors = append(in.Errors, "exe: "+err.Error())
	}
	if ns, err := os.Readlink(filepath.Join(p, "ns", "user")); err == nil {
		in.UserNS = ns
	} else {
		in.Errors = append(in.Errors, "user ns: "+err.Error())
	}
	if ns, err := os.Readlink(filepath.Join(p, "ns", "pid")); err == nil {
		in.PidNS = ns
	} else {
		in.Errors = append(in.Errors, "pid ns: "+err.Error())
	}
	if b, err := os.ReadFile(filepath.Join(p, "cgroup")); err == nil {
		in.Cgroup = parseCgroup(string(b))
	} else {
		in.Errors = append(in.Errors, "cgroup: "+err.Error())
	}
	in.ChainPIDs, in.Chain = ancestry(in.PPID)
}

// Stat is the part of /proc/PID/stat cotty uses.
type Stat struct {
	Comm      string
	State     string
	PPID      int
	PGID      int
	SID       int
	TTYNr     uint64
	TPGID     int
	StartTime uint64
}

// ReadStat parses /proc/PID/stat.
func ReadStat(pid int) (Stat, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return Stat{}, err
	}
	return parseStat(string(b))
}

func parseStat(s string) (Stat, error) {
	// comm is in parentheses and may itself contain spaces and ')'.
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return Stat{}, errors.New("malformed stat")
	}
	f := strings.Fields(s[end+1:])
	// f[0] is field 3 (state).
	if len(f) < 20 {
		return Stat{}, errors.New("short stat")
	}
	atoi := func(x string) int { n, _ := strconv.Atoi(x); return n }
	tty, _ := strconv.ParseInt(f[4], 10, 64)
	start, _ := strconv.ParseUint(f[19], 10, 64)
	return Stat{
		Comm: s[open+1 : end], State: f[0],
		PPID: atoi(f[1]), PGID: atoi(f[2]), SID: atoi(f[3]),
		TTYNr: uint64(uint32(tty)), TPGID: atoi(f[5]), StartTime: start,
	}, nil
}

// TTYName renders a tty_nr as a device name ("pts/3", "tty1", or
// "dev:MAJ:MIN"); "" for no controlling terminal.
func TTYName(nr uint64) string {
	if nr == 0 {
		return ""
	}
	maj, min := unix.Major(nr), unix.Minor(nr)
	switch {
	case maj >= 136 && maj <= 143:
		return fmt.Sprintf("pts/%d", (maj-136)*256+min)
	case maj == 4 && min < 64:
		return fmt.Sprintf("tty%d", min)
	}
	return fmt.Sprintf("dev:%d:%d", maj, min)
}

// parseCgroup returns the cgroup v2 path ("0::/path"), or the first path
// on a v1 system.
func parseCgroup(s string) string {
	first := ""
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			return parts[2]
		}
		if first == "" {
			first = parts[2]
		}
	}
	return first
}

func ancestry(ppid int) ([]int, []string) {
	var pids []int
	var names []string
	for pid, depth := ppid, 0; pid > 0 && depth < 64; depth++ {
		st, err := ReadStat(pid)
		if err != nil {
			break
		}
		pids = append(pids, pid)
		names = append(names, fmt.Sprintf("%d %s", pid, st.Comm))
		if pid == 1 {
			break
		}
		pid = st.PPID
	}
	return pids, names
}

// contextType returns the type field of user:role:type:level.
func contextType(ctx string) string {
	parts := strings.SplitN(ctx, ":", 4)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}
