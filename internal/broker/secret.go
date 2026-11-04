package broker

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/peer"
	"github.com/openbasalt/cotty/internal/proto"
)

// ttyState is what the broker reads from the PTY master: the slave's
// termios (TCGETS on a Linux pty master returns the slave's settings) and
// the foreground process group.
type ttyState struct {
	ok     bool
	echo   bool
	icanon bool
	pgid   int
}

// readTTY polls the PTY. The kernel sends no notification of termios
// changes (packet mode reports flow control only), so this runs before
// each batch of person input, on every output chunk and on a timer.
func readTTY(fd int) ttyState {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return ttyState{}
	}
	st := ttyState{ok: true, echo: t.Lflag&unix.ECHO != 0, icanon: t.Lflag&unix.ICANON != 0}
	if pg, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP); err == nil {
		st.pgid = pg
	}
	return st
}

// DefaultSecretPrograms are raw mode programs that read secrets (matched
// by executable base name). ICANON is off while they read, so the termios
// rule alone does not see them.
var DefaultSecretPrograms = []string{"pinentry-curses", "pinentry-tty", "pinentry"}

// LoadSecretPrograms returns the default list plus the lines of
// ~/.config/cotty/secret-programs (one name or absolute path per line, #
// comments). Adding a program only makes detection stricter, so the file
// needs no protection.
func LoadSecretPrograms() []string {
	list := append([]string(nil), DefaultSecretPrograms...)
	cfg, err := os.UserConfigDir()
	if err != nil {
		return list
	}
	f, err := os.Open(filepath.Join(cfg, "cotty", "secret-programs"))
	if err != nil {
		return list
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			list = append(list, l)
		}
	}
	return list
}

// isSecret applies the detection rule: ECHO off with ICANON on (getpass,
// sudo, ssh, passwd, read -s); or ECHO off in raw mode when a member of
// the foreground process group is on the secret program list, or is a
// setuid-root process that has started no child process. The last one is
// a password prompt read in raw mode: sudo-rs (Ubuntu 26.04's sudo) reads
// it that way and prints a mark per key. Once sudo has run the command it
// relays its own terminal for it in raw mode too, but then it has a child
// (`sudo vim`, `sudo -i`), and the command, not sudo, reads the keys.
// Setuid root is the kernel's word (the user cannot make a root-owned
// setuid binary), so a renamed program cannot pass for it; the lock still
// judges and names every member.
func isSecret(st ttyState, members []*proto.Program, list []string) bool {
	if !st.ok || st.echo {
		return false
	}
	if st.icanon {
		return true
	}
	for _, prog := range members {
		if prog != nil && prog.SetuidRoot && !hasChildren(prog.PID) {
			return true
		}
	}
	for _, prog := range members {
		if prog == nil {
			continue
		}
		for _, p := range list {
			// Name is the executable's base name, possibly followed by the
			// name it was started under ("pinentry-curses (as pinentry)").
			if p == prog.Name || p == prog.Exe || (prog.Exe != "" && p == filepath.Base(prog.Exe)) ||
				strings.HasSuffix(prog.Name, " (as "+p+")") {
				return true
			}
		}
	}
	return false
}

// procStarted reports whether process pid runs and started at start
// (clock ticks since boot, /proc/PID/stat field 22), so a reused pid does
// not count.
func procStarted(pid int, start uint64) bool {
	st, err := peer.ReadStat(pid)
	return err == nil && st.StartTime == start
}

// hasChildren reports whether a process has a child, from the children
// lists of its threads (readable for any process). Unreadable means no
// (the prompt rule then fails toward secret).
func hasChildren(pid int) bool {
	if pid <= 0 {
		return false
	}
	base := "/proc/" + strconv.Itoa(pid) + "/task"
	tasks, err := os.ReadDir(base)
	if err != nil {
		return false
	}
	for _, t := range tasks {
		b, err := os.ReadFile(base + "/" + t.Name() + "/children")
		if err == nil && len(strings.TrimSpace(string(b))) > 0 {
			return true
		}
	}
	return false
}

// interpreters run whatever script they are given, so a prompt from one
// (a shell's read -s, python's getpass) gets the amber lock even though
// the binary is a root-owned system file.
var interpreters = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "fish": true, "dash": true, "ksh": true, "mksh": true,
	"tcsh": true, "csh": true, "busybox": true, "python": true, "python3": true, "perl": true,
	"ruby": true, "node": true, "nodejs": true, "lua": true, "php": true, "tclsh": true,
	"expect": true, "awk": true, "gawk": true, "env": true,
}

func isInterpreter(name string) bool {
	if interpreters[name] {
		return true
	}
	// python3.13, perl5.40 and similar versioned names.
	for _, p := range []string{"python", "perl", "ruby", "lua", "php", "node"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// systemDirs are where a green-lock program must live.
var systemDirs = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/", "/usr/lib/"}

// describeJob describes the foreground process group as the lock must
// judge it: the process that reads the password may be any member, not
// only the group leader (`sudo -n sleep 600 | python3 fake.py` has a
// trusted leader and an interpreter reading the terminal, review B6). It
// returns one description for the job and the description of every
// member. The job is trusted (green) only when every member is; its name
// lists the members when there are several ("sleep | python3"), and its
// exe is the first untrusted member's.
func describeJob(pgid, sid, uid int) (*proto.Program, []*proto.Program) {
	if pgid <= 0 {
		return nil, nil
	}
	members := groupMembers(pgid, sid, uid)
	if len(members) == 0 {
		p := describeProgram(pgid, uid)
		return p, []*proto.Program{p}
	}
	if len(members) == 1 {
		p := *members[0]
		return &p, members
	}
	job := &proto.Program{PID: pgid, Trust: proto.TrustSystem}
	names := make([]string, 0, len(members))
	leader := members[0]
	for _, m := range members {
		names = append(names, m.Name)
		if m.PID == pgid {
			leader = m
		}
		if m.Trust != proto.TrustSystem && job.Trust == proto.TrustSystem {
			job.Trust = proto.TrustOther
			job.Exe = m.Exe
		}
	}
	if job.Exe == "" {
		job.Exe = leader.Exe
	}
	job.Name = strings.Join(names, " | ")
	job.Pipeline = names
	return job, members
}

// maxJobMembers bounds how many members of a process group are described.
const maxJobMembers = 64

// groupMembers lists the processes of process group pgid in kernel session
// sid (0: any), in pid order (the order a shell starts a pipeline in).
func groupMembers(pgid, sid, uid int) []*proto.Program {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		st, err := peer.ReadStat(pid)
		if err != nil || st.PGID != pgid || (sid > 0 && st.SID != sid) {
			continue
		}
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	var out []*proto.Program
	for _, pid := range pids {
		if len(out) >= maxJobMembers {
			// Too many to judge: one untrusted entry keeps the lock amber.
			out = append(out, &proto.Program{PID: pid, Name: "...", Trust: proto.TrustOther})
			break
		}
		out = append(out, describeProgram(pid, uid))
	}
	return out
}

// describeProgram names one process and decides its lock colour. A
// process whose effective uid is root while its real uid is the user's
// was started from a setuid-root binary (sudo, su, passwd): its exe link
// is unreadable to the user, and it is trusted (green). Otherwise the
// executable must be a root-owned file in a system directory that the
// user cannot write and not an interpreter (green); anything else is
// amber.
//
// The name shown is the base name of the executable that was judged, not
// the process's comm: comm is the base name of the path given to execve,
// so `ln -s /usr/bin/head /tmp/sudo; /tmp/sudo` would show a green "sudo"
// for head reading the password (review N3). When comm differs, both are
// shown: "head (as sudo)". A setuid-root process's exe cannot be read, so
// its name is its comm; it is a root process reading the terminal either
// way.
func describeProgram(pid, uid int) *proto.Program {
	if pid <= 0 {
		return nil
	}
	st, err := peer.ReadStat(pid)
	if err != nil {
		return &proto.Program{PID: pid, Trust: proto.TrustOther}
	}
	p := &proto.Program{PID: pid, Name: st.Comm, Trust: proto.TrustOther}
	ruid, euid := statusUIDs(pid)
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err == nil {
		p.Exe = strings.TrimSuffix(exe, " (deleted)")
		p.Name = programName(filepath.Base(p.Exe), st.Comm)
	}
	switch {
	case euid == 0 && ruid == uid && uid != 0:
		p.Trust = proto.TrustSystem
		p.SetuidRoot = true
	case p.Exe != "" && inSystemDir(p.Exe) && !isInterpreter(filepath.Base(p.Exe)) && !isInterpreter(st.Comm):
		if ok, _ := peer.ExeTrust(p.Exe, uid); ok {
			p.Trust = proto.TrustSystem
		}
	}
	return p
}

// commLen is the longest comm the kernel keeps (TASK_COMM_LEN - 1).
const commLen = 15

// programName is the name shown for a process: the executable's base
// name, followed by the name it was started under when that differs
// (comm is cut to 15 bytes, so a longer base name whose start matches is
// the same name).
func programName(base, comm string) string {
	if comm == "" || comm == base || len(comm) == commLen && strings.HasPrefix(base, comm) {
		return base
	}
	return base + " (as " + comm + ")"
}

func inSystemDir(path string) bool {
	for _, d := range systemDirs {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

// statusUIDs returns the real and effective uid from /proc/PID/status.
func statusUIDs(pid int) (int, int) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return -1, -1
	}
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(l, "Uid:"); ok {
			f := strings.Fields(rest)
			if len(f) >= 2 {
				r, _ := strconv.Atoi(f[0])
				e, _ := strconv.Atoi(f[1])
				return r, e
			}
		}
	}
	return -1, -1
}
