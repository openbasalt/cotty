// Command probe is the attack and helper tool of the escape matrix
// (tests/attacks). Attack subcommands try one thing and exit 0 when it
// worked (the confinement was escaped), 1 when it was denied, 2 when the
// attempt does not apply here (skip); they print one line of detail.
// Helper subcommands run outside the confinement and set up targets.
//
// Ideas from basalt-agent's tests/attacks.sh and credattacks.sh
// (basalt-os/basalt-os, packages/basalt-agent, Apache-2.0, same owner).
package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: probe SUBCOMMAND [ARGS]")
		os.Exit(2)
	}
	args := os.Args[2:]
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch os.Args[1] {
	// --- attacks ---
	case "connect":
		connect("unix", arg(0))
	case "connect-abstract":
		connect("unix", "@"+arg(0))
	case "open-read":
		openRead(arg(0))
	case "open-write":
		openWrite(arg(0))
	case "pts-scan":
		ptsScan(arg(0))
	case "own-devpts":
		ownDevpts(arg(0), arg(1))
	case "extra-fds":
		extraFds()
	case "ptrace":
		ptraceAttach(atoi(arg(0)))
	case "ptrace-child":
		ptraceChild()
	case "vm-readv":
		vmReadv(atoi(arg(0)))
	case "vm-readv-child":
		withChild(func(pid int) { vmReadv(pid) })
	case "proc-mem":
		openRead(fmt.Sprintf("/proc/%s/mem", arg(0)))
	case "environ-grep":
		environGrep(arg(0))
	case "kill":
		killPid(atoi(arg(0)))
	case "unshare":
		unshareFlags(arg(0))
	case "clone-userns":
		cloneUserns()
	case "mount-tmpfs":
		mountTmpfs(arg(0))
	case "umount":
		umount(arg(0))
	case "tiocsti":
		tiocsti(arg(0))
	case "core-limit":
		coreLimit()
	case "core-dump":
		coreDump()
	case "keyctl":
		keyctl()
	case "bpf":
		denyCall("bpf", func() error { return rawErr(unix.SYS_BPF, 0, 0, 0) }, unix.EPERM)
	case "perf":
		denyCall("perf_event_open", func() error { return rawErr(unix.SYS_PERF_EVENT_OPEN, 0, 0, 0) }, unix.EPERM)
	case "userfaultfd":
		denyCall("userfaultfd", func() error { return rawErr(unix.SYS_USERFAULTFD, 0, 0, 0) }, unix.EPERM)
	case "io-uring":
		denyCall("io_uring_setup", func() error { return rawErr(unix.SYS_IO_URING_SETUP, 1, 0, 0) }, unix.EPERM)
	case "caps":
		capsHeld()
	case "status":
		statusLine(arg(0), arg(1))
	case "pidns":
		pidns(atoi(arg(0)))
	// --- helpers, run outside ---
	case "listen":
		listen(args)
	case "hold-pty":
		holdPty(arg(0))
	default:
		if brokerCommand(os.Args[1], args) || reviewCommand(os.Args[1], args) || r2Command(os.Args[1], args) || pinentryCommand(os.Args[1], args) {
			return
		}
		fmt.Fprintf(os.Stderr, "unknown subcommand %s\n", os.Args[1])
		os.Exit(2)
	}
}

func escaped(f string, a ...any) {
	fmt.Printf(f+"\n", a...)
	os.Exit(0)
}

func denied(f string, a ...any) {
	fmt.Printf(f+"\n", a...)
	os.Exit(1)
}

func skip(f string, a ...any) {
	fmt.Printf(f+"\n", a...)
	os.Exit(2)
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		skip("bad number %q", s)
	}
	return n
}

func rawErr(trap, a1, a2, a3 uintptr) error {
	_, _, e := unix.Syscall(trap, a1, a2, a3)
	if e != 0 {
		return e
	}
	return nil
}

// denyCall runs a call that must fail with want (the seccomp answer).
func denyCall(name string, call func() error, want syscall.Errno) {
	err := call()
	if errors.Is(err, want) {
		denied("%s: %v", name, err)
	}
	if err == nil {
		escaped("%s succeeded", name)
	}
	// Another error means the call reached the kernel's own checks.
	escaped("%s reached the kernel (%v), not blocked by the filter", name, err)
}

func connect(network, addr string) {
	if addr == "" || addr == "@" {
		skip("no address")
	}
	c, err := net.DialTimeout(network, addr, 3*time.Second)
	if err != nil {
		denied("connect %s: %v", addr, err)
	}
	c.Close()
	escaped("connected to %s", addr)
}

func openRead(p string) {
	f, err := os.Open(p)
	if err != nil {
		denied("open %s: %v", p, err)
	}
	defer f.Close()
	buf := make([]byte, 64)
	if _, err := f.Read(buf); err != nil && !errors.Is(err, os.ErrClosed) {
		if fi, _ := f.Stat(); fi != nil && fi.IsDir() {
			escaped("opened directory %s", p)
		}
		denied("read %s: %v", p, err)
	}
	escaped("read %s", p)
}

func openWrite(p string) {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		denied("open for writing %s: %v", p, err)
	}
	f.Close()
	escaped("opened %s for writing", p)
}

// ptsScan tries every pts other than the agent's own (own).
func ptsScan(own string) {
	var opened []string
	for i := 0; i < 256; i++ {
		p := fmt.Sprintf("/dev/pts/%d", i)
		if p == own {
			continue
		}
		fd, err := unix.Open(p, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
		if err == nil {
			unix.Close(fd)
			opened = append(opened, p)
		}
	}
	if len(opened) > 0 {
		escaped("opened %v (own %s)", opened, own)
	}
	denied("no pts but the own one (%s) can be opened", own)
}

// ownDevpts compares the devpts instance of the controlling terminal with
// the device id the runner recorded outside for the person's pty.
func ownDevpts(outsideDev, own string) {
	if !strings.HasPrefix(own, "/dev/pts/") {
		skip("no controlling terminal")
	}
	var st unix.Stat_t
	if err := unix.Stat(own, &st); err != nil {
		skip("stat %s: %v", own, err)
	}
	if strconv.FormatUint(st.Dev, 10) == outsideDev {
		escaped("the agent's pts is in the person's devpts instance (dev %d)", st.Dev)
	}
	denied("the agent's pts %s is in a private devpts instance (dev %d, outside %s)", own, st.Dev, outsideDev)
}

// extraFds lists descriptors above stdio.
func extraFds() {
	d, err := os.Open("/proc/self/fd")
	if err != nil {
		skip("%v", err)
	}
	names, _ := d.Readdirnames(-1)
	own := int(d.Fd())
	var extra []string
	for _, n := range names {
		fd, _ := strconv.Atoi(n)
		if fd > 2 && fd != own {
			t, _ := os.Readlink("/proc/self/fd/" + n)
			extra = append(extra, n+"->"+t)
		}
	}
	d.Close()
	// The Go runtime of this probe holds its own epoll and eventfd; those
	// are anon inodes, not inherited files. A pipe is counted: the
	// runtime makes none on Linux, so one here was inherited (a pipe to a
	// process outside is a channel out of the confinement).
	var inherited []string
	for _, e := range extra {
		if !strings.Contains(e, "anon_inode:") {
			inherited = append(inherited, e)
		}
	}
	if len(inherited) > 0 {
		escaped("inherited descriptors: %v", inherited)
	}
	denied("only stdio inherited (runtime: %v)", extra)
}

func ptraceAttach(pid int) {
	err := unix.PtraceAttach(pid)
	if err == nil {
		// Detach only works once the tracee is in its attach stop; detaching
		// earlier fails and leaves it stopped when the probe exits (the
		// session shell would stop reading its input for the rest of the
		// run).
		var ws unix.WaitStatus
		_, _ = unix.Wait4(pid, &ws, unix.WALL, nil)
		_ = unix.PtraceDetach(pid)
		escaped("attached to %d", pid)
	}
	denied("ptrace attach %d: %v", pid, err)
}

// withChild runs f with the pid of a child process that sleeps.
func withChild(f func(pid int)) {
	c := exec.Command("sleep", "30")
	if err := c.Start(); err != nil {
		skip("cannot start a child: %v", err)
	}
	defer func() { _ = c.Process.Kill() }()
	time.Sleep(100 * time.Millisecond)
	f(c.Process.Pid)
}

func ptraceChild() {
	withChild(func(pid int) {
		err := unix.PtraceAttach(pid)
		if err == nil {
			_ = unix.PtraceDetach(pid)
			escaped("attached to own child %d", pid)
		}
		if errors.Is(err, unix.EPERM) {
			denied("ptrace own child: %v (seccomp)", err)
		}
		escaped("ptrace own child reached the kernel: %v", err)
	})
}

func vmReadv(pid int) {
	addr := uintptr(0x400000)
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid)); err == nil {
		if line, _, ok := strings.Cut(string(b), "\n"); ok {
			if a, _, ok := strings.Cut(line, "-"); ok {
				if v, err := strconv.ParseUint(a, 16, 64); err == nil {
					addr = uintptr(v)
				}
			}
		}
	}
	buf := make([]byte, 16)
	local := []unix.Iovec{{Base: &buf[0], Len: 16}}
	remote := []unix.RemoteIovec{{Base: addr, Len: 16}}
	n, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err == nil && n > 0 {
		escaped("read %d bytes of %d", n, pid)
	}
	denied("process_vm_readv %d: %v", pid, err)
}

func environGrep(marker string) {
	m, _ := filepath.Glob("/proc/[0-9]*/environ")
	for _, f := range m {
		b, err := os.ReadFile(f)
		if err == nil && strings.Contains(string(b), marker) {
			escaped("marker found in %s", f)
		}
	}
	denied("marker in no visible environ (%d processes visible)", len(m))
}

func killPid(pid int) {
	err := unix.Kill(pid, 0)
	if err == nil {
		escaped("signal 0 delivered to %d", pid)
	}
	denied("kill -0 %d: %v", pid, err)
}

func unshareFlags(which string) {
	flags := map[string]int{"user": unix.CLONE_NEWUSER, "mount": unix.CLONE_NEWNS, "net": unix.CLONE_NEWNET, "pid": unix.CLONE_NEWPID}[which]
	if flags == 0 {
		skip("unknown namespace %q", which)
	}
	err := unix.Unshare(flags)
	if err == nil {
		escaped("unshare %s succeeded", which)
	}
	denied("unshare %s: %v", which, err)
}

func cloneUserns() {
	c := exec.Command("/bin/true")
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if err := c.Run(); err != nil {
		denied("clone(CLONE_NEWUSER): %v", err)
	}
	escaped("started a process in a new user namespace")
}

func mountTmpfs(target string) {
	_ = os.MkdirAll(target, 0o755)
	err := unix.Mount("tmpfs", target, "tmpfs", 0, "")
	if err == nil {
		_ = unix.Unmount(target, 0)
		escaped("mounted a tmpfs on %s", target)
	}
	denied("mount: %v", err)
}

func umount(target string) {
	err := unix.Unmount(target, unix.MNT_DETACH)
	if err == nil {
		escaped("unmounted %s", target)
	}
	denied("umount %s: %v", target, err)
}

func tiocsti(path string) {
	fd := 0
	if path != "" {
		var err error
		fd, err = unix.Open(path, unix.O_RDWR|unix.O_NOCTTY, 0)
		if err != nil {
			denied("open %s: %v", path, err)
		}
	}
	c := byte(' ')
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCSTI, uintptr(unsafe.Pointer(&c)))
	if e == 0 {
		escaped("TIOCSTI pushed a byte into the terminal")
	}
	denied("TIOCSTI: %v", e)
}

func coreLimit() {
	err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	if err == nil {
		escaped("raised RLIMIT_CORE to unlimited")
	}
	var r unix.Rlimit
	_ = unix.Getrlimit(unix.RLIMIT_CORE, &r)
	if r.Max != 0 {
		escaped("RLIMIT_CORE hard limit is %d", r.Max)
	}
	denied("RLIMIT_CORE stays 0 (%v)", err)
}

// coreDump crashes a child in the current directory and looks for a core
// file.
func coreDump() {
	c := exec.Command("sh", "-c", "ulimit -c unlimited 2>/dev/null; kill -SEGV $$")
	_ = c.Run()
	time.Sleep(500 * time.Millisecond)
	m, _ := filepath.Glob("core*")
	if len(m) > 0 {
		escaped("core file written: %v", m)
	}
	denied("no core file after a crash (%v)", c.ProcessState)
}

func keyctl() {
	const keyctlGetKeyringID = 0
	const keySpecUserKeyring = ^uintptr(3) // -4
	_, _, e := unix.Syscall(unix.SYS_KEYCTL, keyctlGetKeyringID, keySpecUserKeyring, 0)
	if e == unix.EPERM {
		denied("keyctl: %v", e)
	}
	if e == 0 {
		escaped("keyctl reached the user keyring")
	}
	escaped("keyctl reached the kernel: %v", e)
}

func capsHeld() {
	b, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(l, ":")
		if (k == "CapEff" || k == "CapPrm" || k == "CapBnd" || k == "CapAmb") && strings.Trim(strings.TrimSpace(v), "0") != "" {
			escaped("%s is %s", k, strings.TrimSpace(v))
		}
	}
	denied("no capabilities held")
}

// statusLine checks /proc/self/status KEY == VALUE; "denied" when equal
// (the protection is on).
func statusLine(key, want string) {
	f, _ := os.Open("/proc/self/status")
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), ":")
		if k == key {
			v = strings.TrimSpace(v)
			if v == want {
				denied("%s: %s", key, v)
			}
			escaped("%s: %s, want %s", key, v, want)
		}
	}
	escaped("%s missing", key)
}

// pidns checks that the outside pid is invisible and few processes show.
func pidns(outside int) {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", outside)); err == nil {
		escaped("outside pid %d is visible", outside)
	}
	m, _ := filepath.Glob("/proc/[0-9]*")
	if len(m) > 50 {
		escaped("%d processes visible", len(m))
	}
	denied("%d processes visible, outside pid %d is not", len(m), outside)
}

// listen (outside) listens on pathname sockets and abstract names (@name)
// and logs every connection to the file given with --log.
func listen(args []string) {
	if len(args) < 2 || args[0] != "--log" {
		fmt.Fprintln(os.Stderr, "usage: probe listen --log FILE ADDR...")
		os.Exit(2)
	}
	logf, err := os.OpenFile(args[1], os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, a := range args[2:] {
		if !strings.HasPrefix(a, "@") {
			_ = os.MkdirAll(filepath.Dir(a), 0o700)
			_ = os.Remove(a)
		}
		l, err := net.Listen("unix", a)
		if err != nil {
			fmt.Fprintf(os.Stderr, "listen %s: %v\n", a, err)
			os.Exit(2)
		}
		go func(a string, l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				fmt.Fprintf(logf, "%s connection on %s\n", time.Now().Format(time.RFC3339), a)
				c.Close()
			}
		}(a, l)
	}
	fmt.Println("ready")
	select {}
}

// holdPty (outside) opens a pty pair, writes the slave path and its
// devpts device id to FILE, and keeps both open: it stands for the
// person's terminal.
func holdPty(file string) {
	m, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	_ = unix.IoctlSetPointerInt(m, unix.TIOCSPTLCK, 0)
	n, err := unix.IoctlGetInt(m, unix.TIOCGPTN)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	p := fmt.Sprintf("/dev/pts/%d", n)
	s, err := unix.Open(p, unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var st unix.Stat_t
	_ = unix.Fstat(s, &st)
	_ = os.WriteFile(file, []byte(fmt.Sprintf("PERSON_PTS=%s\nPERSON_PTS_DEV=%d\n", p, st.Dev)), 0o600)
	for {
		time.Sleep(time.Hour)
	}
}
