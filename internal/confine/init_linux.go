package confine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// RunInit is the init stage (pid 1 of the agent's pid namespace). It never
// returns.
func RunInit() {
	// One thread does the work and forks the exec stage, so a fallback
	// that drops capabilities on this thread alone still covers the child.
	runtime.LockOSThread()
	// Nothing in the namespace may read this process's memory or fds.
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	specFile := os.NewFile(3, "spec")
	var sp Spec
	if err := json.NewDecoder(specFile).Decode(&sp); err != nil {
		initFail("spec: %v", err)
	}
	specFile.Close()
	var sock *os.File
	if sp.PTY {
		sock = os.NewFile(4, "pty-sock")
		unix.CloseOnExec(4)
	}

	if err := setupMounts(&sp); err != nil {
		initFail("%v (if this is Ubuntu, run `cotty doctor`: AppArmor may restrict user namespaces)", err)
	}

	var stdio []uintptr
	if sp.PTY {
		master, slave, err := openPTY()
		if err != nil {
			initFail("pty: %v", err)
		}
		if err := unix.Sendmsg(int(sock.Fd()), []byte{0}, unix.UnixRights(master), nil, 0); err != nil {
			initFail("pty: %v", err)
		}
		unix.Close(master)
		// Wait for the launcher to set the window size.
		ack := make([]byte, 1)
		_, _ = sock.Read(ack)
		sock.Close()
		stdio = []uintptr{uintptr(slave), uintptr(slave), uintptr(slave)}
		defer unix.Close(slave)
	} else {
		stdio = []uintptr{0, 1, 2}
	}

	if err := dropAllCaps(); err != nil {
		initFail("dropping capabilities: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		initFail("%v", err)
	}
	pid, err := syscall.ForkExec("/proc/self/exe", []string{"cotty", StageExec}, &syscall.ProcAttr{
		Dir:   "/",
		Env:   []string{},
		Files: append(stdio, r.Fd()),
		Sys:   &syscall.SysProcAttr{Setsid: true, Setctty: sp.PTY, Ctty: 0},
	})
	if err != nil {
		initFail("start: %v", err)
	}
	r.Close()
	if err := json.NewEncoder(w).Encode(&sp); err != nil {
		initFail("spec: %v", err)
	}
	w.Close()

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for s := range sigs {
			_ = unix.Kill(-pid, s.(syscall.Signal))
		}
	}()

	// Reap everything; leave with the agent's status. The kernel kills the
	// rest of the namespace when pid 1 exits.
	for {
		var ws unix.WaitStatus
		wp, err := unix.Wait4(-1, &ws, 0, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			os.Exit(1)
		}
		if wp == pid {
			if ws.Signaled() {
				os.Exit(128 + int(ws.Signal()))
			}
			os.Exit(ws.ExitStatus())
		}
	}
}

func initFail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "cotty agent: init: "+f+"\n", a...)
	os.Exit(125)
}

type clonedMount struct {
	fd       int
	target   string
	dir      bool
	noFollow bool
}

// setupMounts builds the agent's view of the filesystem.
func setupMounts(sp *Spec) error {
	// Slave propagation, as bubblewrap does: nothing done here propagates
	// back to the person's mounts (mount and unmount events still flow in
	// from outside, onto the original mount points, which stay covered
	// where they are hidden).
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_SLAVE, ""); err != nil {
		return fmt.Errorf("make / a slave mount: %w", err)
	}

	// 1. Detached copies of everything that stays visible, taken before
	// anything is covered.
	var clones []clonedMount
	for _, b := range sp.Binds {
		fd, err := unix.OpenTree(unix.AT_FDCWD, b.Source, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_RECURSIVE)
		if err != nil {
			return fmt.Errorf("bind %s: %w", b.Source, err)
		}
		if !b.RW {
			if err := setReadOnly(fd); err != nil {
				return fmt.Errorf("read-only %s: %w", b.Source, err)
			}
		}
		clones = append(clones, clonedMount{fd: fd, target: b.Target, dir: b.Dir, noFollow: b.NoFollow})
	}
	var devs []clonedMount
	for _, d := range sp.Devices {
		src := filepath.Join("/dev", d)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		fd, err := unix.OpenTree(unix.AT_FDCWD, src, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
		if err != nil {
			return fmt.Errorf("device %s: %w", src, err)
		}
		devs = append(devs, clonedMount{fd: fd, target: src})
	}

	// 2. Cover what the agent must not see.
	for _, h := range sp.Hide {
		if !isDir(h) {
			continue
		}
		mode := "0755"
		switch h {
		case "/tmp", "/var/tmp":
			mode = "1777"
		case sp.Home, sp.RuntimeDir:
			mode = "0700"
		}
		if err := unix.Mount("tmpfs", h, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode="+mode); err != nil {
			return fmt.Errorf("tmpfs on %s: %w", h, err)
		}
	}

	// 3. A private /dev: a few device nodes, a new devpts instance (so no
	// other terminal is visible), its own /dev/shm.
	if err := unix.Mount("tmpfs", "/dev", "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=0755"); err != nil {
		return fmt.Errorf("tmpfs on /dev: %w", err)
	}
	for _, d := range devs {
		if err := placeMount(d); err != nil {
			return err
		}
	}
	if err := os.Mkdir("/dev/pts", 0o755); err != nil {
		return err
	}
	if err := unix.Mount("devpts", "/dev/pts", "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return fmt.Errorf("devpts: %w", err)
	}
	for name, target := range map[string]string{
		"/dev/ptmx": "pts/ptmx", "/dev/fd": "/proc/self/fd", "/dev/stdin": "/proc/self/fd/0",
		"/dev/stdout": "/proc/self/fd/1", "/dev/stderr": "/proc/self/fd/2",
	} {
		if err := os.Symlink(target, name); err != nil {
			return err
		}
	}
	if err := os.Mkdir("/dev/shm", 0o1777); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", "/dev/shm", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777"); err != nil {
		return fmt.Errorf("tmpfs on /dev/shm: %w", err)
	}
	// POSIX message queues of the agent's own ipc namespace (optional).
	if os.Mkdir("/dev/mqueue", 0o755) == nil {
		_ = unix.Mount("mqueue", "/dev/mqueue", "mqueue", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
	}

	// 4. /proc of the new pid namespace: only the agent's processes.
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("proc: %w", err)
	}

	// 5. The cgroup tree seen from the agent's cgroup namespace: its own
	// cgroup is the root, nothing above it exists.
	if isDir("/sys/fs/cgroup") {
		if err := unix.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC|unix.MS_RDONLY, ""); err != nil {
			if err := unix.Mount("tmpfs", "/sys/fs/cgroup", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC|unix.MS_RDONLY, "mode=0555"); err != nil {
				return fmt.Errorf("cover /sys/fs/cgroup: %w", err)
			}
		}
	}

	// 6. The runtime directory and its cotty directory (the binary and the
	// agent endpoint directory) exist, private (mode 0700), even when the
	// person has none or it was under a covered directory. The cotty
	// directory is a tmpfs of its own, read-only once its mount points are
	// in place, so the agent cannot rename it and put a fake endpoint
	// directory or binary where its own tools look.
	cottyDir := filepath.Dir(filepath.Dir(sp.SelfBin))
	if err := os.MkdirAll(cottyDir, 0o700); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", cottyDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0700,size=64k"); err != nil {
		return fmt.Errorf("tmpfs on %s: %w", cottyDir, err)
	}
	// 7. Put back what stays visible, parents first.
	for _, c := range clones {
		if err := placeMount(c); err != nil {
			return err
		}
	}
	// 7b. Socket directories a bind of a parent brought back (the copies
	// were taken before step 2) are covered again.
	for _, h := range sp.Rehide {
		if !isDir(h) {
			continue
		}
		if err := unix.Mount("tmpfs", h, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
			return fmt.Errorf("tmpfs on %s: %w", h, err)
		}
	}
	if err := unix.Mount("", cottyDir, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("read-only %s: %w", cottyDir, err)
	}
	// 8. Launcher links of the profile's programs.
	for _, l := range sp.Links {
		if err := os.MkdirAll(filepath.Dir(l.Path), 0o755); err != nil {
			return err
		}
		if err := os.Symlink(l.Target, l.Path); err != nil && !os.IsExist(err) {
			return fmt.Errorf("link %s: %w", l.Path, err)
		}
	}
	// 8b. Profile directories the agent sees empty (home.hide), after the
	// links, failing closed: a hide that cannot be put in place is a
	// refused start, not a visible directory (review round 4).
	for _, h := range sp.HideDirs {
		if err := noLinkOnPath(h, true); err != nil {
			return fmt.Errorf("hide %s: %w", h, err)
		}
		if fi, err := os.Lstat(h); err != nil || !fi.IsDir() {
			return fmt.Errorf("hide %s: not a directory inside", h)
		}
		if err := unix.Mount("tmpfs", h, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0700"); err != nil {
			return fmt.Errorf("tmpfs on %s: %w", h, err)
		}
	}
	// The working directory of this stage was taken before the mounts and
	// may point into a covered directory.
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	return nil
}

// placeMount attaches a detached mount at its target, creating the
// target (and its parents) when missing.
func placeMount(c clonedMount) error {
	if c.noFollow {
		// The directories on the way are made below, and a link among them
		// would move the mount elsewhere (where it protects nothing).
		if err := noLinkOnPath(filepath.Dir(c.target), false); err != nil {
			return fmt.Errorf("mount %s: %w", c.target, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(c.target), 0o755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", c.target, err)
	}
	if _, err := os.Lstat(c.target); errors.Is(err, os.ErrNotExist) {
		if c.dir {
			err = os.Mkdir(c.target, 0o700)
		} else {
			var f *os.File
			if f, err = os.OpenFile(c.target, os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				f.Close()
			}
		}
		if err != nil {
			return fmt.Errorf("create %s: %w", c.target, err)
		}
	}
	if err := unix.MoveMount(c.fd, "", unix.AT_FDCWD, c.target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("mount %s: %w", c.target, err)
	}
	unix.Close(c.fd)
	return nil
}

// noLinkOnPath fails when a component of the absolute path p is a
// symbolic link. Missing components are fine unless mustExist.
func noLinkOnPath(p string, mustExist bool) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s is not an absolute path", p)
	}
	cur := "/"
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(p), "/"), "/") {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) && !mustExist {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link; refusing to follow it", cur)
		}
	}
	return nil
}

// setReadOnly makes a detached mount tree read-only.
func setReadOnly(fd int) error {
	attr := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}
	return unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH|unix.AT_RECURSIVE, &attr)
}

// openPTY allocates a pty in the namespace's own devpts instance.
func openPTY() (master, slave int, err error) {
	master, err = unix.Open("/dev/pts/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, -1, err
	}
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		unix.Close(master)
		return -1, -1, err
	}
	// TIOCGPTPEER takes the open flags of the slave as its argument.
	r, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(master), unix.TIOCGPTPEER, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC)
	slave, err = int(r), nil
	if e != 0 {
		err = e
		// Older kernels: open the slave by number.
		n, err2 := unix.IoctlGetInt(master, unix.TIOCGPTN)
		if err2 != nil {
			unix.Close(master)
			return -1, -1, err
		}
		slave, err = unix.Open("/dev/pts/"+strconv.Itoa(n), unix.O_RDWR|unix.O_NOCTTY, 0)
		if err != nil {
			unix.Close(master)
			return -1, -1, err
		}
	}
	return master, slave, nil
}

// dropAllCaps empties the bounding, ambient, inheritable, permitted and
// effective sets on every thread, so nothing started from here holds a
// capability in the agent's user namespace (which would let it undo the
// mounts above). The exec stage checks the result again.
func dropAllCaps() error {
	last := 40
	if b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap"); err == nil {
		if n, err := strconv.Atoi(string(trimNL(b))); err == nil {
			last = n
		}
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	// AllThreadsSyscall needs a binary built without cgo; with cgo it
	// returns ENOTSUP and the calling thread (locked, the one that forks
	// the exec stage) is dropped alone.
	all := true
	sys := func(trap, a1, a2, a3 uintptr) syscall.Errno {
		if all {
			_, _, e := syscall.AllThreadsSyscall(trap, a1, a2, a3)
			if e == syscall.ENOTSUP {
				all = false
			} else {
				return e
			}
		}
		_, _, e := syscall.RawSyscall(trap, a1, a2, a3)
		return e
	}
	for c := 0; c <= last; c++ {
		if e := sys(syscall.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(c), 0); e != 0 && e != unix.EINVAL {
			return fmt.Errorf("bounding set: %w", e)
		}
	}
	if e := sys(syscall.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0); e != 0 {
		return fmt.Errorf("ambient set: %w", e)
	}
	if e := sys(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return fmt.Errorf("capset: %w", e)
	}
	return nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
