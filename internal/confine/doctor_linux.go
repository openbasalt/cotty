package confine

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Check is one line of `cotty doctor`.
type Check struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // ok, warn, fail, info
	Value   string `json:"value"`
	Explain string `json:"explain"`
}

// Report is the whole `cotty doctor` result.
type Report struct {
	Checks    []Check  `json:"checks"`
	Assurance string   `json:"assurance"` // layer 2 alone: what `cotty agent` reports
	Gaps      []string `json:"gaps"`
	// Sessions is the level a session created now can reach, with the
	// guard (layer 3) and the binary check counted; SessionsNote explains
	// it. Both are filled by the command, not by Doctor.
	Sessions     string `json:"sessions,omitempty"`
	SessionsNote string `json:"sessions_note,omitempty"`
}

// Assess turns what the launcher can use into an assurance level for
// agents started with `cotty agent`: confined (every layer 2 piece),
// partial (namespaces work, some other piece is missing: see gaps) or
// unavailable (no user namespaces: cotty agent refuses to start).
func Assess(f Features, userns bool) (string, []string) {
	if !userns {
		return "unavailable", []string{"unprivileged user namespaces are not available, so the agent's view of files, sockets and terminals cannot be built"}
	}
	var gaps []string
	partial := false
	switch {
	case f.LandlockABI == 0:
		partial = true
		gaps = append(gaps, "no Landlock: only the mount view limits files, and abstract Unix sockets (X11's @/tmp/.X11-unix) and signals to outside processes are not scoped")
	case f.LandlockABI < 6:
		partial = true
		gaps = append(gaps, fmt.Sprintf("Landlock ABI %d (< 6): abstract Unix sockets (X11's @/tmp/.X11-unix, abstract D-Bus addresses) are reachable from the agent; cotty agent refuses to start while one of those listens, unless given --allow-abstract-sockets", f.LandlockABI))
	}
	if f.LandlockABI < 9 {
		gaps = append(gaps, "Landlock ABI below 9: pathname Unix sockets are kept out only by the mount view (/run, /tmp, $XDG_RUNTIME_DIR and known socket directories under /var, /nix and /opt are hidden); a socket in a directory that stays visible (the project, a --ro or --rw path, a system directory cotty does not know about) can be connected to")
	}
	gaps = append(gaps, "the agent shares your network namespace: it can reach any TCP or UDP service you can, including services listening on localhost (databases, dev servers, a browser's debugging port)")
	if !f.Seccomp {
		partial = true
		gaps = append(gaps, "no seccomp filter for this CPU architecture: ptrace inside the agent, nested namespaces and TIOCSTI are not blocked by cotty")
	}
	if f.Cgroup == "" {
		partial = true
		gaps = append(gaps, "no cgroup of its own: the broker cannot tell the agent's processes apart by cgroup")
	}
	if partial {
		return "partial", gaps
	}
	return "confined", gaps
}

// Doctor inspects the system.
func Doctor() Report {
	var r Report
	add := func(name, status, value, explain string) {
		r.Checks = append(r.Checks, Check{name, status, value, explain})
	}

	var un unix.Utsname
	_ = unix.Uname(&un)
	add("kernel", "info", unix.ByteSliceToString(un.Release[:])+" "+unix.ByteSliceToString(un.Machine[:]), "")

	abi := LandlockABI()
	switch {
	case abi == 0:
		add("landlock", "fail", "absent", "Landlock is not built into this kernel or not in the lsm= boot list. cotty agent still hides files with namespaces, but nothing restricts the agent inside that view and X11's abstract socket stays reachable.")
	case abi < 6:
		ex := "Landlock restricts files, but ABI 6 (Linux 6.12) is needed to keep the agent away from abstract Unix sockets (X11) and from signalling your other processes."
		if risky := abstractSocketsAtRisk(); len(risky) > 0 {
			ex += " These listen now, so cotty agent refuses to start unless given --allow-abstract-sockets: " + strings.Join(risky, ", ") + "."
		}
		add("landlock", "warn", "ABI "+strconv.Itoa(abi), ex)
	case abi < 9:
		add("landlock", "warn", "ABI "+strconv.Itoa(abi), "Files, abstract Unix sockets and signals are restricted. Pathname Unix sockets are kept out only by the agent's mount view, which hides /run, /tmp, $XDG_RUNTIME_DIR and known socket directories under /var, /nix and /opt (D-Bus, ssh-agent, systemd, docker, incus, MySQL, the nix daemon); a socket in a directory that stays visible (the project, a --ro or --rw path, a system directory cotty does not know about) can be connected to. ABI 9 (Linux 7.1) closes that with a Landlock check.")
	default:
		add("landlock", "ok", "ABI "+strconv.Itoa(abi), "Files, abstract and pathname Unix sockets and signals are all restricted by Landlock, on top of the private mount view.")
	}

	lsm := strings.TrimSpace(readFile("/sys/kernel/security/lsm"))
	if lsm == "" {
		add("lsm", "info", "unknown", "/sys/kernel/security/lsm is not readable.")
	} else {
		ex := "Active Linux security modules."
		if !strings.Contains(","+lsm+",", ",bpf,") {
			ex += " bpf is not in the list, so the optional cotty-guard (layer 3) cannot run here."
		} else {
			ex += " bpf is present, so the optional cotty-guard (layer 3) can run here."
		}
		add("lsm", "info", lsm, ex)
	}

	switch v := strings.TrimSpace(readFile("/proc/sys/kernel/yama/ptrace_scope")); v {
	case "":
		add("yama", "warn", "absent", "Yama is not active: any of your processes may ptrace any other. The agent itself is blocked (own pid namespace, seccomp), but other programs you run are not.")
	case "0":
		add("yama", "warn", "ptrace_scope 0", "Any of your processes may ptrace any other. The agent is blocked by its pid namespace and seccomp; consider ptrace_scope 1 (the default on Ubuntu and on Fedora Workstation; Fedora Cloud images ship 0).")
	default:
		add("yama", "ok", "ptrace_scope "+v, "Only a parent may ptrace its children.")
	}

	switch v := strings.TrimSpace(readFile("/proc/sys/dev/tty/legacy_tiocsti")); v {
	case "0":
		add("tiocsti", "ok", "legacy_tiocsti 0", "No program can push characters into a terminal's input queue.")
	case "1":
		add("tiocsti", "warn", "legacy_tiocsti 1", "Programs can push characters into the input of their terminal. The agent is blocked by seccomp and has its own pty; other programs are not.")
	default:
		add("tiocsti", "info", "no switch", "This kernel has no legacy_tiocsti switch (before Linux 6.2): TIOCSTI works for every program. cotty's seccomp filter blocks it for the agent.")
	}

	usernsOK, usernsMsg := probeUserns()
	usernsDetail := []string{}
	if v := strings.TrimSpace(readFile("/proc/sys/user/max_user_namespaces")); v != "" {
		usernsDetail = append(usernsDetail, "max_user_namespaces "+v)
	}
	if v := strings.TrimSpace(readFile("/proc/sys/kernel/unprivileged_userns_clone")); v != "" {
		usernsDetail = append(usernsDetail, "unprivileged_userns_clone "+v)
	}
	aaRestrict := strings.TrimSpace(readFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"))
	if aaRestrict != "" {
		usernsDetail = append(usernsDetail, "apparmor_restrict_unprivileged_userns "+aaRestrict)
	}
	if usernsOK {
		add("userns", "ok", strings.Join(usernsDetail, ", "), "Unprivileged user namespaces work: cotty agent can give the agent its own view of files, processes, terminals and sockets.")
	} else {
		ex := "cotty agent needs unprivileged user, mount and pid namespaces and cannot start an agent here (" + usernsMsg + ")."
		if aaRestrict == "1" {
			ex += " Ubuntu 24.04 and later allow them only to programs with an AppArmor profile: install the one shipped with cotty (dist/apparmor/cotty) to /etc/apparmor.d/ and load it with `sudo apparmor_parser -r /etc/apparmor.d/cotty`."
		}
		if strings.Contains(strings.Join(usernsDetail, " "), "unprivileged_userns_clone 0") {
			ex += " Debian's kernel.unprivileged_userns_clone is 0."
		}
		add("userns", "fail", strings.Join(usernsDetail, ", "), ex)
	}

	seccompOK := SeccompSupported() && strings.Contains(readFile("/proc/self/status"), "Seccomp:")
	if seccompOK {
		add("seccomp", "ok", "filter for "+unix.ByteSliceToString(un.Machine[:]), "ptrace, process_vm_*, bpf, perf_event_open, userfaultfd, io_uring, mount, nested namespaces, kernel keyrings and TIOCSTI/TIOCLINUX are denied to the agent.")
	} else {
		add("seccomp", "warn", "unavailable", "cotty has no seccomp filter for this architecture or the kernel lacks seccomp; the other layers still apply.")
	}

	cg, cgStatus, cgExplain := cgroupState()
	add("cgroup", cgStatus, cg, cgExplain)

	display, dStatus, dExplain := displayState()
	add("display", dStatus, display, dExplain)

	f := Features{LandlockABI: abi, Seccomp: seccompOK}
	if cgStatus == "ok" {
		f.Cgroup = "ok"
	}
	r.Assurance, r.Gaps = Assess(f, usernsOK)
	return r
}

func readFile(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

// probeUserns starts the probe stage in the same namespaces the agent
// gets and has it do the same kinds of mounts.
func probeUserns() (bool, string) {
	cmd := exec.Command("/proc/self/exe", StageProbe)
	uid, gid := os.Getuid(), os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWCGROUP,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP},
		Pdeathsig:   syscall.SIGKILL,
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			msg = err.Error()
		}
		return false, msg
	}
	return true, ""
}

// RunUsernsProbe is the probe stage: the mounts cotty agent needs, on
// throwaway targets. It exits 0 when they all work.
func RunUsernsProbe() {
	step := func(what string, err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
			os.Exit(1)
		}
	}
	step("make / private", unix.Mount("", "/", "", unix.MS_REC|unix.MS_SLAVE, ""))
	fd, err := unix.OpenTree(unix.AT_FDCWD, "/etc", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_RECURSIVE)
	step("open_tree", err)
	step("mount_setattr", setReadOnly(fd))
	step("tmpfs", unix.Mount("tmpfs", "/tmp", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777"))
	step("mkdir", os.Mkdir("/tmp/pts", 0o755))
	step("devpts", unix.Mount("devpts", "/tmp/pts", "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"))
	step("mkdir", os.Mkdir("/tmp/etc", 0o755))
	step("move_mount", unix.MoveMount(fd, "", unix.AT_FDCWD, "/tmp/etc", unix.MOVE_MOUNT_F_EMPTY_PATH))
	step("proc", unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""))
	os.Exit(0)
}

func cgroupState() (string, string, string) {
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &st); err != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		return "no cgroup v2", "warn", "cgroup v2 is not mounted at /sys/fs/cgroup: the agent gets no cgroup of its own."
	}
	cur := currentCgroup()
	if sr, err := systemTool("systemd-run"); err == nil && os.Getenv("XDG_RUNTIME_DIR") != "" {
		if probeScope(sr) == nil {
			return "systemd user scope", "ok", "Each agent gets its own systemd user scope (cotty-agent-*.scope), created before it is confined. Your current cgroup is " + cur + "."
		}
	}
	dir := filepath.Join("/sys/fs/cgroup", cur)
	if unix.Access(dir, unix.W_OK) == nil && strings.TrimSpace(readFile(filepath.Join(dir, "cgroup.subtree_control"))) == "" {
		return "delegated " + cur, "ok", "No systemd user manager answers; cotty agent creates a child of your current cgroup instead."
	}
	return cur, "warn", "No systemd user manager and the current cgroup is not delegated to you: agents run without a cgroup of their own."
}

func displayState() (string, string, string) {
	st := os.Getenv("XDG_SESSION_TYPE")
	d, w := os.Getenv("DISPLAY"), os.Getenv("WAYLAND_DISPLAY")
	switch {
	case st == "x11" || (d != "" && w == ""):
		return "x11", "warn", "X11: every X client of yours can read the keystrokes of every window, including the terminal where you type passwords. cotty agent keeps the agent away from X (no /tmp/.X11-unix, abstract socket scoped by Landlock), but other programs you run can still do it; Wayland does not allow this."
	case st == "wayland" || w != "":
		if d != "" {
			return "wayland (with Xwayland)", "ok", "Wayland isolates windows from each other. X11 programs under Xwayland can read each other's input, but not that of Wayland windows; the agent cannot reach either display."
		}
		return "wayland", "ok", "Wayland isolates windows from each other; the agent cannot reach the display."
	default:
		return "none", "info", "No graphical session in this environment."
	}
}
