package confine

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The seccomp filter is a small classic BPF program written by hand, so
// cotty needs no C library and the rules stay readable here:
//
//   - wrong architecture: kill (a 32-bit or x32 entry point would bypass
//     the syscall numbers below);
//   - deniedSyscalls: EPERM;
//   - clone3: ENOSYS, so the C library falls back to clone, whose flags
//     a filter can see (clone3 passes them in memory);
//   - clone and unshare with any namespace flag: EPERM (no nested user
//     namespace, no new mount namespace);
//   - ioctl TIOCSTI, TIOCLINUX and TIOCSETD: EPERM (typing into a
//     terminal's input queue, reading a virtual console, changing the
//     line discipline, which loads kernel code paths few programs use);
//   - socket with a family in deniedFamilies: EAFNOSUPPORT.

const (
	seccompRetKillProcess = 0x80000000
	seccompRetErrno       = 0x00050000
	seccompRetAllow       = 0x7fff0000

	// Offsets in struct seccomp_data.
	offNr   = 0
	offArch = 4
	offArg0 = 16 // low 32 bits on little endian
	offArg1 = 24

	nsFlags = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
		unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWTIME
)

// commonDenied are syscalls denied on every architecture.
var commonDenied = []uint32{
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD, unix.SYS_IO_URING_SETUP,
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
	unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSCONFIG,
	unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR, unix.SYS_SETNS,
	unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE,
	unix.SYS_DELETE_MODULE, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_PIDFD_GETFD,
	unix.SYS_PROCESS_MADVISE, unix.SYS_ACCT, unix.SYS_SWAPON, unix.SYS_SWAPOFF,
	unix.SYS_KCMP, unix.SYS_OPEN_TREE_ATTR,
}

// deniedFamilies are socket address families the agent cannot open: the
// kernel crypto API (AF_ALG, a frequent source of kernel bugs) and
// virtual machine sockets (AF_VSOCK, a channel to the host or to VMs).
var deniedFamilies = []uint32{unix.AF_ALG, unix.AF_VSOCK}

// SeccompSupported reports whether this build has a filter for the
// running architecture.
func SeccompSupported() bool { return auditArch != 0 }

// BuildSeccompFilter returns the filter program.
func BuildSeccompFilter() ([]unix.SockFilter, error) {
	if auditArch == 0 {
		return nil, errors.New("no seccomp filter for this architecture")
	}
	stmt := func(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
	jump := func(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
	}
	const (
		ldw  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jge  = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		jset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K
	)
	eperm := seccompRetErrno | uint32(unix.EPERM)
	enosys := seccompRetErrno | uint32(unix.ENOSYS)

	p := []unix.SockFilter{
		stmt(ldw, offArch),
		jump(jeq, auditArch, 1, 0),
		stmt(ret, seccompRetKillProcess),
		stmt(ldw, offNr),
	}
	if x32Bit != 0 {
		// x32 syscalls carry this bit; deny them all.
		p = append(p, jump(jge, x32Bit, 0, 1), stmt(ret, eperm))
	}
	for _, nr := range append(append([]uint32(nil), commonDenied...), archDenied...) {
		p = append(p, jump(jeq, nr, 0, 1), stmt(ret, eperm))
	}
	p = append(p, jump(jeq, unix.SYS_CLONE3, 0, 1), stmt(ret, enosys))
	// clone and unshare: flags in the first argument.
	for _, nr := range []uint32{unix.SYS_CLONE, unix.SYS_UNSHARE} {
		p = append(p,
			jump(jeq, nr, 0, 4),
			stmt(ldw, offArg0),
			jump(jset, nsFlags, 0, 1),
			stmt(ret, eperm),
			stmt(ret, seccompRetAllow),
		)
	}
	// socket: the family is the first argument (an int).
	eafns := seccompRetErrno | uint32(unix.EAFNOSUPPORT)
	p = append(p, jump(jeq, unix.SYS_SOCKET, 0, uint8(3+len(deniedFamilies))), stmt(ldw, offArg0))
	for i, fam := range deniedFamilies {
		p = append(p, jump(jeq, fam, uint8(len(deniedFamilies)-i), 0))
	}
	p = append(p, stmt(ret, seccompRetAllow), stmt(ret, eafns))
	// ioctl: the request number is an unsigned int, so only the low 32
	// bits count (the kernel ignores the rest).
	p = append(p,
		jump(jeq, unix.SYS_IOCTL, 0, 6),
		stmt(ldw, offArg1),
		jump(jeq, unix.TIOCSTI, 3, 0),
		jump(jeq, unix.TIOCLINUX, 2, 0),
		jump(jeq, unix.TIOCSETD, 1, 0),
		stmt(ret, seccompRetAllow),
		stmt(ret, eperm),
		stmt(ret, seccompRetAllow),
	)
	return p, nil
}

// InstallSeccomp loads the filter for every thread of the process. The
// caller must have set no_new_privs.
func InstallSeccomp() error {
	prog, err := BuildSeccompFilter()
	if err != nil {
		return err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	_, _, e := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	if e != 0 {
		// Without TSYNC the filter still covers the calling thread, which
		// is the one that executes the agent.
		_, _, e = unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&fprog)))
		if e != 0 {
			return fmt.Errorf("seccomp: %w", e)
		}
	}
	return nil
}
