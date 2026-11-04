package confine

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// runBPF evaluates a classic BPF seccomp program on one seccomp_data.
func runBPF(t *testing.T, prog []unix.SockFilter, nr int32, arch uint32, args [6]uint64) uint32 {
	t.Helper()
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:], uint32(nr))
	binary.LittleEndian.PutUint32(data[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[16+8*i:], a)
	}
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if acc == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			if acc >= in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if acc&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		default:
			t.Fatalf("unknown instruction %#x at %d", in.Code, pc)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

func TestSeccompFilter(t *testing.T) {
	if !SeccompSupported() {
		t.Skip("no filter for this architecture")
	}
	prog, err := BuildSeccompFilter()
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) > 4096 {
		t.Fatalf("program too long: %d", len(prog))
	}
	eperm := uint32(seccompRetErrno | uint32(unix.EPERM))
	enosys := uint32(seccompRetErrno | uint32(unix.ENOSYS))
	a := uint32(auditArch)
	cases := []struct {
		name string
		nr   int32
		arch uint32
		args [6]uint64
		want uint32
	}{
		{"read", unix.SYS_READ, a, [6]uint64{}, seccompRetAllow},
		{"wrong arch", unix.SYS_READ, 0x40000003, [6]uint64{}, seccompRetKillProcess},
		{"ptrace", unix.SYS_PTRACE, a, [6]uint64{}, eperm},
		{"process_vm_readv", unix.SYS_PROCESS_VM_READV, a, [6]uint64{}, eperm},
		{"bpf", unix.SYS_BPF, a, [6]uint64{}, eperm},
		{"mount", unix.SYS_MOUNT, a, [6]uint64{}, eperm},
		{"setns", unix.SYS_SETNS, a, [6]uint64{}, eperm},
		{"keyctl", unix.SYS_KEYCTL, a, [6]uint64{}, eperm},
		{"io_uring_setup", unix.SYS_IO_URING_SETUP, a, [6]uint64{}, eperm},
		{"clone3", unix.SYS_CLONE3, a, [6]uint64{}, enosys},
		{"clone fork", unix.SYS_CLONE, a, [6]uint64{uint64(unix.SIGCHLD)}, seccompRetAllow},
		{"clone thread", unix.SYS_CLONE, a, [6]uint64{unix.CLONE_VM | unix.CLONE_THREAD | unix.CLONE_SIGHAND}, seccompRetAllow},
		{"clone newuser", unix.SYS_CLONE, a, [6]uint64{unix.CLONE_NEWUSER | uint64(unix.SIGCHLD)}, eperm},
		{"clone newns", unix.SYS_CLONE, a, [6]uint64{unix.CLONE_NEWNS}, eperm},
		{"unshare files", unix.SYS_UNSHARE, a, [6]uint64{unix.CLONE_FILES}, seccompRetAllow},
		{"unshare newuser", unix.SYS_UNSHARE, a, [6]uint64{unix.CLONE_NEWUSER}, eperm},
		{"unshare newtime", unix.SYS_UNSHARE, a, [6]uint64{unix.CLONE_NEWTIME}, eperm},
		{"ioctl tcgets", unix.SYS_IOCTL, a, [6]uint64{0, unix.TCGETS}, seccompRetAllow},
		{"ioctl tiocsti", unix.SYS_IOCTL, a, [6]uint64{0, unix.TIOCSTI}, eperm},
		{"ioctl tiocsti high bits", unix.SYS_IOCTL, a, [6]uint64{0, 0xffffffff00000000 | unix.TIOCSTI}, eperm},
		{"ioctl tioclinux", unix.SYS_IOCTL, a, [6]uint64{0, unix.TIOCLINUX}, eperm},
		{"ioctl tiocsetd", unix.SYS_IOCTL, a, [6]uint64{0, unix.TIOCSETD}, eperm},
		{"kcmp", unix.SYS_KCMP, a, [6]uint64{}, eperm},
		{"open_tree_attr", unix.SYS_OPEN_TREE_ATTR, a, [6]uint64{}, eperm},
		{"socket inet", unix.SYS_SOCKET, a, [6]uint64{unix.AF_INET}, seccompRetAllow},
		{"socket unix", unix.SYS_SOCKET, a, [6]uint64{unix.AF_UNIX}, seccompRetAllow},
		{"socket alg", unix.SYS_SOCKET, a, [6]uint64{unix.AF_ALG}, seccompRetErrno | uint32(unix.EAFNOSUPPORT)},
		{"socket vsock", unix.SYS_SOCKET, a, [6]uint64{unix.AF_VSOCK}, seccompRetErrno | uint32(unix.EAFNOSUPPORT)},
		{"write", unix.SYS_WRITE, a, [6]uint64{}, seccompRetAllow},
	}
	if x32Bit != 0 {
		cases = append(cases, struct {
			name string
			nr   int32
			arch uint32
			args [6]uint64
			want uint32
		}{"x32 read", int32(x32Bit), a, [6]uint64{}, eperm})
	}
	for _, c := range cases {
		if got := runBPF(t, prog, c.nr, c.arch, c.args); got != c.want {
			t.Errorf("%s: got %#x, want %#x", c.name, got, c.want)
		}
	}
}
