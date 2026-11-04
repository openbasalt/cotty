package confine

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_X86_64
	x32Bit    = 0x40000000 // __X32_SYSCALL_BIT
)

// archDenied are amd64-only syscalls: port I/O and the old uselib.
var archDenied = []uint32{unix.SYS_IOPERM, unix.SYS_IOPL, unix.SYS_USELIB}
