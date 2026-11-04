package confine

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_AARCH64
	x32Bit    = 0
)

var archDenied = []uint32{}
