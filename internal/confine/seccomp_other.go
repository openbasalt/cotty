//go:build linux && !amd64 && !arm64

package confine

// No filter for this architecture yet: cotty doctor reports it and the
// agent runs without the seccomp layer.
const (
	auditArch = 0
	x32Bit    = 0
)

var archDenied = []uint32{}
