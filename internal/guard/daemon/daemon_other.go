//go:build !(linux && (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64))

package daemon

import (
	"context"
	"errors"
)

// Options configure the daemon.
type Options struct {
	SocketPath   string
	PinPath      string
	AuditPath    string
	ExtraSockets []string
	Verbose      bool
	CottyPaths   []string
	// ExceptionsPath is the pts exception list.
	ExceptionsPath string
}

// ErrUnsupported is returned when the guard cannot run here.
var ErrUnsupported = errors.New("cotty-guard needs Linux on a little-endian architecture")

// Run always fails here: the BPF object is built for little-endian Linux.
func Run(context.Context, Options) error { return ErrUnsupported }

// Uninstall always fails here.
func Uninstall(string, string) error { return ErrUnsupported }
