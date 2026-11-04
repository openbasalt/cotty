// Package harden holds process-level hardening for the broker and the
// attach client, the two processes that hold unmasked terminal data and
// what the person types.
//
// Provenance: the prctl pattern comes from basalt-shell internal/harden
// (github.com/basalt-os/basalt-shell, commit 47b7463), same owner,
// Apache-2.0. no_new_privs is deliberately not set here: the session's
// shell must be able to run sudo.
package harden

import (
	"golang.org/x/sys/unix"
)

// Process makes the calling process non-dumpable (no core dumps, no
// ptrace or /proc/PID/mem by other processes of the same uid, /proc/PID
// files owned by root) and sets RLIMIT_CORE to 0, which every child
// inherits (the session shell and its commands: a core dump of a program
// holding a password must not land on disk).
func Process() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

// Dumpable reports the current PR_GET_DUMPABLE value (for tests and
// cotty doctor).
func Dumpable() (int, error) {
	r, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	return r, err
}

// Wipe overwrites a buffer that held person input in secret mode, so the
// bytes do not linger in the heap until the garbage collector reuses it.
func Wipe(b []byte) {
	clear(b)
}
