//go:build cgo && !race

package main

// cotty must be built with CGO_ENABLED=0 (see the Makefile): the agent
// launcher drops capabilities on every thread with
// syscall.AllThreadsSyscall, which a cgo binary cannot do, and the binary
// must not depend on the C library of the build host. This reference to
// an undefined name stops a cgo build here, with this explanation next to
// it. Race detector builds (which need cgo) are exempt.
var _ = cotty_must_be_built_with_CGO_ENABLED_0
