//go:build linux

package mask

import (
	"os"
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// liveMappings counts arenas that are still mapped (for tests).
var liveMappings atomic.Int64

// newArena allocates n bytes outside the Go heap with an anonymous private
// mapping, locks it in RAM (no swap) and excludes it from core dumps. All of
// this is best effort: when the mapping or the lock fails (for example
// RLIMIT_MEMLOCK is exhausted) the arena still works, it is just not locked.
func newArena(n int) *arena {
	if n <= 0 {
		return &arena{}
	}
	page := os.Getpagesize()
	size := (n + page - 1) / page * page
	mem, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return &arena{buf: make([]byte, n)}
	}
	a := &arena{buf: mem[:n:n], mapping: mem}
	_ = unix.Madvise(mem, unix.MADV_DONTDUMP)
	if unix.Mlock(mem) == nil {
		a.locked = true
	}
	// An Engine dropped without Close would otherwise leak the mapping
	// (it is not Go heap memory). The cleanup is cancelled by free.
	a.cleanup = runtime.AddCleanup(a, releaseMapping, mem)
	liveMappings.Add(1)
	return a
}

// releaseMapping zeroes, unlocks and unmaps a mapping.
func releaseMapping(mem []byte) {
	liveMappings.Add(-1)
	clear(mem)
	_ = unix.Munlock(mem)
	_ = unix.Munmap(mem)
}

// free zeroes the arena and releases the mapping.
func (a *arena) free() {
	if a == nil {
		return
	}
	if a.mapping != nil {
		a.cleanup.Stop()
		releaseMapping(a.mapping)
	} else {
		clear(a.buf)
	}
	a.buf, a.mapping, a.locked = nil, nil, false
}
