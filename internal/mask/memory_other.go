//go:build !linux

package mask

// newArena falls back to the Go heap where no locked mapping is available.
// cotty targets Linux; this keeps the package buildable elsewhere.
func newArena(n int) *arena {
	return &arena{buf: make([]byte, max(n, 0))}
}

// free zeroes the arena.
func (a *arena) free() {
	if a == nil {
		return
	}
	clear(a.buf)
	a.buf = nil
}
