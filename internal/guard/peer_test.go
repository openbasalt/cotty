package guard_test

import (
	"github.com/openbasalt/cotty/internal/guard"
	"github.com/openbasalt/cotty/internal/peer"
)

// The broker uses *guard.Guard as its peer.Guard.
var _ peer.Guard = (*guard.Guard)(nil)

// The broker's per-session guard is a peer.Guard too.
var _ peer.Guard = (*guard.Session)(nil)
