package confine

import (
	"testing"

	"github.com/openbasalt/cotty/internal/peer"
)

// The broker recognises a confined agent by pid 1 of its namespace
// running the init stage (peer.verifyLaunch): the names must agree.
func TestInitStageName(t *testing.T) {
	if StageInit != peer.InitStage {
		t.Fatalf("confine.StageInit %q != peer.InitStage %q", StageInit, peer.InitStage)
	}
}
