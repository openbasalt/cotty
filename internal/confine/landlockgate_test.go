package confine

import (
	"errors"
	"testing"
)

// Review COT-4: no Landlock at all is a refused start unless the person
// accepted it, and the exec stage never ignores a failed Landlock
// otherwise.
func TestLandlockGate(t *testing.T) {
	if landlockGate(0, false) == nil {
		t.Error("ABI 0 accepted without --allow-no-landlock")
	}
	if landlockGate(0, true) != nil || landlockGate(1, false) != nil {
		t.Error("refused a start that should go on")
	}
	fail := errors.New("landlock is not available")
	if landlockApplied(0, fail, false) == nil {
		t.Error("exec stage went on without Landlock and without the launcher's consent")
	}
	if landlockApplied(0, fail, true) != nil {
		t.Error("exec stage refused an accepted run without Landlock")
	}
	if landlockApplied(3, fail, true) == nil {
		t.Error("a Landlock failure on a kernel that has it was ignored")
	}
	if landlockApplied(6, nil, false) != nil {
		t.Error("success refused")
	}
}
