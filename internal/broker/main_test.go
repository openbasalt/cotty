package broker

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// sleeperName is the name under which the test binary acts as sleep(1):
// promptCopy copies it there to stand for a listed prompt program.
const sleeperName = "pinentry-tty"

// TestMain lets the test binary, started as sleeperName, sleep for its
// first argument (seconds) and exit, like sleep(1) under any name. A
// copy of the system's sleep does not do that everywhere (the uutils
// multicall binary chooses the utility by its own name).
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == sleeperName {
		secs := 0.0
		if len(os.Args) > 1 {
			secs, _ = strconv.ParseFloat(os.Args[1], 64)
		}
		time.Sleep(time.Duration(secs * float64(time.Second)))
		os.Exit(0)
	}
	os.Exit(m.Run())
}
