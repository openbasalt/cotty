package broker

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/openbasalt/cotty/internal/peer"
	"github.com/openbasalt/cotty/internal/proto"
)

// memberStarts returns the start time of every described member (0 when
// it could not be read, which the next re-check takes for a change).
func memberStarts(members []*proto.Program) map[int]uint64 {
	out := make(map[int]uint64, len(members))
	for _, m := range members {
		if m == nil || m.PID <= 0 {
			continue
		}
		if st, err := peer.ReadStat(m.PID); err == nil {
			out[m.PID] = st.StartTime
		}
	}
	return out
}

// jobUnchanged reports whether the foreground group pgid still is what
// its last description saw, reading a few /proc files per member instead
// of walking all of /proc: every member is alive (same start time), still
// in the group, runs the same executable under the same name (an exec
// changes them), and no child of a member has joined the group without
// being described (a fork). Anything unreadable or unusual counts as a
// change, so the caller describes the group again.
func jobUnchanged(pgid int, members []*proto.Program, starts map[int]uint64) bool {
	if len(members) == 0 || len(members) > maxJobMembers {
		return false
	}
	in := make(map[int]bool, len(members))
	for _, m := range members {
		if m == nil || m.PID <= 0 {
			return false
		}
		in[m.PID] = true
	}
	for _, m := range members {
		st, err := peer.ReadStat(m.PID)
		if err != nil || st.PGID != pgid || st.StartTime != starts[m.PID] || starts[m.PID] == 0 {
			return false
		}
		name, exe := st.Comm, ""
		if l, err := os.Readlink("/proc/" + strconv.Itoa(m.PID) + "/exe"); err == nil {
			exe = strings.TrimSuffix(l, " (deleted)")
			name = programName(filepath.Base(exe), st.Comm)
		}
		if name != m.Name || exe != m.Exe {
			return false
		}
		kids, ok := childrenOf(m.PID)
		if !ok {
			return false
		}
		for _, k := range kids {
			if in[k] {
				continue
			}
			// A child in another group (a shell's background job) is not a
			// member; one that cannot be read is taken for a new member.
			if ks, err := peer.ReadStat(k); err != nil || ks.PGID == pgid {
				return false
			}
		}
	}
	return true
}

// childrenOf lists the children of a process, from the children lists of
// its threads. ok is false when the lists cannot be read.
func childrenOf(pid int) ([]int, bool) {
	base := "/proc/" + strconv.Itoa(pid) + "/task"
	tasks, err := os.ReadDir(base)
	if err != nil {
		return nil, false
	}
	var out []int
	for _, t := range tasks {
		b, err := os.ReadFile(base + "/" + t.Name() + "/children")
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // the thread ended
			}
			return nil, false
		}
		for _, f := range strings.Fields(string(b)) {
			if k, err := strconv.Atoi(f); err == nil && k > 0 {
				out = append(out, k)
			}
		}
	}
	return out, true
}

// liveMembers drops the members that have ended (gone or a zombie) or
// whose pid now belongs to another process (a different start time). A
// member whose state cannot be read for another reason is kept: while a
// prompt is detected, a failed read must not unlock.
func liveMembers(members []*proto.Program, starts map[int]uint64) []*proto.Program {
	out := make([]*proto.Program, 0, len(members))
	for _, m := range members {
		if m == nil || m.PID <= 0 {
			out = append(out, m)
			continue
		}
		st, err := peer.ReadStat(m.PID)
		switch {
		case err != nil && errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			out = append(out, m)
		case st.State == "Z" || st.State == "X":
			continue
		case starts[m.PID] != 0 && st.StartTime != starts[m.PID]:
			continue
		default:
			out = append(out, m)
		}
	}
	return out
}

// procWalks counts full descriptions of a foreground group (each walks
// all of /proc); tests read it to check the idle cost.
var procWalks atomic.Uint64

// describeGroup is describeJob, counted.
func describeGroup(pgid, sid, uid int) (*proto.Program, []*proto.Program) {
	procWalks.Add(1)
	return describeJob(pgid, sid, uid)
}
