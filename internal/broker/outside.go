package broker

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/peer"
	"github.com/openbasalt/cotty/internal/proto"
)

// Without the guard (or while its daemon cannot answer), nothing in the
// kernel stops a process outside the session from opening the session pts
// and reading the person's keys: a pinentry-curses that gpg-agent starts
// with GPG_TTY, or any program of the user run with the pts as its
// terminal. The foreground job cannot explain such a reader, so while a
// job runs with echo off and no prompt is detected, the broker looks for
// processes of the user, outside the session, that hold the pts open
// (/proc/PID/fd), and lights the lock for the first one (fail closed: the
// agent's input is held and its view frozen as for any secret prompt).
//
// The scan is bounded like the raw-mode re-check of the foreground group
// (review round 4): a cheap pass reads the /proc directory and only looks
// at the descriptors of processes it has not seen before, or that started
// less than holderYoung ago (a child between fork and the open of the
// pts); a full pass over every process runs at most every
// fullDescribeEvery (a process that opens the pts long after it started).
// Nothing of it runs under b.mu.

// holderYoung is how long after it started a process is looked at again
// on every cheap pass.
const holderYoung = 2 * time.Second

// holderScanner finds processes outside the session that hold the session
// pts open.
type holderScanner struct {
	dev, ino uint64 // the session pts (stat of the slave)
	self     int    // the broker: never a holder
	// anyPath (tests only) looks at descriptors of any path, not only
	// terminals under /dev/pts.
	anyPath bool

	mu     sync.Mutex
	seen   map[int]time.Time // pid -> until when it is young (zero: old)
	fullAt time.Time         // last full pass
}

func newHolderScanner(dev, ino uint64) *holderScanner {
	return &holderScanner{dev: dev, ino: ino, self: os.Getpid(), seen: map[int]time.Time{}}
}

// holder is a process outside the session holding the pts.
type holder struct {
	pid   int
	start uint64
}

// scan looks for a holder. inSession tells whether a pid belongs to the
// session (its processes, their descendants, the broker). wait says the
// caller must have an answer (person input): it waits for a scan under
// way instead of skipping; it never runs the full pass itself, so a key
// does not wait for a walk of every process.
func (h *holderScanner) scan(wait bool, inSession func(pid int) bool) (holder, bool) {
	if wait {
		h.mu.Lock()
	} else if !h.mu.TryLock() {
		return holder{}, false
	}
	defer h.mu.Unlock()
	now := time.Now()
	full := !wait && now.Sub(h.fullAt) >= fullDescribeEvery
	if full {
		h.fullAt = now
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return holder{}, false
	}
	uptime := uptimeTicks()
	live := make(map[int]bool, len(ents))
	var found holder
	ok := false
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		live[pid] = true
		young, known := h.seen[pid]
		if !known {
			young = youngUntil(pid, uptime, now)
			h.seen[pid] = young
		} else if !full && !now.Before(young) {
			continue
		}
		if ok || pid == h.self || !h.holds(pid) || inSession(pid) {
			continue
		}
		st, err := peer.ReadStat(pid)
		if err != nil {
			continue
		}
		found, ok = holder{pid: pid, start: st.StartTime}, true
	}
	for pid := range h.seen {
		if !live[pid] {
			delete(h.seen, pid)
		}
	}
	return found, ok
}

// holds reports whether pid has a descriptor open on the session pts.
// The descriptors of other users' processes (and of non-dumpable ones)
// cannot be read: they are not looked at (another user cannot open the
// pts, which is the user's and mode 0620, group tty, write only).
func (h *holderScanner) holds(pid int) bool {
	dir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, fd := range fds {
		p := filepath.Join(dir, fd.Name())
		target, err := os.Readlink(p)
		if err != nil || !h.candidate(target) {
			continue
		}
		var st unix.Stat_t
		if unix.Stat(p, &st) == nil && uint64(st.Dev) == h.dev && uint64(st.Ino) == h.ino {
			return true
		}
	}
	return false
}

// candidate tells whether a descriptor's link target may be the session
// pts: a terminal under /dev/pts (or, with anyPath, any path); sockets,
// pipes and anonymous inodes are skipped without a stat.
func (h *holderScanner) candidate(target string) bool {
	return strings.HasPrefix(target, "/dev/pts/") || h.anyPath && strings.HasPrefix(target, "/")
}

// inSessionOf returns the session test for scan: a process is the
// session's when it, or one of its ancestors (up to 64 levels), is the
// broker or belongs to the shell's session (a job that left the broker's
// tree when its parent exited keeps the session id).
func inSessionOf(self, sid int) func(pid int) bool {
	return func(pid int) bool {
		for i := 0; i < 64 && pid > 1; i++ {
			if pid == self {
				return true
			}
			st, err := peer.ReadStat(pid)
			if err != nil {
				// Gone, or unreadable: not a holder we can name.
				return true
			}
			if sid > 0 && st.SID == sid {
				return true
			}
			pid = st.PPID
		}
		return false
	}
}

// parentName names the parent of pid for the lock ("" when unknown):
// `LOCK pinentry-curses (exception, for gpg-agent)` tells the person who
// started the program that reads the keys.
func parentName(pid, uid int) string {
	st, err := peer.ReadStat(pid)
	if err != nil || st.PPID <= 0 {
		return ""
	}
	if p := describeProgram(st.PPID, uid); p != nil && p.Name != "" {
		return p.Name
	}
	return ""
}

// sessionAncestorPgids are the process groups of pid's ancestors that are
// in the shell's session (sid): when one of them is a job the agent
// started, so is what it launched outside the session.
func sessionAncestorPgids(pid, sid int) []int {
	var out []int
	for i := 0; i < 64 && pid > 1; i++ {
		st, err := peer.ReadStat(pid)
		if err != nil {
			break
		}
		if sid > 0 && st.SID == sid {
			out = append(out, st.PGID)
		}
		pid = st.PPID
	}
	return out
}

// outsideProgram describes a process outside the session that holds the
// pts for the lock: never trusted as a system prompt (it is not the job
// the person started), marked as outside and named with its parent.
func outsideProgram(pid, uid int) *proto.Program {
	p := describeProgram(pid, uid)
	if p == nil {
		p = &proto.Program{PID: pid}
	}
	p.Trust = proto.TrustOther
	p.SetuidRoot = false
	p.Outside = true
	p.Parent = parentName(pid, uid)
	return p
}

// nestedPIDNamespace reports whether this process runs in a pid namespace
// below the initial one (NSpid in /proc/self/status has more than one
// entry): the guard names processes in its own namespace.
func nestedPIDNamespace() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(l, "NSpid:"); ok {
			return len(strings.Fields(rest)) > 1
		}
	}
	return false
}

// userHZ is the unit of the start times in /proc/PID/stat (USER_HZ, 100
// on every Linux architecture).
const userHZ = 100

// uptimeTicks is the time since boot in USER_HZ ticks (0 when unknown).
func uptimeTicks() uint64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	secs, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	return uint64(secs * userHZ)
}

// youngUntil is when pid stops being young (holderYoung after it
// started); zero when it is already old or its age cannot be read (the
// full pass still looks at it).
func youngUntil(pid int, uptime uint64, now time.Time) time.Time {
	st, err := peer.ReadStat(pid)
	if err != nil || uptime == 0 || st.StartTime > uptime {
		return time.Time{}
	}
	age := time.Duration(uptime-st.StartTime) * time.Second / userHZ
	if age >= holderYoung {
		return time.Time{}
	}
	return now.Add(holderYoung - age)
}
