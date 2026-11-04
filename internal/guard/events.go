package guard

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbasalt/cotty/internal/audit"
)

// Hook and reason numbers, mirrored from bpf/guard.bpf.c.
var hookNames = map[uint32]string{
	1:  "ptrace_access_check",
	2:  "file_open",
	3:  "unix_stream_connect",
	4:  "unix_may_send",
	5:  "bprm_creds_from_file",
	6:  "bpf",
	7:  "task_kill",
	8:  "file_ioctl",
	9:  "file_receive",
	10: "inode",
	11: "task_set",
	12: "file_fcntl",
	13: "task_alloc",
}

var reasonNames = map[uint32]string{
	1:  "task of another agent or of the person",
	2:  "/proc file of a task outside the agent",
	3:  "cotty session pts, opened by neither its broker nor the session's own processes",
	4:  "input device",
	5:  "cgroup migration (cgroup.procs or cgroup.threads)",
	6:  "Unix socket not on the agent's allowlist",
	7:  "abstract Unix socket the agent did not create",
	8:  "exec that gains privileges (setuid, setgid, file capabilities)",
	9:  "bpf() syscall",
	10: "terminal input injection (TIOCSTI, TIOCLINUX)",
	11: "cgroup file opened for writing (kill, freeze, limits)",
	12: "change in a guarded directory (the cotty runtime directory or an allowed socket directory)",
	13: "attach to a process of a cotty session from outside it",
	14: "SIGIO owner or signal (F_SETOWN, F_SETSIG, O_ASYNC, FIOSETOWN, SIOCSPGRP, FIOASYNC)",
	15: "the agent's new task could not be tagged",
	16: "change in a cotty runtime directory by a process that is not a registered broker",
	17: "removal or replacement of a session socket another live broker claimed",
	18: "cotty session pts opened by an executable on the exception list (allowed)",
}

// ReasonPTSException is the reason of an allowed exception use (not a
// denial): a listed executable opened a session pts.
const ReasonPTSException = 18

// maxSeen bounds the Dedup map.
const maxSeen = 8192

// Denial is one event from the BPF programs, decoded.
type Denial struct {
	Agent  uint64
	Hook   uint32
	Reason uint32
	PID    uint32
	TGID   uint32
	Target uint32
	Dev    uint64
	Ino    uint64
	Comm   string
	Name   string
	// Allowed: the event reports an access the rules allowed (an
	// exception use), not a denial.
	Allowed bool
	// Exe, for an exception use: the listed path of the executable.
	Exe string
}

// HookName names a hook number.
func HookName(h uint32) string {
	if n, ok := hookNames[h]; ok {
		return n
	}
	return "hook" + strconv.Itoa(int(h))
}

// ReasonText explains a reason number.
func ReasonText(r uint32) string {
	if n, ok := reasonNames[r]; ok {
		return n
	}
	return "reason " + strconv.Itoa(int(r))
}

// Record turns a denial into an audit record (event guard.denial), or an
// exception use into one of event guard.exception.
func (d Denial) Record() audit.Record {
	if d.Allowed {
		return d.exceptionRecord()
	}
	data := map[string]any{
		"source": "cotty-guard",
		"agent":  FormatTag(d.Agent),
		"hook":   HookName(d.Hook),
		"reason": ReasonText(d.Reason),
		"comm":   d.Comm,
		"tid":    d.PID,
	}
	if d.Name != "" {
		data["name"] = d.Name
	}
	if d.Target != 0 {
		if d.Reason == 3 {
			data["broker"] = d.Target
		} else {
			data["target"] = d.Target
		}
	}
	switch d.Hook {
	case 7:
		data["signal"] = d.Ino
	case 8:
		data["ioctl"] = fmt.Sprintf("%#x", d.Ino)
	case 11:
		data["change"] = map[uint64]string{1: "rlimit", 2: "nice", 3: "ioprio", 4: "scheduler"}[d.Ino]
	case 12:
		data["fcntl"] = d.Ino
	default:
		if d.Ino != 0 {
			data["dev"] = fmt.Sprintf("%d:%d", d.Dev>>20, d.Dev&(1<<20-1))
			data["ino"] = d.Ino
		}
	}
	uid := -1
	exe := ""
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", d.TGID)); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "Uid:"); ok {
				if f := strings.Fields(v); len(f) > 0 {
					uid, _ = strconv.Atoi(f[0])
				}
			}
		}
	}
	if l, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", d.TGID)); err == nil {
		exe = strings.TrimSuffix(l, " (deleted)")
	}
	subj := audit.Subject{Role: "agent", PID: int(d.TGID), Exe: exe, Assurance: "strong"}
	if d.Agent == 0 {
		// A process that is not an agent (a protected pts opened from
		// outside the session).
		subj = audit.Subject{Role: "process", PID: int(d.TGID), Exe: exe}
	}
	return audit.Record{UID: uid, Event: audit.GuardDenial, Outcome: "denied", Subject: subj, Data: data}
}

// Dedup drops repeats of the same denial within a window, so a program
// that retries in a loop does not flood the audit log.
type Dedup struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	window time.Duration
	// Dropped counts suppressed repeats.
	Dropped uint64
}

// NewDedup suppresses repeats within window.
func NewDedup(window time.Duration) *Dedup {
	return &Dedup{seen: map[string]time.Time{}, window: window}
}

// Admit reports whether x should be logged (not a recent repeat).
func (d *Dedup) Admit(x Denial, now time.Time) bool {
	key := fmt.Sprintf("%d/%d/%d/%d/%d/%d", x.TGID, x.Hook, x.Reason, x.Target, x.Dev, x.Ino)
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.seen[key]; ok && now.Sub(t) < d.window {
		d.Dropped++
		return false
	}
	if len(d.seen) >= maxSeen {
		for k, t := range d.seen {
			if now.Sub(t) >= d.window {
				delete(d.seen, k)
			}
		}
		if len(d.seen) >= maxSeen {
			// Still full of recent keys (many processes denied at once):
			// start over rather than grow.
			clear(d.seen)
		}
	}
	d.seen[key] = now
	return true
}

// DroppedCount returns the number of repeats suppressed so far.
func (d *Dedup) DroppedCount() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Dropped
}

// exceptionRecord is the audit record of an exception use.
func (d Denial) exceptionRecord() audit.Record {
	data := map[string]any{
		"source": "cotty-guard",
		"reason": ReasonText(d.Reason),
		"comm":   d.Comm,
		"tid":    d.PID,
		"exe":    d.Exe,
		"broker": d.Target,
		"pts":    fmt.Sprintf("%d:%d ino %d", d.Dev>>20, d.Dev&(1<<20-1), d.Ino),
	}
	if d.Name != "" {
		data["name"] = d.Name
	}
	uid := -1
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", d.TGID)); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "Uid:"); ok {
				if f := strings.Fields(v); len(f) > 0 {
					uid, _ = strconv.Atoi(f[0])
				}
			}
		}
	}
	return audit.Record{UID: uid, Event: audit.GuardException, Outcome: "allowed",
		Subject: audit.Subject{Role: "process", PID: int(d.TGID), Exe: d.Exe}, Data: data}
}
