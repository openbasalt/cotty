//go:build linux && (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64)

package daemon

import (
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/guard"
)

// excAnyGen in exe_val.flags (EXC_ANY_GEN): match device and inode only.
const excAnyGen = 1

// exceptionsPath is the configured list (Options.ExceptionsPath, or the
// default).
func (d *daemon) exceptionsPath() string {
	if d.opts.ExceptionsPath != "" {
		return d.opts.ExceptionsPath
	}
	return guard.ExceptionsPath
}

// loadExceptions reads the exception list again and brings the
// pts_exceptions map in line with it: at start, on SIGHUP and on every
// tick (a package upgrade gives the listed file a new inode). Every
// change, and every refusal, is logged once.
func (d *daemon) loadExceptions() {
	path := d.exceptionsPath()
	var want []exceptionExe
	var notes []string
	paths, problems, err := readExceptionsFile(path, 0)
	switch {
	case errors.Is(err, errNoExceptions):
		notes = append(notes, fmt.Sprintf("no pts exception list at %s (no exception applies)", path))
	case err != nil:
		notes = append(notes, err.Error())
	default:
		for _, p := range problems {
			notes = append(notes, fmt.Sprintf("%s: %s", path, p))
		}
		for _, p := range paths {
			e, err := resolveException(p, 0)
			if err != nil {
				notes = append(notes, fmt.Sprintf("%s: exception %s skipped: %v", path, p, err))
				continue
			}
			want = append(want, e)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	keep := map[guardbpfExeKey]guardbpfExeVal{}
	for _, e := range want {
		k := guardbpfExeKey{Dev: e.KDev, Ino: e.Ino}
		v := guardbpfExeVal{Gen: e.Gen}
		if e.AnyGen {
			v.Flags = excAnyGen
		}
		keep[k] = v
	}
	var k guardbpfExeKey
	var v guardbpfExeVal
	var stale []guardbpfExeKey
	it := d.maps.PtsExceptions.Iterate()
	for it.Next(&k, &v) {
		if _, ok := keep[k]; !ok {
			stale = append(stale, k)
		}
	}
	for _, s := range stale {
		_ = d.maps.PtsExceptions.Delete(s)
	}
	for k, v := range keep {
		if err := d.maps.PtsExceptions.Update(k, v, ebpf.UpdateAny); err != nil {
			notes = append(notes, fmt.Sprintf("exception dev %d:%d ino %d: %v", k.Dev>>20, k.Dev&(1<<20-1), k.Ino, err))
		}
	}
	summary := "pts exceptions: none"
	if len(want) > 0 {
		var parts []string
		for _, e := range want {
			s := e.Path
			if e.Real != e.Path {
				s += " -> " + e.Real
			}
			gen := fmt.Sprintf("generation %d", e.Gen)
			if e.AnyGen {
				gen = "no generation"
			}
			parts = append(parts, fmt.Sprintf("%s (dev %d:%d ino %d, %s)", s, e.KDev>>20, e.KDev&(1<<20-1), e.Ino, gen))
		}
		summary = "pts exceptions: " + strings.Join(parts, ", ")
	}
	if summary != d.excSummary || !slices.Equal(notes, d.excNotes) {
		for _, n := range notes {
			log.Printf("cotty-guard: %s", n)
		}
		log.Printf("cotty-guard: %s", summary)
	}
	d.exceptions, d.excSummary, d.excNotes = want, summary, notes
}

// clearExceptions empties the pts_exceptions map (the daemon stops): no
// exception applies until the next start loads the list again.
func (d *daemon) clearExceptions() {
	d.mu.Lock()
	defer d.mu.Unlock()
	var k guardbpfExeKey
	var v guardbpfExeVal
	var all []guardbpfExeKey
	it := d.maps.PtsExceptions.Iterate()
	for it.Next(&k, &v) {
		all = append(all, k)
	}
	for _, x := range all {
		_ = d.maps.PtsExceptions.Delete(x)
	}
	if len(all) > 0 {
		log.Printf("cotty-guard: stopping: the pts exception list no longer applies (%d entries removed)", len(all))
	}
	d.exceptions, d.excSummary, d.excNotes = nil, "", nil
}

// exceptionPathLocked names a listed executable by its kernel device and
// inode ("" when it is no longer listed).
func (d *daemon) exceptionPathLocked(dev, ino uint64) string {
	for _, e := range d.exceptions {
		if e.KDev == dev && e.Ino == ino {
			return e.Path
		}
	}
	return ""
}

// exceptionList is the list for status.
func (d *daemon) exceptionListLocked() []string {
	out := make([]string, 0, len(d.exceptions))
	for _, e := range d.exceptions {
		out = append(out, e.Path)
	}
	return out
}

// exceptionUse is the recorded exception use of a pts (kernel key), when
// its process still runs.
func (d *daemon) exceptionUse(k guardbpfFileKey) *guard.ExceptionUse {
	var u guardbpfExcUse
	if d.maps.PtsExcUses.Lookup(k, &u) != nil || u.Tgid == 0 {
		return nil
	}
	if !ownerAlive(guardbpfPtsOwner{Tgid: u.Tgid, Start: u.Start}) {
		return nil
	}
	d.mu.Lock()
	exe := d.exceptionPathLocked(u.ExeDev, u.ExeIno)
	d.mu.Unlock()
	return &guard.ExceptionUse{PID: int(u.Tgid), Start: u.Start, Exe: exe}
}

// exceptionUseAny names the executable of the recorded exception use of a
// pts, whether or not its process still runs ("" when unknown).
func (d *daemon) exceptionUseAny(k guardbpfFileKey) string {
	var u guardbpfExcUse
	if d.maps.PtsExcUses.Lookup(k, &u) != nil {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.exceptionPathLocked(u.ExeDev, u.ExeIno)
}

// ptsException answers pts-exception: the caller must be the process that
// protected the pts (its broker).
func (d *daemon) ptsException(c caller, fd int) guard.Response {
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &sfs); err != nil {
		return fail("%v", err)
	}
	if sfs.Type != unix.DEVPTS_SUPER_MAGIC {
		return fail("not a devpts terminal")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fail("%v", err)
	}
	start, err := startTicks(c.pid)
	if err != nil {
		return fail("caller: %v", err)
	}
	if err := alive(c.pidfd); err != nil {
		return fail("%v", err)
	}
	k := guardbpfFileKey{Dev: guard.KernelDev(st.Dev), Ino: st.Ino}
	var cur guardbpfPtsOwner
	if d.maps.ProtectedFiles.Lookup(k, &cur) != nil || cur.Tgid != uint32(c.pid) || cur.Start != start {
		return fail("the terminal is not protected for this process")
	}
	return guard.Response{OK: true, Exception: d.exceptionUse(k)}
}

// logException writes the log line of an exception use (the audit record
// is written by readEvents).
func logException(den guard.Denial) {
	exe := den.Exe
	if exe == "" {
		exe = "an executable no longer listed"
	}
	log.Printf("cotty-guard: exception used: pid %d (%s) running %s opened the session pts %s (dev %d:%d ino %d) of broker %d",
		den.TGID, den.Comm, exe, den.Name, den.Dev>>20, den.Dev&(1<<20-1), den.Ino, den.Target)
}
