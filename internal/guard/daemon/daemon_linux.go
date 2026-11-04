//go:build linux && (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64)

package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/audit"
	"github.com/openbasalt/cotty/internal/guard"
	"github.com/openbasalt/cotty/internal/session"
)

// Options configure the daemon.
type Options struct {
	SocketPath string
	PinPath    string
	AuditPath  string
	// ExtraSockets are pathname sockets (or directories of them) every
	// agent may connect to, besides the system ones.
	ExtraSockets []string
	// Verbose logs every denial to stderr (the journal) too.
	Verbose bool
	// CottyPaths are the paths a registered broker's executable may have
	// (DefaultCottyPaths when empty).
	CottyPaths []string
	// ExceptionsPath is the pts exception list (guard.ExceptionsPath
	// when empty).
	ExceptionsPath string
}

// systemSockets are the system service sockets every agent may reach:
// the same list `cotty agent` keeps visible (internal/confine/plan.go).
var systemSockets = []string{"/run/systemd/resolve", "/run/systemd/userdb", "/run/systemd/journal", "/dev/log", "/run/nscd", "/var/run/nscd", "/var/lib/sss/pipes"}

// ErrUnsupported is returned when the kernel cannot run the guard; the
// daemon then exits cleanly.
var ErrUnsupported = errors.New("the kernel cannot run cotty-guard")

const cgroupRoot = "/sys/fs/cgroup"

type registration struct {
	id    uint64
	path  string // cgroup v2 path, relative to cgroupRoot
	level int    // depth in the cgroup tree (the root is 0)
	uid   uint32
	when  time.Time
}

// guard_state slots and allowed_socks values, as in bpf/guard.bpf.c.
const (
	stateAgents    = 0
	stateLevels    = 1
	stateDropped   = 2
	stateHeartbeat = 3

	sockConnect = 1
	dirGuarded  = 2
	dirBrokers  = 4

	maxCgroupLevel = 63

	// evAllowed in event.extra: an access the rules allowed (EV_ALLOWED).
	evAllowed = 1
)

// optionalPrograms are attached only where the kernel has the hook.
var optionalPrograms = map[string]string{
	"cotty_file_ioctl_compat": "file_ioctl_compat",
}

type daemon struct {
	opts    Options
	facts   guard.Facts
	coll    *ebpf.Collection
	maps    guardbpfMaps
	links   map[string]link.Link
	audit   *audit.Log
	dedup   *guard.Dedup
	started time.Time
	denials atomic.Uint64

	mu       sync.Mutex
	regs     map[uint64]*registration
	global   map[guardbpfFileKey]bool
	warnings []string

	connMu sync.Mutex
	conns  map[uint32]int // open connections per uid

	// exes are the executables registered brokers ran when they
	// registered (guarded by mu, kept in exesPath across restarts of the
	// daemon): a package upgrade replaces the installed cotty with a new
	// inode, and the running brokers stay verifiable (review G3).
	exes map[exeKey]exeID

	// exceptions is the pts exception list as last loaded (guarded by
	// mu), excSummary and excNotes what was last logged about it.
	exceptions []exceptionExe
	excSummary string
	excNotes   []string
}

// Run loads and attaches the programs, serves the socket and writes
// denials to the audit log until ctx ends.
func Run(ctx context.Context, opts Options) error {
	if opts.SocketPath == "" {
		opts.SocketPath = guard.SocketPath
	}
	if opts.PinPath == "" {
		opts.PinPath = guard.PinPath
	}
	if opts.AuditPath == "" {
		opts.AuditPath = guard.AuditPath
	}
	f := guard.ReadFacts()
	if !f.BPFLSM || !f.BTF {
		return fmt.Errorf("%w: %s", ErrUnsupported, f.Explain)
	}
	d := &daemon{
		opts: opts, facts: f, links: map[string]link.Link{},
		audit: audit.Open(opts.AuditPath), dedup: guard.NewDedup(2 * time.Second), started: time.Now(),
		regs: map[uint64]*registration{}, global: map[guardbpfFileKey]bool{}, conns: map[uint32]int{},
	}
	d.exes = loadExes(d.exesPath())
	if err := d.load(); err != nil {
		return err
	}
	defer d.unload()
	d.recover()
	d.loadExceptions()
	d.rebuildGlobal()
	d.pruneBrokers()
	d.scanSystemSockets()

	rd, err := ringbuf.NewReader(d.maps.Events)
	if err != nil {
		return fmt.Errorf("ring buffer: %w", err)
	}
	go d.readEvents(rd)
	defer rd.Close()

	lfd, err := d.listen()
	if err != nil {
		return err
	}
	go d.serve(lfd)
	d.heartbeat(true)
	d.markEnforcing()
	log.Printf("cotty-guard: enforcing (kernel %s, %d programs, pins in %s, socket %s, audit %s)",
		f.Kernel, len(d.links), opts.PinPath, opts.SocketPath, opts.AuditPath)

	// SIGHUP reloads the pts exception list (it is also read again on
	// every tick).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-hup:
			log.Printf("cotty-guard: SIGHUP: reloading the pts exception list")
			d.loadExceptions()
		case <-ctx.Done():
			// Everything else stays in force. The broker directory rule
			// needs a daemon brokers can register with: it lapses once the last
			// heartbeat is older than the programs' limit (90 s), so a
			// restart or an upgrade never opens a window, and a daemon
			// stopped for good does not keep new sessions from starting.
			// The pts exception list does not stay: without a daemon no
			// broker learns about an exception use, so the lock would not
			// light for it. It is emptied now (and, after a crash, the
			// programs stop honouring it once the heartbeat is stale); the
			// next start loads it again.
			d.clearExceptions()
			_ = unix.Shutdown(lfd, unix.SHUT_RDWR)
			_ = unix.Close(lfd)
			_ = os.Remove(opts.SocketPath)
			return nil
		case <-tick.C:
			d.heartbeat(true)
			d.gc()
			d.prunePTS()
			d.pruneBrokers()
			d.scanSystemSockets()
			d.loadExceptions()
		}
	}
}

// load loads the collection (reusing pinned maps, so tags, registrations
// and protections survive a restart), attaches every program and swaps
// the pinned links. Programs for hooks the kernel lacks (optionalPrograms)
// are left out with a warning.
func (d *daemon) load() error {
	_ = rlimit.RemoveMemlock()
	if err := os.MkdirAll(d.opts.PinPath, 0o700); err != nil {
		return fmt.Errorf("pin directory: %w (is bpffs mounted on /sys/fs/bpf?)", err)
	}
	spec, err := loadGuardbpf()
	if err != nil {
		return err
	}
	if kspec, err := btf.LoadKernelSpec(); err == nil {
		for prog, hook := range optionalPrograms {
			var fn *btf.Func
			if kspec.TypeByName("bpf_lsm_"+hook, &fn) != nil {
				delete(spec.Programs, prog)
				d.warn("this kernel has no %s hook; %s is not attached", hook, prog)
			}
		}
	}
	// Pinned maps of an older build with another layout are migrated, or
	// the start is refused (the old programs keep enforcing): an upgrade
	// never drops tags, registrations or protections.
	if err := migratePins(spec, d.opts.PinPath); err != nil {
		return err
	}
	opts := ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: d.opts.PinPath}}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load: %+v", ve)
		}
		return fmt.Errorf("load: %w", err)
	}
	if err := coll.Assign(&d.maps); err != nil {
		coll.Close()
		return fmt.Errorf("maps: %w", err)
	}
	d.coll = coll
	for name, p := range coll.Programs {
		l, err := link.AttachLSM(link.LSMOptions{Program: p})
		if err != nil {
			for _, l := range d.links {
				_ = l.Close()
			}
			d.links = map[string]link.Link{}
			coll.Close()
			return fmt.Errorf("attach %s: %w", name, err)
		}
		d.links[name] = l
	}
	// The new links enforce from here on; drop the old pinned ones and pin
	// the new ones, so a stop or a crash leaves the enforcement in place.
	for name, l := range d.links {
		pin := filepath.Join(d.opts.PinPath, "link_"+name)
		if old, err := link.LoadPinnedLink(pin, nil); err == nil {
			_ = old.Unpin()
			_ = old.Close()
		}
		if err := l.Pin(pin); err != nil {
			d.warn("pin %s: %v", name, err)
		}
	}
	// Links of programs this build no longer has.
	ents, _ := os.ReadDir(d.opts.PinPath)
	for _, e := range ents {
		if name, ok := strings.CutPrefix(e.Name(), "link_"); ok && d.links[name] == nil {
			if old, err := link.LoadPinnedLink(filepath.Join(d.opts.PinPath, e.Name()), nil); err == nil {
				_ = old.Unpin()
				_ = old.Close()
			} else {
				_ = os.Remove(filepath.Join(d.opts.PinPath, e.Name()))
			}
		}
	}
	return nil
}

// volatileMaps hold nothing that protects anybody (a rate limit window,
// the event queue): a pinned one of another layout is simply replaced.
// The pts exception list is rewritten from its file at every start, and
// the record of exception uses only names the latest opener of each pts.
var volatileMaps = map[string]bool{"event_rate": true, "events": true, "pts_exceptions": true, "pts_exc_uses": true}

// migratePins brings the pinned maps in pinPath to the layout of spec
// before the collection is loaded. A pinned map that is compatible stays.
// One that differs only in its number of entries (a hash or an array whose
// key and value are unchanged) is copied into a new map of the new size,
// which replaces the pin. A volatile map is replaced empty. Anything else
// (a changed key or value, task or socket storage, which cannot be
// copied) refuses the start: the pinned programs of the old build keep
// enforcing on the old maps until the person stops the sessions and runs
// `cotty-guard uninstall`.
func migratePins(spec *ebpf.CollectionSpec, pinPath string) error {
	names := make([]string, 0, len(spec.Maps))
	for n := range spec.Maps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		ms := spec.Maps[name]
		if ms.Pinning != ebpf.PinByName {
			continue
		}
		pin := filepath.Join(pinPath, name)
		old, err := ebpf.LoadPinnedMap(pin, nil)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("pinned map %s: %w", name, err)
		}
		cerr := ms.Compatible(old)
		if cerr == nil {
			old.Close()
			continue
		}
		if volatileMaps[name] {
			log.Printf("cotty-guard: pinned map %s has another layout (%v); replacing it", name, cerr)
			_ = old.Unpin()
			old.Close()
			continue
		}
		err = copyMap(ms, old, pin)
		old.Close()
		if err != nil {
			return fmt.Errorf("pinned map %s is from a build with another layout (%v) and cannot be migrated (%v); "+
				"the programs already loaded keep enforcing. Stop the cotty sessions and agents, run `cotty-guard uninstall`, "+
				"then start cotty-guard again", name, cerr, err)
		}
		log.Printf("cotty-guard: pinned map %s migrated to the new layout (%v)", name, cerr)
	}
	return nil
}

// copyMap copies old into a new map built from ms (only its size may
// differ) and pins the new map in old's place.
func copyMap(ms *ebpf.MapSpec, old *ebpf.Map, pin string) error {
	switch ms.Type {
	case ebpf.Hash, ebpf.LRUHash, ebpf.Array:
	default:
		return fmt.Errorf("a %s map cannot be copied", ms.Type)
	}
	if old.Type() != ms.Type || old.KeySize() != ms.KeySize || old.ValueSize() != ms.ValueSize || old.Flags() != ms.Flags {
		return errors.New("its key, value or type changed")
	}
	cp := ms.Copy()
	cp.Pinning = ebpf.PinNone
	nm, err := ebpf.NewMap(cp)
	if err != nil {
		return err
	}
	defer nm.Close()
	k := make([]byte, ms.KeySize)
	v := make([]byte, ms.ValueSize)
	n := 0
	it := old.Iterate()
	for it.Next(&k, &v) {
		if n++; uint32(n) > ms.MaxEntries {
			return fmt.Errorf("the old map holds more than the new %d entries", ms.MaxEntries)
		}
		if err := nm.Update(k, v, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	// Pin the copy next to the old map, then move it over the old pin in
	// one rename: the pin path never disappears. (bpffs refuses names with
	// a dot.)
	tmp := filepath.Join(filepath.Dir(pin), "migrate_"+filepath.Base(pin))
	_ = os.Remove(tmp)
	if err := nm.Pin(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, pin); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// markEnforcing creates guard.EnforcingMarker next to the socket (the
// attach client fails closed while it exists and the daemon does not
// answer).
func (d *daemon) markEnforcing() {
	p := filepath.Join(filepath.Dir(d.opts.SocketPath), filepath.Base(guard.EnforcingMarker))
	if err := os.WriteFile(p, []byte("cotty-guard enforces; see cotty-guard status\n"), 0o644); err != nil {
		d.warn("marker %s: %v", p, err)
	}
}

// unload closes the daemon's handles on a stop. The links and maps stay
// pinned: the enforcement, every tag, registration and pts protection go
// on without the daemon, and the next start picks them up (a restart or
// an upgrade changes nothing for running agents and sessions). Only
// Uninstall removes them.
func (d *daemon) unload() {
	for _, l := range d.links {
		_ = l.Close()
	}
	if d.coll != nil {
		d.coll.Close()
	}
}

// Uninstall removes the pinned programs and maps: the enforcement stops and
// every tag, registration and protection is forgotten. It refuses while a
// daemon answers on the socket.
func Uninstall(pinPath, socketPath string) error {
	if pinPath == "" {
		pinPath = guard.PinPath
	}
	if socketPath == "" {
		socketPath = guard.SocketPath
	}
	if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0); err == nil {
		err := unix.Connect(fd, &unix.SockaddrUnix{Name: socketPath})
		_ = unix.Close(fd)
		if err == nil {
			return errors.New("cotty-guard is running; stop it first (systemctl stop cotty-guard)")
		}
	}
	// The attach client no longer expects a guard.
	if err := os.Remove(filepath.Join(filepath.Dir(socketPath), filepath.Base(guard.EnforcingMarker))); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	ents, err := os.ReadDir(pinPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		p := filepath.Join(pinPath, e.Name())
		if strings.HasPrefix(e.Name(), "link_") {
			if l, err := link.LoadPinnedLink(p, nil); err == nil {
				_ = l.Unpin()
				_ = l.Close()
				continue
			}
		}
		if err := os.Remove(p); err != nil {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(pinPath); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (d *daemon) warn(f string, a ...any) {
	msg := fmt.Sprintf(f, a...)
	log.Printf("cotty-guard: warning: %s", msg)
	d.mu.Lock()
	d.warnings = append(d.warnings, msg)
	d.mu.Unlock()
}

// ---- registry ----

// recover rebuilds the registry from pinned maps after a restart: each
// registered cgroup id is looked up in the cgroup tree; ids whose cgroup
// is gone are removed, with their allowlist entries.
func (d *daemon) recover() {
	want := map[uint64]bool{}
	var k, v uint64
	it := d.maps.AgentCgroups.Iterate()
	for it.Next(&k, &v) {
		want[k] = true
	}
	if len(want) > 0 {
		_ = filepath.WalkDir(cgroupRoot, func(p string, e fs.DirEntry, err error) error {
			if err != nil || !e.IsDir() {
				return nil
			}
			var st unix.Stat_t
			if unix.Stat(p, &st) == nil && want[st.Ino] {
				rel := strings.TrimPrefix(p, cgroupRoot)
				d.regs[st.Ino] = &registration{id: st.Ino, path: rel, level: cgroupLevel(rel), uid: st.Uid, when: time.Now()}
				delete(want, st.Ino)
			}
			return nil
		})
		for id := range want {
			_ = d.maps.AgentCgroups.Delete(id)
		}
	}
	d.pruneAllowlist()
	d.updateCount()
	if len(d.regs) > 0 {
		log.Printf("cotty-guard: %d agent cgroups kept from the previous run", len(d.regs))
	}
	// Protections whose broker is gone (a crash, or sessions that ended
	// while the daemon was stopped) would keep a reused pts index
	// unopenable; the programs ignore them already, remove them now.
	n := d.prunePTS()
	if kept := d.countPTS(); kept > 0 || n > 0 {
		log.Printf("cotty-guard: %d session terminals still protected from the previous run, %d stale removed", kept, n)
	}
}

// cgroupLevel is the depth of a cgroup v2 path ("/" is 0).
func cgroupLevel(p string) int {
	p = strings.Trim(filepath.Clean(p), "/")
	if p == "" || p == "." {
		return 0
	}
	return strings.Count(p, "/") + 1
}

// pruneAllowlist removes per-agent socket entries of agents that are no
// longer registered.
func (d *daemon) pruneAllowlist() {
	var k guardbpfFileKey
	var v uint8
	var stale []guardbpfFileKey
	it := d.maps.AllowedSocks.Iterate()
	for it.Next(&k, &v) {
		// Self-tagged agents (high bit) have no registration and no list.
		if k.Agent != 0 && k.Agent>>63 == 0 && d.regs[k.Agent] == nil {
			stale = append(stale, k)
		}
	}
	for _, s := range stale {
		_ = d.maps.AllowedSocks.Delete(s)
	}
}

// updateCount publishes the number of registered cgroups and the levels
// of the cgroup tree they are at (the programs look only there).
func (d *daemon) updateCount() {
	n := uint64(len(d.regs))
	var levels uint64
	for _, r := range d.regs {
		if r.level >= 0 && r.level <= maxCgroupLevel {
			levels |= 1 << uint(r.level)
		}
	}
	// Levels first, so the walk never sees a count without its level.
	_ = d.maps.GuardState.Update(uint32(stateLevels), levels, ebpf.UpdateAny)
	_ = d.maps.GuardState.Update(uint32(stateAgents), n, ebpf.UpdateAny)
}

// heartbeat tells the programs the daemon runs (CLOCK_MONOTONIC, the clock
// of bpf_ktime_get_ns), or, with alive false, that it stopped.
func (d *daemon) heartbeat(alive bool) {
	var now uint64
	if alive {
		var ts unix.Timespec
		if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) == nil {
			now = uint64(ts.Nano())
		}
	}
	_ = d.maps.GuardState.Update(uint32(stateHeartbeat), now, ebpf.UpdateAny)
}

// ---- brokers ----

// DefaultCottyPaths are the only places a registered broker's executable
// may be (Options.CottyPaths overrides them): the package and the
// `make install` locations.
var DefaultCottyPaths = []string{"/usr/bin/cotty", "/usr/local/bin/cotty"}

// installedBroker checks, as root, that pid runs the installed cotty
// binary (one of the configured paths, a regular file owned by root, in
// root-owned directories, none of them writable by group or others) as a
// broker (`__broker` as its first argument, without -dev-insecure), is
// not dumpable (its /proc/PID/status belongs to root), as every broker
// makes itself, and is not traced (a tracer started before the exec would
// control the broker).
//
// known is the executable the broker ran when it registered, if the
// daemon recorded it: a broker still running that inode passes the path
// checks even after a package upgrade replaced or removed the installed
// file (review G3). It returns the executable it judged.
func installedBroker(pid int, uid uint32, paths []string, known *exeID) (exeID, error) {
	proc := "/proc/" + strconv.Itoa(pid)
	var exe unix.Stat_t
	if err := unix.Stat(proc+"/exe", &exe); err != nil {
		return exeID{}, fmt.Errorf("executable of %d: %v", pid, err)
	}
	if exe.Mode&unix.S_IFMT != unix.S_IFREG || exe.Uid != 0 || exe.Mode&0o022 != 0 {
		return exeID{}, fmt.Errorf("process %d does not run a root-owned executable", pid)
	}
	id := exeID{Dev: exe.Dev, Ino: exe.Ino}
	if known == nil || *known != id {
		if err := installedPath(pid, proc, exe, paths); err != nil {
			return exeID{}, err
		}
	}
	return id, brokerProcess(pid, uid, proc)
}

// installedPath checks that pid's executable is the installed cotty: one
// of paths, in root-owned directories closed to others.
func installedPath(pid int, proc string, exe unix.Stat_t, paths []string) error {
	path, err := os.Readlink(proc + "/exe")
	if err != nil || strings.HasSuffix(path, " (deleted)") || !filepath.IsAbs(path) {
		return fmt.Errorf("process %d runs a deleted or unknown executable", pid)
	}
	if len(paths) == 0 {
		paths = DefaultCottyPaths
	}
	if !slices.Contains(paths, path) {
		return fmt.Errorf("process %d runs %s, not the installed cotty (%s)", pid, path, strings.Join(paths, ", "))
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil || st.Dev != exe.Dev || st.Ino != exe.Ino {
		return fmt.Errorf("process %d: %s is not the executable it runs", pid, path)
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if err := unix.Stat(dir, &st); err != nil || st.Uid != 0 || st.Mode&0o022 != 0 {
			return fmt.Errorf("process %d: %s is in %s, which is not a root-owned directory closed to others", pid, path, dir)
		}
		if dir == "/" {
			break
		}
	}
	return nil
}

// brokerProcess checks the rest: a broker command line without
// -dev-insecure, not dumpable, not traced.
func brokerProcess(pid int, uid uint32, proc string) error {
	var st unix.Stat_t
	b, err := os.ReadFile(proc + "/cmdline")
	if err != nil {
		return fmt.Errorf("command line of %d: %v", pid, err)
	}
	args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	if len(args) < 2 || args[1] != "__broker" {
		return fmt.Errorf("process %d is not a cotty broker", pid)
	}
	if insecureArgs(args[2:]) {
		return fmt.Errorf("process %d is a -dev-insecure broker: with the guard loaded it cannot be registered", pid)
	}
	if f, _, _ := session.ParseBrokerArgs(args[2:]); !session.ValidName(f.Name) {
		return fmt.Errorf("process %d: broker without a valid session name", pid)
	}
	if uid != 0 {
		// The per-task files (not the /proc/PID directory itself) belong
		// to root once the process is not dumpable.
		if err := unix.Stat(proc+"/status", &st); err != nil || st.Uid != 0 {
			return fmt.Errorf("process %d is dumpable (brokers are not)", pid)
		}
	}
	if tp, err := tracerPID(pid); err != nil || tp != 0 {
		return fmt.Errorf("process %d is traced (by %d) or unreadable: %v", pid, tp, err)
	}
	return nil
}

// insecureArgs tells whether a broker's arguments (after "__broker") ask
// for -dev-insecure. They are parsed with the broker's own flag
// definitions, so a flag value such as "--" cannot hide the flag from
// this check (review G1); arguments the broker would not parse count as
// insecure (refused).
func insecureArgs(args []string) bool {
	f, _, err := session.ParseBrokerArgs(args)
	return err != nil || f.Insecure
}

// tracerPID reads TracerPid from /proc/PID/status.
func tracerPID(pid int) (int, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "TracerPid:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, errors.New("no TracerPid in status")
}

func nameKey(uid uint32, name string) guardbpfBrokerName {
	k := guardbpfBrokerName{Uid: uid}
	for i := 0; i < len(name) && i < len(k.Name)-1; i++ {
		k.Name[i] = int8(name[i])
	}
	return k
}

func keyName(k guardbpfBrokerName) string { return cString(k.Name[:]) }

// regOwner is the process a registration belongs to.
func regOwner(r guardbpfBrokerReg) guardbpfPtsOwner {
	return guardbpfPtsOwner{Tgid: r.Tgid, Start: r.Start}
}

// nameHolder decides whether a caller (tgid, start) may register a session
// name: free names and names whose broker is gone are taken; a name held
// by another live broker is refused (a second broker never takes a
// running session over); the holder itself may register again (after a
// daemon restart).
func nameHolder(cur guardbpfBrokerReg, have, curAlive bool, tgid uint32, start uint64) error {
	if !have || !curAlive {
		return nil
	}
	if cur.Tgid == tgid && cur.Start == start {
		return nil
	}
	return fmt.Errorf("the session name is held by the live broker %d", cur.Tgid)
}

// vouch decides verify-broker for a listener (pid, start): it must be the
// live broker that holds the session name.
func vouch(reg guardbpfBrokerReg, have, alive bool, pid int, start uint64) error {
	if !have {
		return errors.New("no broker is registered for this session")
	}
	if !alive {
		return errors.New("the session's registered broker is gone")
	}
	if int(reg.Tgid) != pid || reg.Start != start {
		return fmt.Errorf("the listener (pid %d) is not the session's registered broker (pid %d)", pid, reg.Tgid)
	}
	return nil
}

// registerBroker records the caller as the broker of session name and
// marks its runtime directories (fds) as broker directories.
func (d *daemon) registerBroker(c caller, name string, fds []int) guard.Response {
	if !session.ValidName(name) {
		return fail("register-broker needs a valid session name")
	}
	if tag, err := d.tagOf(c.pidfd, c.pid); err != nil {
		return fail("%v", err)
	} else if tag != "" {
		return fail("the caller is an agent (%s)", tag)
	}
	start, err := startTicks(c.pid)
	if err != nil {
		return fail("caller: %v", err)
	}
	ek := exeKey{Tgid: uint32(c.pid), Start: start}
	exe, err := installedBroker(c.pid, c.uid, d.opts.CottyPaths, d.knownExe(ek))
	if err != nil {
		return fail("%v", err)
	}
	if err := alive(c.pidfd); err != nil {
		return fail("%v", err)
	}
	if len(fds) != 2 {
		return fail("register-broker needs the runtime directory and its agent directory")
	}
	var keys [2]guardbpfFileKey
	for i, fd := range fds {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return fail("%v", err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != c.uid || st.Mode&0o077 != 0 {
			return fail("inode %d is not a directory of uid %d closed to others", st.Ino, c.uid)
		}
		keys[i] = guardbpfFileKey{Dev: guard.KernelDev(st.Dev), Ino: st.Ino}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneBrokersLocked()
	nk := nameKey(c.uid, name)
	var cur guardbpfBrokerReg
	have := d.maps.BrokerNames.Lookup(nk, &cur) == nil
	if err := nameHolder(cur, have, have && ownerAlive(regOwner(cur)), uint32(c.pid), start); err != nil {
		return fail("session %q: %v", name, err)
	}
	mine := have && cur.Tgid == uint32(c.pid) && cur.Start == start
	// One broker, one session name.
	var k guardbpfBrokerName
	var r guardbpfBrokerReg
	n := 0
	it := d.maps.BrokerNames.Iterate()
	for it.Next(&k, &r) {
		if k.Uid == c.uid {
			n++
		}
		if r.Tgid == uint32(c.pid) && r.Start == start && keyName(k) != name {
			return fail("this broker is already registered as session %q", keyName(k))
		}
	}
	if !mine && n >= guard.MaxBrokersPerUser {
		return fail("uid %d already has %d registered sessions (the limit)", c.uid, n)
	}
	reg := guardbpfBrokerReg{Tgid: uint32(c.pid), Start: start,
		DirDev: keys[0].Dev, DirIno: keys[0].Ino, AdirDev: keys[1].Dev, AdirIno: keys[1].Ino}
	if mine {
		reg.SockDev, reg.SockIno, reg.AsockDev, reg.AsockIno = cur.SockDev, cur.SockIno, cur.AsockDev, cur.AsockIno
	}
	if err := d.maps.Brokers.Update(uint32(c.pid), start, ebpf.UpdateAny); err != nil {
		return fail("register: %v", err)
	}
	if err := d.maps.BrokerNames.Update(nk, reg, ebpf.UpdateAny); err != nil {
		return fail("register: %v", err)
	}
	for _, k := range keys {
		var v uint8
		_ = d.maps.AllowedSocks.Lookup(k, &v)
		if err := d.maps.AllowedSocks.Update(k, v|dirBrokers|dirGuarded, ebpf.UpdateAny); err != nil {
			return fail("directory: %v", err)
		}
	}
	if d.exes[ek] != exe {
		d.exes[ek] = exe
		d.saveExesLocked()
	}
	return guard.Response{OK: true}
}

// claimSocket records a socket the registered broker of session name
// bound (slot 0: the person socket, 1: the agent socket): from then on the
// programs refuse its removal or replacement to every other process but
// root while the broker runs.
func (d *daemon) claimSocket(c caller, name string, slot int, fds []int) guard.Response {
	if len(fds) != 1 || (slot != 0 && slot != 1) {
		return fail("claim-socket needs one socket and slot 0 or 1")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fds[0], &st); err != nil {
		return fail("%v", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != c.uid {
		return fail("not a socket of uid %d", c.uid)
	}
	start, err := startTicks(c.pid)
	if err != nil {
		return fail("caller: %v", err)
	}
	if err := alive(c.pidfd); err != nil {
		return fail("%v", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	nk := nameKey(c.uid, name)
	var reg guardbpfBrokerReg
	if d.maps.BrokerNames.Lookup(nk, &reg) != nil || reg.Tgid != uint32(c.pid) || reg.Start != start {
		return fail("the caller is not the registered broker of session %q", name)
	}
	key := guardbpfFileKey{Dev: guard.KernelDev(st.Dev), Ino: st.Ino}
	var other guardbpfPtsOwner
	if d.maps.BrokerSocks.Lookup(key, &other) == nil && ownerAlive(other) && (other.Tgid != reg.Tgid || other.Start != reg.Start) {
		return fail("the socket is claimed by broker %d", other.Tgid)
	}
	oldDev, oldIno := &reg.SockDev, &reg.SockIno
	if slot == 1 {
		oldDev, oldIno = &reg.AsockDev, &reg.AsockIno
	}
	if *oldIno != 0 && (*oldDev != key.Dev || *oldIno != key.Ino) {
		_ = d.maps.BrokerSocks.Delete(guardbpfFileKey{Dev: *oldDev, Ino: *oldIno})
	}
	*oldDev, *oldIno = key.Dev, key.Ino
	if err := d.maps.BrokerSocks.Update(key, guardbpfPtsOwner{Tgid: reg.Tgid, Uid: c.uid, Start: reg.Start}, ebpf.UpdateAny); err != nil {
		return fail("claim: %v", err)
	}
	if err := d.maps.BrokerNames.Update(nk, reg, ebpf.UpdateAny); err != nil {
		return fail("claim: %v", err)
	}
	return guard.Response{OK: true}
}

// verifyBroker looks at the process listening on the other end of the
// caller's connected socket fd: it must be the registered broker of
// session name of the caller's uid, running the installed cotty binary.
func (d *daemon) verifyBroker(c caller, name string, fd int) guard.Response {
	if !session.ValidName(name) {
		return fail("verify-broker needs a valid session name")
	}
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return fail("not a connected Unix socket: %v", err)
	}
	if cred.Uid != c.uid {
		return fail("the listener runs as uid %d, not as the caller (uid %d)", cred.Uid, c.uid)
	}
	pid := int(cred.Pid)
	pfd, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	if err != nil {
		return fail("listener pidfd: %v", err)
	}
	defer unix.Close(pfd)
	start, err := startTicks(pid)
	if err != nil {
		return fail("listener: %v", err)
	}
	if _, err := installedBroker(pid, cred.Uid, d.opts.CottyPaths, d.knownExe(exeKey{Tgid: uint32(pid), Start: start})); err != nil {
		return fail("%v", err)
	}
	if err := alive(pfd); err != nil {
		return fail("the listener exited")
	}
	var want uint64
	if d.maps.Brokers.Lookup(uint32(pid), &want) != nil || want != start {
		return fail("process %d is not a registered broker", pid)
	}
	d.mu.Lock()
	var reg guardbpfBrokerReg
	have := d.maps.BrokerNames.Lookup(nameKey(c.uid, name), &reg) == nil
	d.mu.Unlock()
	if err := vouch(reg, have, have && ownerAlive(regOwner(reg)), pid, start); err != nil {
		return fail("session %q: %v", name, err)
	}
	return guard.Response{OK: true, PID: pid}
}

// pruneBrokers forgets brokers that exited, their session names and
// sockets, and the runtime directories no live broker registered.
func (d *daemon) pruneBrokers() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneBrokersLocked()
}

func (d *daemon) pruneBrokersLocked() {
	var tg uint32
	var st uint64
	var stale []uint32
	it := d.maps.Brokers.Iterate()
	for it.Next(&tg, &st) {
		if !ownerAlive(guardbpfPtsOwner{Tgid: tg, Start: st}) {
			stale = append(stale, tg)
		}
	}
	for _, t := range stale {
		_ = d.maps.Brokers.Delete(t)
	}
	pruned := false
	for k := range d.exes {
		if !ownerAlive(guardbpfPtsOwner{Tgid: k.Tgid, Start: k.Start}) {
			delete(d.exes, k)
			pruned = true
		}
	}
	if pruned {
		d.saveExesLocked()
	}
	// Session names of gone brokers; the directories live ones use.
	dirs := map[guardbpfFileKey]bool{}
	var nk guardbpfBrokerName
	var reg guardbpfBrokerReg
	var staleNames []guardbpfBrokerName
	itn := d.maps.BrokerNames.Iterate()
	for itn.Next(&nk, &reg) {
		if !ownerAlive(regOwner(reg)) {
			staleNames = append(staleNames, nk)
			continue
		}
		dirs[guardbpfFileKey{Dev: reg.DirDev, Ino: reg.DirIno}] = true
		dirs[guardbpfFileKey{Dev: reg.AdirDev, Ino: reg.AdirIno}] = true
	}
	for _, k := range staleNames {
		_ = d.maps.BrokerNames.Delete(k)
	}
	var sk guardbpfFileKey
	var so guardbpfPtsOwner
	var staleSocks []guardbpfFileKey
	its := d.maps.BrokerSocks.Iterate()
	for its.Next(&sk, &so) {
		if !ownerAlive(so) {
			staleSocks = append(staleSocks, sk)
		}
	}
	for _, k := range staleSocks {
		_ = d.maps.BrokerSocks.Delete(k)
	}
	// Runtime directories no live broker registered: an inode number
	// reused later (a new /run/user/UID) must not keep the broker rule.
	var ak guardbpfFileKey
	var v uint8
	type upd struct {
		k guardbpfFileKey
		v uint8
	}
	var drop []upd
	ita := d.maps.AllowedSocks.Iterate()
	for ita.Next(&ak, &v) {
		if ak.Agent == 0 && v&dirBrokers != 0 && !dirs[ak] {
			drop = append(drop, upd{ak, v &^ (dirBrokers | dirGuarded)})
		}
	}
	for _, u := range drop {
		if u.v == 0 {
			_ = d.maps.AllowedSocks.Delete(u.k)
		} else {
			_ = d.maps.AllowedSocks.Update(u.k, u.v, ebpf.UpdateAny)
		}
	}
}

func (d *daemon) countBrokers() int {
	var tg uint32
	var st uint64
	n := 0
	it := d.maps.Brokers.Iterate()
	for it.Next(&tg, &st) {
		n++
	}
	return n
}

// isRegisteredBroker tells whether pid (with start) is a registered broker.
func (d *daemon) isRegisteredBroker(pid int, start uint64) bool {
	var want uint64
	return d.maps.Brokers.Lookup(uint32(pid), &want) == nil && want == start
}

// ---- protected terminals ----

// startTicks reads a process's start time in clock ticks since boot
// (/proc/PID/stat field 22), the unit the programs compare with.
func startTicks(pid int) (uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, errors.New("odd /proc stat")
	}
	f := strings.Fields(string(b[i+1:]))
	// f[0] is field 3 (state); field 22 is f[19].
	if len(f) < 20 {
		return 0, errors.New("short /proc stat")
	}
	return strconv.ParseUint(f[19], 10, 64)
}

// ownerAlive tells whether the broker of a protection still runs.
func ownerAlive(o guardbpfPtsOwner) bool {
	st, err := startTicks(int(o.Tgid))
	return err == nil && st == o.Start
}

// prunePTS removes protections whose broker is gone; it returns how many.
// It runs under d.mu, like every writer of protected_files, and looks at
// an entry again right before removing it: a pts index reused and
// protected by a new broker in the meantime keeps its new protection.
func (d *daemon) prunePTS() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	var k guardbpfFileKey
	var o guardbpfPtsOwner
	var stale []guardbpfFileKey
	it := d.maps.ProtectedFiles.Iterate()
	for it.Next(&k, &o) {
		if !ownerAlive(o) {
			stale = append(stale, k)
		}
	}
	n := 0
	for _, s := range stale {
		var now guardbpfPtsOwner
		if d.maps.ProtectedFiles.Lookup(s, &now) == nil && !ownerAlive(now) {
			_ = d.maps.ProtectedFiles.Delete(s)
			n++
		}
	}
	return n
}

func (d *daemon) countPTS() int {
	var k guardbpfFileKey
	var o guardbpfPtsOwner
	n := 0
	it := d.maps.ProtectedFiles.Iterate()
	for it.Next(&k, &o) {
		n++
	}
	return n
}

// gc forgets cgroups that were removed.
func (d *daemon) gc() {
	d.mu.Lock()
	defer d.mu.Unlock()
	changed := false
	for id, r := range d.regs {
		var st unix.Stat_t
		if err := unix.Stat(cgroupRoot+r.path, &st); err != nil || st.Ino != id {
			_ = d.maps.AgentCgroups.Delete(id)
			delete(d.regs, id)
			changed = true
		}
	}
	if changed {
		d.pruneAllowlist()
		d.updateCount()
	}
}

// scanSystemSockets refreshes the global socket allowlist (a service
// restart makes a new inode).
func (d *daemon) scanSystemSockets() {
	found := map[guardbpfFileKey]bool{}
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		var st unix.Stat_t
		if unix.Stat(p, &st) != nil {
			return
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFSOCK:
			found[guardbpfFileKey{Dev: guard.KernelDev(st.Dev), Ino: st.Ino}] = true
		case unix.S_IFDIR:
			// The directory itself too, so a socket recreated between two
			// scans stays reachable.
			found[guardbpfFileKey{Dev: guard.KernelDev(st.Dev), Ino: st.Ino}] = true
			if depth > 1 {
				return
			}
			ents, _ := os.ReadDir(p)
			for _, e := range ents {
				walk(filepath.Join(p, e.Name()), depth+1)
			}
		}
	}
	for _, p := range append(append([]string(nil), systemSockets...), d.opts.ExtraSockets...) {
		walk(p, 0)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range found {
		if !d.global[k] {
			var v uint8
			_ = d.maps.AllowedSocks.Lookup(k, &v)
			if err := d.maps.AllowedSocks.Update(k, v|sockConnect, ebpf.UpdateAny); err == nil {
				d.global[k] = true
			}
		}
	}
	for k := range d.global {
		if !found[k] {
			// Keep other bits (a broker directory on the same inode).
			var v uint8
			if d.maps.AllowedSocks.Lookup(k, &v) == nil && v&^sockConnect != 0 {
				_ = d.maps.AllowedSocks.Update(k, v&^sockConnect, ebpf.UpdateAny)
			} else {
				_ = d.maps.AllowedSocks.Delete(k)
			}
			delete(d.global, k)
		}
	}
}

// rebuildGlobal reads the global socket entries left by the previous run
// (scanSystemSockets then removes the ones that are gone).
func (d *daemon) rebuildGlobal() {
	d.mu.Lock()
	defer d.mu.Unlock()
	var k guardbpfFileKey
	var v uint8
	it := d.maps.AllowedSocks.Iterate()
	for it.Next(&k, &v) {
		if k.Agent == 0 && v&sockConnect != 0 {
			d.global[k] = true
		}
	}
}

// ---- events ----

func (d *daemon) readEvents(rd *ringbuf.Reader) {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var ev guardbpfEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		den := guard.Denial{
			Agent: ev.Agent, Hook: ev.Hook, Reason: ev.Reason, PID: ev.Pid, TGID: ev.Tgid,
			Target: ev.Target, Dev: ev.Dev, Ino: ev.Ino, Comm: cString(ev.Comm[:]), Name: cString(ev.Name[:]),
		}
		if ev.Extra&evAllowed != 0 {
			// Not a denial: an executable on the exception list opened a
			// session pts. Always logged (the journal and the audit log).
			den.Allowed = true
			den.Exe = d.exceptionUseAny(guardbpfFileKey{Dev: ev.Dev, Ino: ev.Ino})
			logException(den)
			if d.dedup.Admit(den, time.Now()) {
				if _, err := d.audit.Append(den.Record()); err != nil {
					log.Printf("cotty-guard: audit: %v", err)
				}
			}
			continue
		}
		d.denials.Add(1)
		if !d.dedup.Admit(den, time.Now()) {
			continue
		}
		r := den.Record()
		if _, err := d.audit.Append(r); err != nil {
			log.Printf("cotty-guard: audit: %v", err)
		}
		if d.opts.Verbose {
			log.Printf("cotty-guard: denied %s (%s) pid %d %s %s target %d", guard.HookName(den.Hook), guard.ReasonText(den.Reason),
				den.TGID, den.Comm, den.Name, den.Target)
		}
	}
}

func cString(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// ---- socket ----

func (d *daemon) listen() (int, error) {
	dir := filepath.Dir(d.opts.SocketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return -1, err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return -1, err
	}
	_ = os.Remove(d.opts.SocketPath)
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: d.opts.SocketPath}); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	// Anyone may connect; every request is checked against SO_PEERCRED and
	// SO_PEERPIDFD, and only ever restricts.
	if err := os.Chmod(d.opts.SocketPath, 0o666); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if err := unix.Listen(fd, 64); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// serve accepts connections until the listening socket is shut down. A
// transient failure (out of descriptors or memory, which any local user
// can provoke) only slows it down; it never stops serving.
func (d *daemon) serve(lfd int) {
	backoff := 5 * time.Millisecond
	for {
		cfd, _, err := unix.Accept4(lfd, unix.SOCK_CLOEXEC)
		if err != nil {
			switch {
			case errors.Is(err, unix.EINTR), errors.Is(err, unix.ECONNABORTED), errors.Is(err, unix.EAGAIN):
				continue
			case errors.Is(err, unix.EINVAL), errors.Is(err, unix.EBADF), errors.Is(err, unix.ENOTSOCK):
				return // shut down
			}
			log.Printf("cotty-guard: accept: %v (retrying)", err)
			time.Sleep(backoff)
			backoff = min(2*backoff, time.Second)
			continue
		}
		backoff = 5 * time.Millisecond
		go d.conn(cfd)
	}
}

// connRead and connWrite bound how long a client may keep the daemon
// waiting; the broker's session asks every 2 s, other clients send one
// request and wait for its answer.
const (
	connRead  = 60 * time.Second
	connWrite = 5 * time.Second
)

// admitConn counts a connection of uid; false when uid already has
// guard.MaxConnsPerUser open (root is not limited).
func (d *daemon) admitConn(uid uint32) bool {
	d.connMu.Lock()
	defer d.connMu.Unlock()
	if uid != 0 && d.conns[uid] >= guard.MaxConnsPerUser {
		return false
	}
	d.conns[uid]++
	return true
}

func (d *daemon) releaseConn(uid uint32) {
	d.connMu.Lock()
	defer d.connMu.Unlock()
	if d.conns[uid]--; d.conns[uid] <= 0 {
		delete(d.conns, uid)
	}
}

// caller is the kernel's view of a connected client.
type caller struct {
	uid   uint32
	pid   int
	pidfd int
}

func (d *daemon) conn(fd int) {
	defer unix.Close(fd)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: int64(connRead / time.Second)})
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: int64(connWrite / time.Second)})
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return
	}
	if !d.admitConn(cred.Uid) {
		log.Printf("cotty-guard: uid %d has %d connections open (the limit); refusing pid %d", cred.Uid, guard.MaxConnsPerUser, cred.Pid)
		_ = guard.WriteMsg(fd, guard.Response{Error: "too many open connections for this user"}, nil)
		return
	}
	defer d.releaseConn(cred.Uid)
	pidfd, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	if err != nil {
		log.Printf("cotty-guard: SO_PEERPIDFD of pid %d: %v", cred.Pid, err)
		_ = guard.WriteMsg(fd, guard.Response{Error: "the kernel lacks SO_PEERPIDFD (Linux 6.5 or later is needed)"}, nil)
		return
	}
	defer unix.Close(pidfd)
	c := caller{uid: cred.Uid, pid: int(cred.Pid), pidfd: pidfd}
	// Nothing is tied to the connection: a protection lasts as long as its
	// broker runs, so an idle broker, a broken connection or a daemon
	// restart does not end it.
	for {
		var req guard.Request
		fds, err := guard.ReadMsg(fd, &req)
		if err != nil {
			return
		}
		resp := d.handle(c, req, fds)
		guard.CloseFDs(fds)
		if err := guard.WriteMsg(fd, resp, nil); err != nil {
			return
		}
	}
}

func fail(f string, a ...any) guard.Response { return guard.Response{Error: fmt.Sprintf(f, a...)} }

func (d *daemon) handle(c caller, req guard.Request, fds []int) guard.Response {
	switch req.Op {
	case guard.OpStatus:
		return guard.Response{OK: true, Status: d.status()}
	case guard.OpRegister:
		return d.register(c, fds, req.Guard)
	case guard.OpTagSelf:
		return d.tagSelf(c)
	case guard.OpTagOf:
		if len(fds) != 1 {
			return fail("tag-of needs one pidfd")
		}
		pid, err := pidOfPidfd(fds[0])
		if err != nil {
			return fail("%v", err)
		}
		tag, err := d.tagOf(fds[0], pid)
		if err != nil {
			return fail("%v", err)
		}
		return guard.Response{OK: true, Tag: tag}
	case guard.OpProtectPTS:
		if len(fds) != 2 {
			return fail("protect-pts needs the terminal and its master")
		}
		return d.pts(c, req.Op, fds[0], fds[1])
	case guard.OpCheckPTS, guard.OpReleasePTS:
		if len(fds) != 1 {
			return fail("%s needs one terminal descriptor", req.Op)
		}
		return d.pts(c, req.Op, fds[0], -1)
	case guard.OpRegisterBroker:
		return d.registerBroker(c, req.Name, fds)
	case guard.OpClaimSocket:
		return d.claimSocket(c, req.Name, req.Slot, fds)
	case guard.OpVerifyBroker:
		if len(fds) != 1 {
			return fail("verify-broker needs one connected socket")
		}
		return d.verifyBroker(c, req.Name, fds[0])
	case guard.OpPTSException:
		if len(fds) != 1 {
			return fail("pts-exception needs one terminal descriptor")
		}
		return d.ptsException(c, fds[0])
	case guard.OpUntag, guard.OpUnregister:
		return fail("the guard never removes a tag or a registration; they end with the agent's processes and cgroup")
	}
	return fail("unknown operation %q", req.Op)
}

func (d *daemon) status() *guard.Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	names := make([]string, 0, len(d.links))
	for n := range d.links {
		names = append(names, n)
	}
	sort.Strings(names)
	return &guard.Status{
		Loaded: len(d.links) > 0, Kernel: d.facts.Kernel, LSMs: d.facts.LSMs, Programs: names,
		Agents: len(d.regs), Ptys: d.countPTS(), Brokers: d.countBrokers(), Dropped: d.dropped(), Pinned: d.opts.PinPath, Audit: d.opts.AuditPath, Denials: d.denials.Load(),
		Since: d.started.UTC().Format(time.RFC3339), Version: guard.ProtocolVersion, Warnings: append([]string(nil), d.warnings...),
		Exceptions: d.exceptionListLocked(),
	}
}

// dropped is the number of denials not written to the audit log: events
// the programs did not send (rate limit, full ring buffer) and repeats.
func (d *daemon) dropped() uint64 {
	var n uint64
	_ = d.maps.GuardState.Lookup(uint32(stateDropped), &n)
	return n + d.dedup.DroppedCount()
}

// alive checks that the caller still exists (so the /proc reads above
// were about it, not about a reused pid).
func alive(pidfd int) error {
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return errors.New("the process exited")
	}
	return nil
}

func (d *daemon) register(c caller, fds []int, nGuard int) guard.Response {
	if tag, err := d.tagOf(c.pidfd, c.pid); err != nil {
		return fail("%v", err)
	} else if tag != "" {
		return fail("the caller is already an agent (%s): an agent cannot register agents", tag)
	}
	cg, err := cgroupOf(c.pid)
	if err != nil {
		return fail("%v", err)
	}
	if err := alive(c.pidfd); err != nil {
		return fail("%v", err)
	}
	if cg == "/" || !strings.HasPrefix(filepath.Base(cg), guard.AgentCgroupPrefix) {
		return fail("the caller's cgroup %s is not an agent cgroup (its name must start with %s)", cg, guard.AgentCgroupPrefix)
	}
	level := cgroupLevel(cg)
	if level > maxCgroupLevel {
		return fail("cgroup %s is nested too deep (level %d, at most %d)", cg, level, maxCgroupLevel)
	}
	var st unix.Stat_t
	if err := unix.Stat(cgroupRoot+cg, &st); err != nil {
		return fail("cgroup %s: %v", cg, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fail("cgroup %s is not a directory", cg)
	}
	if st.Uid != c.uid {
		return fail("cgroup %s belongs to uid %d, not to the caller (uid %d)", cg, st.Uid, c.uid)
	}
	if nGuard < 0 || nGuard > len(fds) {
		return fail("bad guarded directory count %d", nGuard)
	}
	id := st.Ino
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.regs[id] == nil {
		n := 0
		for _, r := range d.regs {
			if r.uid == c.uid {
				n++
			}
		}
		if n >= guard.MaxAgentsPerUser {
			return fail("uid %d already has %d registered agents (the limit)", c.uid, n)
		}
	}
	resp := guard.Response{OK: true, Tag: guard.FormatTag(id)}
	for i, fd := range fds {
		guardOnly := i >= len(fds)-nGuard
		var fst unix.Stat_t
		if err := unix.Fstat(fd, &fst); err != nil {
			resp.Skipped = append(resp.Skipped, fmt.Sprintf("fd: %v", err))
			continue
		}
		var val uint8
		switch fst.Mode & unix.S_IFMT {
		case unix.S_IFSOCK:
			if guardOnly {
				resp.Skipped = append(resp.Skipped, fmt.Sprintf("inode %d is not a directory", fst.Ino))
				continue
			}
			val = sockConnect
		case unix.S_IFDIR:
			// A directory allows every socket directly in it: refuse one
			// that anybody can create sockets in. Allowed directories are
			// guarded too, so the agent cannot move a socket into them.
			if !guardOnly && fst.Mode&0o002 != 0 {
				resp.Skipped = append(resp.Skipped, fmt.Sprintf("directory inode %d is world-writable", fst.Ino))
				continue
			}
			val = dirGuarded
			if !guardOnly {
				val |= sockConnect
			}
		default:
			resp.Skipped = append(resp.Skipped, fmt.Sprintf("inode %d is not a socket or a directory", fst.Ino))
			continue
		}
		k := guardbpfFileKey{Agent: id, Dev: guard.KernelDev(fst.Dev), Ino: fst.Ino}
		var old uint8
		if d.maps.AllowedSocks.Lookup(k, &old) == nil {
			val |= old
		}
		if err := d.maps.AllowedSocks.Update(k, val, ebpf.UpdateAny); err != nil {
			resp.Skipped = append(resp.Skipped, fmt.Sprintf("inode %d: %v", fst.Ino, err))
		}
	}
	if err := d.maps.AgentCgroups.Update(id, id, ebpf.UpdateNoExist); err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
		return fail("register: %v", err)
	}
	d.regs[id] = &registration{id: id, path: cg, level: level, uid: c.uid, when: time.Now()}
	d.updateCount()
	log.Printf("cotty-guard: registered agent cgroup %s (%s) for uid %d, %d sockets and directories, %d skipped", cg, resp.Tag, c.uid, len(fds), len(resp.Skipped))
	return resp
}

func (d *daemon) tagSelf(c caller) guard.Response {
	tag, err := d.tagOf(c.pidfd, c.pid)
	if err != nil {
		return fail("%v", err)
	}
	if tag != "" {
		return guard.Response{OK: true, Tag: tag}
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	// High bit set: never a cgroup id.
	id := binary.LittleEndian.Uint64(b[:]) | 1<<63
	if err := d.maps.AgentTasks.Update(uint32(c.pidfd), guardbpfTag{Agent: id}, ebpf.UpdateAny); err != nil {
		return fail("tag: %v", err)
	}
	log.Printf("cotty-guard: tagged pid %d (uid %d) as %s", c.pid, c.uid, guard.FormatTag(id))
	return guard.Response{OK: true, Tag: guard.FormatTag(id)}
}

// tagOf reads a process's tag from the kernel: its task storage (through
// the pidfd), then its cgroup and every ancestor.
func (d *daemon) tagOf(pidfd, pid int) (string, error) {
	var t guardbpfTag
	if err := d.maps.AgentTasks.Lookup(uint32(pidfd), &t); err == nil && t.Agent != 0 {
		return guard.FormatTag(t.Agent), nil
	}
	cg, err := cgroupOf(pid)
	if err != nil {
		return "", err
	}
	if err := alive(pidfd); err != nil {
		return "", err
	}
	for p := cg; ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if unix.Stat(cgroupRoot+p, &st) == nil {
			var a uint64
			if d.maps.AgentCgroups.Lookup(st.Ino, &a) == nil && a != 0 {
				return guard.FormatTag(a), nil
			}
		}
		if p == "/" || p == "." {
			break
		}
	}
	return "", nil
}

// pts handles protect-pts, check-pts and release-pts. A protection is
// owned by the calling process (tgid and start time): the programs let
// only that process and the terminal's own session open it, and ignore it
// once that process is gone. Nobody else can take it over, check it or
// release it. Only a registered broker may protect, and only the terminal
// whose master it holds (master), so no other process can protect a pts
// first and keep the session from starting, or protect the person's other
// terminals.
func (d *daemon) pts(c caller, op string, fd, master int) guard.Response {
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
	if st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return fail("not a terminal device")
	}
	if st.Uid != c.uid {
		return fail("the terminal belongs to uid %d, not to the caller", st.Uid)
	}
	start, err := startTicks(c.pid)
	if err != nil {
		return fail("caller: %v", err)
	}
	if err := alive(c.pidfd); err != nil {
		return fail("%v", err)
	}
	if op == guard.OpProtectPTS {
		if !d.isRegisteredBroker(c.pid, start) {
			return fail("only a registered cotty broker may protect a terminal")
		}
		if err := masterOf(master, st); err != nil {
			return fail("%v", err)
		}
	}
	me := guardbpfPtsOwner{Tgid: uint32(c.pid), Uid: c.uid, Start: start}
	k := guardbpfFileKey{Dev: guard.KernelDev(st.Dev), Ino: st.Ino}
	d.mu.Lock()
	defer d.mu.Unlock()
	var cur guardbpfPtsOwner
	have := d.maps.ProtectedFiles.Lookup(k, &cur) == nil
	mine := have && cur.Tgid == me.Tgid && cur.Start == me.Start
	switch op {
	case guard.OpCheckPTS:
		if len(d.links) == 0 {
			return fail("the guard's programs are not attached")
		}
		if !mine {
			return fail("the terminal is not protected for this process")
		}
		return guard.Response{OK: true}
	case guard.OpReleasePTS:
		if mine {
			_ = d.maps.ProtectedFiles.Delete(k)
		}
		return guard.Response{OK: true}
	}
	if mine {
		return guard.Response{OK: true, Kept: true}
	}
	if have && ownerAlive(cur) {
		// Taking it over would make the caller the one process outside the
		// session allowed to open it (an O_PATH descriptor is enough to
		// ask).
		return fail("the terminal is already protected by process %d", cur.Tgid)
	}
	n := 0
	var ok guardbpfFileKey
	var o guardbpfPtsOwner
	it := d.maps.ProtectedFiles.Iterate()
	for it.Next(&ok, &o) {
		if o.Uid == c.uid && ownerAlive(o) {
			n++
		}
	}
	if n >= guard.MaxProtectionsPerUser {
		return fail("uid %d already has %d protected terminals (the limit)", c.uid, n)
	}
	if err := d.maps.ProtectedFiles.Update(k, me, ebpf.UpdateAny); err != nil {
		return fail("protect: %v", err)
	}
	return guard.Response{OK: true}
}

// masterOf checks that master is the pty master of the terminal pts
// (fstat of the slave): the kernel opens the master's peer as O_PATH
// (TIOCGPTPEER; no terminal open, no file_open) and it must be the same
// inode.
func masterOf(master int, pts unix.Stat_t) error {
	if master < 0 {
		return errors.New("no master descriptor")
	}
	pfd, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(master), uintptr(unix.TIOCGPTPEER),
		uintptr(unix.O_PATH|unix.O_CLOEXEC|unix.O_NOCTTY))
	if errno != 0 {
		return fmt.Errorf("not the master of a pty: %v", errno)
	}
	defer unix.Close(int(pfd))
	var st unix.Stat_t
	if err := unix.Fstat(int(pfd), &st); err != nil {
		return err
	}
	if st.Dev != pts.Dev || st.Ino != pts.Ino {
		return errors.New("the master given is not the terminal's")
	}
	return nil
}

// cgroupOf reads a process's cgroup v2 path.
func cgroupOf(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", fmt.Errorf("cgroup of pid %d: %w", pid, err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			p = filepath.Clean(p)
			if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
				return "", fmt.Errorf("odd cgroup path %q", p)
			}
			return p, nil
		}
	}
	return "", fmt.Errorf("pid %d has no cgroup v2 path", pid)
}

// pidOfPidfd reads the pid a pidfd refers to (in the daemon's namespace).
func pidOfPidfd(fd int) (int, error) {
	b, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return 0, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Pid:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return 0, err
			}
			if n <= 0 {
				return 0, errors.New("the process exited")
			}
			return n, nil
		}
	}
	return 0, errors.New("not a pidfd")
}
