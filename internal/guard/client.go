package guard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Conn is a connection to the daemon.
type Conn struct {
	fd int
	mu sync.Mutex
}

// socketPath and daemonUID are variables for tests (a fake daemon runs as
// the test's user).
var (
	socketPath        = SocketPath
	daemonUID  uint32 = 0
)

// Dial connects to the daemon and checks that the other end runs as root,
// so a process that managed to bind a socket at the same path cannot
// answer for the guard. It returns ErrNotRunning when nothing listens.
func Dial() (*Conn, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: socketPath}); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ECONNREFUSED) {
			return nil, ErrNotRunning
		}
		return nil, fmt.Errorf("connect %s: %w", socketPath, err)
	}
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if cred.Uid != daemonUID {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%s is served by uid %d, not root: refusing to trust it", socketPath, cred.Uid)
	}
	// A daemon that stops answering must not hang the caller (the broker
	// asks it under its own locks).
	tv := unix.NsecToTimeval(int64(clientTimeout))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	return &Conn{fd: fd}, nil
}

// clientTimeout bounds every request to the daemon.
var clientTimeout = 3 * time.Second

// Close ends the connection; terminals protected through it are released.
func (c *Conn) Close() error { return unix.Close(c.fd) }

func (c *Conn) do(op string, fds []int) (Response, error) {
	return c.doReq(Request{Op: op}, fds)
}

func (c *Conn) doReq(req Request, fds []int) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := WriteMsg(c.fd, req, fds); err != nil {
		// The daemon may have refused the connection with a message before
		// closing it (too many connections): report that, not EPIPE.
		if errors.Is(err, unix.EPIPE) || errors.Is(err, unix.ECONNRESET) {
			var r Response
			if got, rerr := ReadMsg(c.fd, &r); rerr == nil {
				CloseFDs(got)
				if r.Error != "" {
					return r, &RefusedError{Msg: r.Error}
				}
			}
		}
		return Response{}, err
	}
	var r Response
	got, err := ReadMsg(c.fd, &r)
	CloseFDs(got)
	if err != nil {
		return Response{}, err
	}
	if !r.OK {
		return r, &RefusedError{Msg: r.Error}
	}
	return r, nil
}

// RefusedError is an answer of the daemon that refuses a request (as
// opposed to a failure to reach it).
type RefusedError struct{ Msg string }

func (e *RefusedError) Error() string { return e.Msg }

// Status asks the daemon for its state.
func (c *Conn) Status() (Status, error) {
	r, err := c.do(OpStatus, nil)
	if err != nil {
		return Status{}, err
	}
	if r.Status == nil {
		return Status{}, errors.New("empty status")
	}
	return *r.Status, nil
}

// Register makes the caller's own cgroup an agent cgroup. sockets are
// pathname Unix sockets, or directories whose sockets (directly in them)
// the agent may still connect to; guarded are directories the agent may
// not change at all (no socket planted or moved there, no rename), such
// as the cotty runtime directory. Allowed directories are guarded too. It
// returns the agent's tag and the entries the daemon skipped.
func (c *Conn) Register(sockets, guarded []string) (string, []string, error) {
	fds, skipped := openSockets(sockets, true)
	gfds, gskipped := openSockets(guarded, false)
	skipped = append(skipped, gskipped...)
	if len(fds)+len(gfds) > maxRequestFDs {
		CloseFDs(fds)
		CloseFDs(gfds)
		return "", skipped, fmt.Errorf("too many sockets and directories (%d, at most %d)", len(fds)+len(gfds), maxRequestFDs)
	}
	all := append(fds, gfds...)
	defer CloseFDs(all)
	c.mu.Lock()
	err := WriteMsg(c.fd, Request{Op: OpRegister, Guard: len(gfds)}, all)
	var r Response
	if err == nil {
		var got []int
		got, err = ReadMsg(c.fd, &r)
		CloseFDs(got)
	}
	c.mu.Unlock()
	if err == nil && !r.OK {
		err = &RefusedError{Msg: r.Error}
	}
	return r.Tag, append(skipped, r.Skipped...), err
}

// TagSelf tags the calling process (and with it every process it starts).
func (c *Conn) TagSelf() (string, error) {
	r, err := c.do(OpTagSelf, nil)
	return r.Tag, err
}

// TagOf returns the tag of a pid ("" when it is not an agent). The pid
// goes to the daemon as a pidfd, so it cannot be swapped for another
// process on the way.
func (c *Conn) TagOf(pid int) (string, error) {
	pfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return "", fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	defer unix.Close(pfd)
	r, err := c.do(OpTagOf, []int{pfd})
	return r.Tag, err
}

// ProtectPTS makes a terminal unopenable for every agent and for every
// process outside its session (a cotty session's pts). pts may be an
// O_PATH descriptor (the terminal need not be opened, or even unlocked,
// yet); master is its pty master. The protection lasts as long as the
// calling process runs (the kernel checks its pid and start time), across
// daemon restarts, until ReleasePTS. The caller must be a registered
// broker holding the master; a terminal another live process protected
// is refused.
func (c *Conn) ProtectPTS(pts, master int) (kept bool, err error) {
	r, err := c.doReq(Request{Op: OpProtectPTS}, []int{pts, master})
	return r.Kept, err
}

// CheckPTS returns nil when the terminal is protected for the caller, a
// *RefusedError when the daemon says it is not.
func (c *Conn) CheckPTS(fd int) error {
	_, err := c.do(OpCheckPTS, []int{fd})
	return err
}

// PTSException returns the running process that opened the terminal
// through the guard's exception list, nil when there is none. Only the
// process that protected the terminal may ask.
func (c *Conn) PTSException(fd int) (*ExceptionUse, error) {
	r, err := c.do(OpPTSException, []int{fd})
	return r.Exception, err
}

// ReleasePTS ends the caller's protection of a terminal.
func (c *Conn) ReleasePTS(fd int) error {
	_, err := c.do(OpReleasePTS, []int{fd})
	return err
}

// pathFD opens an O_PATH descriptor of the file f refers to. It is enough
// for the daemon (fstat, fstatfs) and, unlike the terminal itself, it is
// not a terminal anybody can read or write: the guard lets O_PATH
// descriptors of a protected pts travel (file_receive).
func pathFD(f *os.File) (int, error) {
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("O_PATH descriptor of %s: %w", f.Name(), err)
	}
	return fd, nil
}

// openSockets opens each socket path, or directory of sockets (or, with
// sockets false, each directory), with O_PATH. Missing paths are skipped
// quietly; others that cannot be used are reported.
func openSockets(paths []string, sockets bool) ([]int, []string) {
	var fds []int
	var skipped []string
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || seen[p] || len(fds) >= maxRequestFDs {
			continue
		}
		seen[p] = true
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			if !errors.Is(err, unix.ENOENT) {
				skipped = append(skipped, p+": "+err.Error())
			}
			continue
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
		case unix.S_IFSOCK:
			if !sockets {
				skipped = append(skipped, p+": not a directory")
				continue
			}
		default:
			skipped = append(skipped, p+": not a socket or a directory")
			continue
		}
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			skipped = append(skipped, p+": "+err.Error())
			continue
		}
		fds = append(fds, fd)
	}
	return fds, skipped
}

// ForAgent is called by `cotty agent` once it runs in the agent's own
// cgroup (cgroup is its cgroup v2 path, "" when it has none) and before
// it starts the agent: with a guard running, it registers the cgroup
// (or, without a usable cgroup, tags the launcher itself) together with
// the sockets the agent may still reach and the directories it may not
// change (guarded: the cotty runtime directory). Without a guard it does
// nothing and returns "". An error means the guard is running but
// refused, and the launcher should not start the agent.
func ForAgent(cgroup string, sockets, guarded []string) (string, []string, error) {
	c, err := Dial()
	if errors.Is(err, ErrNotRunning) {
		return "", nil, nil
	}
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			// The guard denies agents its socket: this process is already
			// an agent (cotty agent started inside an agent), and so is
			// everything it starts.
			return "", []string{"already an agent: the guard socket is closed to agents"}, nil
		}
		return "", nil, err
	}
	defer c.Close()
	if cgroup != "" && strings.HasPrefix(filepath.Base(cgroup), AgentCgroupPrefix) {
		return c.Register(sockets, guarded)
	}
	tag, err := c.TagSelf()
	return tag, []string{"no agent cgroup: tagged the launcher instead; the socket allowlist does not apply"}, err
}

// Guard implements peer.Guard for the broker (package guard does not
// import peer, so peer or the broker may import guard).
type Guard struct {
	mu       sync.Mutex
	loaded   bool
	checked  time.Time
	cacheTTL time.Duration
}

// New returns a peer.Guard backed by the daemon.
func New() *Guard { return &Guard{cacheTTL: 2 * time.Second} }

// Loaded reports whether the daemon answers and its programs are attached
// (cached for a short time).
func (g *Guard) Loaded() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if time.Since(g.checked) < g.cacheTTL {
		return g.loaded
	}
	g.checked = time.Now()
	g.loaded = false
	c, err := Dial()
	if err != nil {
		return false
	}
	defer c.Close()
	st, err := c.Status()
	g.loaded = err == nil && st.Loaded
	return g.loaded
}

// Tag returns the guard's tag for pid. Without a guard it is always "".
// With a guard, a failed lookup is an error, which the classifier treats
// as "not a person".
func (g *Guard) Tag(pid int) (string, error) {
	c, err := Dial()
	if errors.Is(err, ErrNotRunning) {
		g.mu.Lock()
		g.loaded, g.checked = false, time.Now()
		g.mu.Unlock()
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.TagOf(pid)
}

// RawOp sends any operation without descriptors and returns the tag of
// the answer (used by the escape matrix to try refused operations).
func RawOp(c *Conn, op string) (string, error) {
	r, err := c.do(op, nil)
	return r.Tag, err
}
