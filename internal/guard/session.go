package guard

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Session is the broker's side of layer 3 for one session: it registers
// the broker under the session name (RegisterBroker), claims its sockets
// (ClaimSocket), protects the session's pts (Protect, given to
// broker.Config.ProtectPTS) and, as the broker's peer.Guard, reports the
// guard as loaded only while that protection is confirmed alive by the
// daemon.
//
// The kernel keeps a protection as long as the broker process runs, across
// daemon restarts and whatever happens to the connection. The session
// still asks the daemon every CheckInterval (one request on a connection
// it keeps, reconnecting after a restart): while the daemon does not
// answer, the session is not reported `strong`. A protection that the
// daemon no longer knows (removed by `cotty-guard uninstall`, or never set
// up because the guard was not running when the session started) is a
// lapse: the pts may have been opened by anybody in the meantime, and such
// a descriptor stays usable, so the session is never `strong` again; it
// protects the pts again as soon as it can, for what that is worth.
//
// Requests to the daemon never run under mu: Loaded and Why, which the
// broker calls under its own lock, only read the last answer.
type Session struct {
	*Guard // tag lookups for the classifier

	interval time.Duration

	// io serializes the requests of check, Close and the registrations.
	io   sync.Mutex
	conn *Conn // used under io

	mu        sync.Mutex
	pts       int    // O_PATH descriptor of the session pts; -1 before Protect
	master    int    // a duplicate of the pty master (re-protection); -1 before Protect
	confirmed bool   // the daemon said the pts is protected for us, at the last check
	lapsed    bool   // the protection was missing at some point: never strong again
	why       string // the reason when not confirmed
	// name and brokerDirs are registered again after a daemon restart or
	// a late start (RegisterBroker); socks are claimed again.
	name       string
	brokerDirs []string
	socks      map[int]string // slot -> socket path
	stop       chan struct{}
	done       chan struct{}
}

// CheckInterval is how often a Session asks the daemon about its
// protection.
const CheckInterval = 2 * time.Second

// NewSession returns a Session; call Protect once the pts exists.
func NewSession() *Session {
	return &Session{Guard: New(), interval: CheckInterval, pts: -1, master: -1,
		why: "the session pts is not protected yet", socks: map[int]string{}}
}

// Protect protects the session pts before the shell starts and before
// anybody can open it: pts is an O_PATH descriptor of the slave, taken
// while the pty is still locked, and ptmx its master. A running guard that
// refuses is an error (the session must not start). Without a guard the
// session runs unprotected: the returned closer is valid, and the session
// protects the pts if the guard starts later, but it is not reported
// `strong`.
func (s *Session) Protect(ptmx *os.File, pts int) (io.Closer, error) {
	fd, err := unix.FcntlInt(uintptr(pts), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	mfd, err := dupFile(ptmx)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	s.io.Lock()
	defer s.io.Unlock()
	s.mu.Lock()
	if s.pts >= 0 {
		s.mu.Unlock()
		_ = unix.Close(fd)
		_ = unix.Close(mfd)
		return nil, errors.New("guard session: Protect called twice")
	}
	s.pts, s.master = fd, mfd
	s.mu.Unlock()
	c, err := Dial()
	switch {
	case errors.Is(err, ErrNotRunning):
		s.mu.Lock()
		s.lapsed, s.why = true, "cotty-guard was not running when the session started"
		s.mu.Unlock()
	case err != nil:
		s.closeFDs()
		return nil, err
	default:
		if _, err := c.ProtectPTS(fd, mfd); err != nil {
			c.Close()
			s.closeFDs()
			return nil, err
		}
		s.conn = c
		s.mu.Lock()
		s.confirmed, s.why = true, ""
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.stop, s.done = make(chan struct{}), make(chan struct{})
	stop, done := s.stop, s.done
	s.mu.Unlock()
	go s.watch(stop, done)
	return s, nil
}

func (s *Session) closeFDs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pts >= 0 {
		_ = unix.Close(s.pts)
	}
	if s.master >= 0 {
		_ = unix.Close(s.master)
	}
	s.pts, s.master = -1, -1
}

// dupFile duplicates the descriptor of f without putting f into blocking
// mode (os.File.Fd would).
func dupFile(f *os.File) (int, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return -1, err
	}
	nfd := -1
	var derr error
	if err := raw.Control(func(fd uintptr) { nfd, derr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 3) }); err != nil {
		return -1, err
	}
	return nfd, derr
}

// Loaded reports whether the session's pts protection is confirmed alive
// (so the session may be reported `strong`). It never blocks on the
// daemon: the answer is the last check's.
func (s *Session) Loaded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.confirmed && !s.lapsed
}

// Why says why Loaded is false ("" when it is true).
func (s *Session) Why() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.confirmed && !s.lapsed {
		return ""
	}
	return s.why
}

// PTSException asks the daemon whether a process outside the session
// opened the session pts through the exception list and still runs (the
// broker then lights the lock for it). It never dials: without a
// connection (no guard, or a daemon restart under way) it answers
// ErrNotRunning, so the broker knows the guard cannot tell (and watches
// the pts itself), and the next periodic check reconnects.
func (s *Session) PTSException() (pid int, start uint64, exe string, err error) {
	s.io.Lock()
	defer s.io.Unlock()
	s.mu.Lock()
	pts := s.pts
	s.mu.Unlock()
	if s.conn == nil || pts < 0 {
		return 0, 0, "", ErrNotRunning
	}
	u, err := s.conn.PTSException(pts)
	if err != nil || u == nil {
		return 0, 0, "", err
	}
	return u.PID, u.Start, u.Exe, nil
}

// Close releases the protection (the session ended) and stops checking.
func (s *Session) Close() error {
	s.mu.Lock()
	stop, done := s.stop, s.done
	s.stop = nil
	s.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
	s.io.Lock()
	defer s.io.Unlock()
	s.mu.Lock()
	pts := s.pts
	s.mu.Unlock()
	if s.conn != nil && pts >= 0 {
		_ = s.conn.ReleasePTS(pts)
	}
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.closeFDs()
	s.mu.Lock()
	s.confirmed, s.why = false, "the session ended"
	s.mu.Unlock()
	return nil
}

func (s *Session) watch(stop, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.check()
		}
	}
}

// check asks the daemon whether the pts is still protected for this
// process, reconnecting once when the connection broke (a restart).
func (s *Session) check() {
	s.io.Lock()
	defer s.io.Unlock()
	s.mu.Lock()
	pts, master, confirmed := s.pts, s.master, s.confirmed
	name, dirs := s.name, append([]string(nil), s.brokerDirs...)
	socks := map[int]string{}
	for k, v := range s.socks {
		socks[k] = v
	}
	s.mu.Unlock()
	if pts < 0 {
		return
	}
	set := func(f func()) {
		s.mu.Lock()
		f()
		s.mu.Unlock()
	}
	for attempt := 0; attempt < 2; attempt++ {
		if s.conn == nil {
			c, err := Dial()
			if err != nil {
				set(func() { s.confirmed, s.why = false, fmt.Sprintf("cotty-guard does not answer: %v", err) })
				return
			}
			s.conn = c
			// A new connection is a new daemon, or one that lost its
			// state: register again whatever the last check said (review
			// G7).
			confirmed = false
		}
		err := s.conn.CheckPTS(pts)
		if name != "" && !confirmed {
			// After a restart or a late start: register the broker again
			// (idempotent for the name's holder) and claim its sockets, so
			// its runtime directories and sockets stay its own.
			if s.conn.registerBroker(name, dirs) == nil {
				for slot, p := range socks {
					_ = s.conn.claimSocket(name, slot, p)
				}
			}
		}
		var refused *RefusedError
		switch {
		case err == nil:
			set(func() {
				s.confirmed = true
				if !s.lapsed {
					s.why = ""
				}
			})
			return
		case errors.As(err, &refused):
			// The daemon answers, and the pts is not protected for us.
			set(func() {
				s.lapsed, s.confirmed = true, false
				s.why = "the session pts was unprotected for a while (" + refused.Msg + "); a process may have opened it"
			})
			// Best effort: protect it again from here on.
			_, _ = s.conn.ProtectPTS(pts, master)
			return
		default:
			// The connection broke (daemon restarted or stopped).
			s.conn.Close()
			s.conn = nil
			set(func() { s.confirmed, s.why = false, fmt.Sprintf("lost the connection to cotty-guard: %v", err) })
		}
	}
}
