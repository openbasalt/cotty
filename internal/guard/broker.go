package guard

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// RegisterBroker makes the calling process (a broker) the registered
// broker of session name: in dirs (the cotty runtime directory and its
// agent directory) only registered brokers may then bind, link, rename or
// remove, so no other process of the user can replace the socket a person
// attaches to, and the name is this broker's while it runs (a second
// broker with the same name is refused, and verify-broker vouches only for
// this process). It is called before the broker binds its sockets, and
// again by the session after a daemon restart. Without a guard it returns
// nil and remembers the name and directories for a later registration.
func (s *Session) RegisterBroker(name string, dirs []string) error {
	s.mu.Lock()
	s.name, s.brokerDirs = name, append([]string(nil), dirs...)
	s.mu.Unlock()
	s.io.Lock()
	defer s.io.Unlock()
	c, err := Dial()
	if errors.Is(err, ErrNotRunning) {
		return nil
	}
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.registerBroker(name, dirs); err != nil {
		return fmt.Errorf("cotty-guard refused to register this broker (with the guard loaded, cotty must be installed root-owned in a configured path, and a session name belongs to its first broker): %w", err)
	}
	return nil
}

// ClaimSocket asks the guard to keep the socket the broker just bound at
// path (slot 0: the person socket, 1: the agent socket) its own: nobody
// else, another broker included, may remove, rename or replace it while
// the broker runs. Without a guard it returns nil and remembers the socket
// for a later claim.
func (s *Session) ClaimSocket(slot int, path string) error {
	s.mu.Lock()
	name := s.name
	s.socks[slot] = path
	s.mu.Unlock()
	s.io.Lock()
	defer s.io.Unlock()
	c, err := Dial()
	if errors.Is(err, ErrNotRunning) {
		return nil
	}
	if err != nil {
		return err
	}
	defer c.Close()
	return c.claimSocket(name, slot, path)
}

func (c *Conn) registerBroker(name string, dirs []string) error {
	fds, skipped := openSockets(dirs, false)
	defer CloseFDs(fds)
	if len(skipped) > 0 {
		return fmt.Errorf("runtime directories: %v", skipped)
	}
	_, err := c.doReq(Request{Op: OpRegisterBroker, Name: name}, fds)
	return err
}

func (c *Conn) claimSocket(name string, slot int, path string) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, err = c.doReq(Request{Op: OpClaimSocket, Name: name, Slot: slot}, []int{fd})
	return err
}

// BrokerVerifier is the attach client's check of a session listener
// (attach.BrokerVerifier), answered by the guard as root: the listener must
// be the registered broker of the session (the first broker that
// registered its name and still runs) running the installed cotty binary.
type BrokerVerifier struct{}

// VerifyBroker sends the client's connected socket to the guard, which
// looks at the process on its other end. pid is the listener's pid as the
// client's SO_PEERCRED gives it; the guard's answer must match it.
func (BrokerVerifier) VerifyBroker(conn *net.UnixConn, session string, pid int) error {
	if conn == nil {
		return errors.New("not a Unix socket")
	}
	c, err := Dial()
	if err != nil {
		return fmt.Errorf("cannot ask cotty-guard: %w", err)
	}
	defer c.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var r Response
	var derr error
	if err := raw.Control(func(fd uintptr) {
		r, derr = c.doReq(Request{Op: OpVerifyBroker, Name: session}, []int{int(fd)})
	}); err != nil {
		return err
	}
	if derr != nil {
		return derr
	}
	if r.PID != pid {
		return fmt.Errorf("the guard verified pid %d, the connection says %d", r.PID, pid)
	}
	return nil
}

// ErrGuardSilent is returned by ClientVerifier when the guard enforces
// (its marker exists) but the daemon does not answer.
var ErrGuardSilent = errors.New("cotty-guard is installed and enforcing but its daemon does not answer; " +
	"the session's broker cannot be verified (start it: systemctl start cotty-guard; or remove the guard: cotty-guard uninstall)")

// markerPath is EnforcingMarker (a variable for tests).
var markerPath = EnforcingMarker

// Enforcing tells whether the guard's marker says the pinned programs
// enforce (the marker must be a root-owned regular file in a root-owned
// directory, so no user process can fake or hide it short of root).
func Enforcing() bool {
	var st unix.Stat_t
	if unix.Lstat(markerPath, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != daemonUID {
		return false
	}
	var dst unix.Stat_t
	dir := filepath.Dir(markerPath)
	return unix.Lstat(dir, &dst) == nil && dst.Mode&unix.S_IFMT == unix.S_IFDIR && dst.Uid == daemonUID && dst.Mode&0o022 == 0
}

// ClientVerifier returns the verifier the attach client must use: the
// guard's when its daemon answers, nil when no guard is installed, and
// ErrGuardSilent when the guard enforces but does not answer (the client
// then refuses to attach rather than skip the check).
func ClientVerifier() (*BrokerVerifier, error) {
	c, err := Dial()
	if err == nil {
		st, serr := c.Status()
		c.Close()
		if serr == nil && st.Loaded {
			return &BrokerVerifier{}, nil
		}
	}
	if Enforcing() {
		return nil, ErrGuardSilent
	}
	if err != nil && !errors.Is(err, ErrNotRunning) {
		// Something answers on the guard socket that is not the guard.
		return nil, err
	}
	return nil, nil
}
