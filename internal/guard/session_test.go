package guard

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeDaemon answers the session protocol on a socket in a temporary
// directory, as the test's user (daemonUID is set to it). protected says
// whether check-pts succeeds.
type fakeDaemon struct {
	t         *testing.T
	path      string
	mu        sync.Mutex
	lfd       int
	conns     []int
	protected bool
	protects  int
	silent    bool // read requests, never answer (a stuck daemon)
	stopped   bool
	// wg counts serve and the connection goroutines. stop waits for them
	// before closing any descriptor: a goroutine still using a closed
	// descriptor number would read from whatever reuses it next (the
	// next test's daemon socket) and answer for the wrong fake.
	wg sync.WaitGroup
}

func startFake(t *testing.T, path string, protected bool) *fakeDaemon {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(path)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 8); err != nil {
		t.Fatal(err)
	}
	f := &fakeDaemon{t: t, path: path, lfd: fd, protected: protected}
	f.wg.Add(1)
	go f.serve()
	return f
}

func (f *fakeDaemon) serve() {
	defer f.wg.Done()
	for {
		c, _, err := unix.Accept4(f.lfd, unix.SOCK_CLOEXEC)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return
		}
		f.mu.Lock()
		if f.stopped {
			f.mu.Unlock()
			_ = unix.Close(c)
			return
		}
		f.conns = append(f.conns, c)
		f.wg.Add(1)
		f.mu.Unlock()
		go func(c int) {
			defer f.wg.Done()
			for {
				var req Request
				fds, err := ReadMsg(c, &req)
				if err != nil {
					return
				}
				CloseFDs(fds)
				f.mu.Lock()
				if f.silent {
					f.mu.Unlock()
					continue
				}
				resp := Response{OK: true}
				switch req.Op {
				case OpProtectPTS:
					f.protects++
					f.protected = true
				case OpCheckPTS:
					if !f.protected {
						resp = Response{Error: "the terminal is not protected"}
					}
				}
				f.mu.Unlock()
				if WriteMsg(c, resp, nil) != nil {
					return
				}
			}
		}(c)
	}
}

// stop closes the listener and every connection: a daemon restart.
// Shutdown wakes the goroutines blocked in accept or recvmsg; the
// descriptors are closed only once they have all returned.
func (f *fakeDaemon) stop() {
	f.mu.Lock()
	f.stopped = true
	_ = unix.Shutdown(f.lfd, unix.SHUT_RDWR)
	conns := f.conns
	f.conns = nil
	for _, c := range conns {
		_ = unix.Shutdown(c, unix.SHUT_RDWR)
	}
	f.mu.Unlock()
	f.wg.Wait()
	_ = unix.Close(f.lfd)
	for _, c := range conns {
		_ = unix.Close(c)
	}
	_ = os.Remove(f.path)
}

func (f *fakeDaemon) set(protected bool) {
	f.mu.Lock()
	f.protected = protected
	f.mu.Unlock()
}

func withFakeSocket(t *testing.T) string {
	t.Helper()
	oldPath, oldUID := socketPath, daemonUID
	socketPath, daemonUID = filepath.Join(t.TempDir(), "guard.sock"), uint32(os.Getuid())
	t.Cleanup(func() { socketPath, daemonUID = oldPath, oldUID })
	return socketPath
}

func newTestSession() *Session {
	s := NewSession()
	s.interval = 20 * time.Millisecond
	return s
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// B4: the broker reports strong only while the daemon confirms the
// protection; a daemon that stops answering, then comes back (a restart)
// with the protection kept, gives strong back.
func TestSessionStrongOnlyWhileConfirmed(t *testing.T) {
	path := withFakeSocket(t)
	d := startFake(t, path, false)
	s := newTestSession()
	if s.Loaded() {
		t.Fatal("strong before Protect")
	}
	c, err := s.Protect(devNull(t), int(devNull(t).Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !s.Loaded() {
		t.Fatalf("not strong right after Protect: %s", s.Why())
	}
	d.stop()
	waitFor(t, "not strong while the daemon is down", func() bool { return !s.Loaded() })
	d2 := startFake(t, path, true)
	defer d2.stop()
	waitFor(t, "strong again after the restart", s.Loaded)
}

// B4/B5: when the daemon no longer knows the protection (it lapsed), the
// session is never strong again, even after it protects the pts anew.
func TestSessionLapseIsPermanent(t *testing.T) {
	path := withFakeSocket(t)
	d := startFake(t, path, false)
	defer d.stop()
	s := newTestSession()
	c, err := s.Protect(devNull(t), int(devNull(t).Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	d.set(false)
	waitFor(t, "lapse detected", func() bool { return !s.Loaded() })
	// check marks the lapse before it sends the new protect request, so
	// the request may not have reached the daemon yet: wait for it rather
	// than reading the count right away.
	waitFor(t, "the pts protected again", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.protects >= 2
	})
	// Wait for a later check that the daemon confirms (the fake keeps the
	// new protection): even then the session must not be strong.
	waitFor(t, "the new protection confirmed", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.confirmed
	})
	if s.Loaded() {
		t.Fatal("strong again after a lapse")
	}
}

// A session started while no guard runs is unprotected: never strong,
// even once a guard starts and protects it late.
func TestSessionWithoutGuardAtStart(t *testing.T) {
	path := withFakeSocket(t)
	s := newTestSession()
	c, err := s.Protect(devNull(t), int(devNull(t).Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if s.Loaded() {
		t.Fatal("strong without a guard")
	}
	d := startFake(t, path, false)
	defer d.stop()
	waitFor(t, "late protection", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.protects > 0
	})
	time.Sleep(100 * time.Millisecond)
	if s.Loaded() {
		t.Fatal("strong after a late protection")
	}
	if s.Why() == "" {
		t.Fatal("no reason given")
	}
}

// N10: a daemon that stops answering never blocks Loaded (the broker asks
// it under its own lock), and the session stops being strong once the
// request times out.
func TestSessionSilentDaemonDoesNotBlock(t *testing.T) {
	path := withFakeSocket(t)
	old := clientTimeout
	clientTimeout = 300 * time.Millisecond
	t.Cleanup(func() { clientTimeout = old })
	d := startFake(t, path, true)
	defer d.stop()
	s := newTestSession()
	c, err := s.Protect(devNull(t), int(devNull(t).Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	d.mu.Lock()
	d.silent = true
	d.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		start := time.Now()
		_ = s.Loaded()
		_ = s.Why()
		if el := time.Since(start); el > 50*time.Millisecond {
			t.Fatalf("Loaded blocked for %v while the daemon was silent", el)
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitFor(t, "not strong once the silent daemon timed out", func() bool { return !s.Loaded() })
}

// N10: with the guard's marker present and no daemon, the attach client
// gets an error instead of silently skipping the broker check; without
// the marker it gets no verifier.
func TestClientVerifierFailsClosed(t *testing.T) {
	withFakeSocket(t)
	oldMarker := markerPath
	t.Cleanup(func() { markerPath = oldMarker })
	markerPath = filepath.Join(t.TempDir(), "enforcing")
	if v, err := ClientVerifier(); v != nil || err != nil {
		t.Fatalf("no guard, no marker: want nil, nil; got %v, %v", v, err)
	}
	if err := os.WriteFile(markerPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !Enforcing() {
		t.Fatal("marker not seen")
	}
	if _, err := ClientVerifier(); !errors.Is(err, ErrGuardSilent) {
		t.Fatalf("marker without a daemon: want ErrGuardSilent, got %v", err)
	}
	// A marker that is a symlink, or in a directory others may write, is
	// not trusted (Lstat, mode check).
	link := filepath.Join(t.TempDir(), "enforcing")
	if err := os.Symlink(markerPath, link); err != nil {
		t.Fatal(err)
	}
	markerPath = link
	if Enforcing() {
		t.Fatal("a symlinked marker was trusted")
	}
}
