package confine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// watchedGitNames are files that redirect git when they appear in a git
// directory that lacks them: commondir points git at another directory
// for config and hooks.
var watchedGitNames = map[string]bool{"commondir": true}

// watchGitDirs watches dirs (outside the confinement, with inotify) for
// one of watchedGitNames appearing. On the first hit it removes the file,
// then calls hit with its path. The returned function stops the watch.
func watchGitDirs(dirs []string, hit func(path string)) (func(), error) {
	if len(dirs) == 0 {
		return func() {}, nil
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	wds := map[int32]string{}
	for _, d := range dirs {
		wd, err := unix.InotifyAddWatch(fd, d, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_ONLYDIR)
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("watch %s: %w", d, err)
		}
		wds[int32(wd)] = d
		// A file created before the watch started.
		for n := range watchedGitNames {
			if _, err := os.Lstat(filepath.Join(d, n)); err == nil {
				p := filepath.Join(d, n)
				_ = os.RemoveAll(p)
				go hit(p)
			}
		}
	}
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return
			}
			select {
			case <-stop:
				return
			default:
			}
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				name := ""
				if ev.Len > 0 {
					raw := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(ev.Len)]
					name = strings.TrimRight(string(raw), "\x00")
				}
				off += unix.SizeofInotifyEvent + int(ev.Len)
				if d, ok := wds[ev.Wd]; ok && watchedGitNames[name] {
					p := filepath.Join(d, name)
					_ = os.RemoveAll(p)
					hit(p)
				}
			}
		}
	}()
	// The descriptor stays open until the process exits: closing it under
	// the blocked read could hand its number to another file.
	return func() { close(stop) }, nil
}

// holdGitInitGuard takes a shared lock on the empty .git placed in a
// project without one, recreating it when another agent's cleanup removed
// it in between. The returned function releases the lock and removes the
// directory when it is still empty and no other agent holds it.
func holdGitInitGuard(p string) (func(), error) {
	for i := 0; i < 20; i++ {
		if err := os.Mkdir(p, 0o700); err != nil && !os.IsExist(err) {
			return nil, err
		}
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		if err := unix.Flock(fd, unix.LOCK_SH); err != nil {
			unix.Close(fd)
			return nil, err
		}
		var a, b unix.Stat_t
		if unix.Fstat(fd, &a) == nil && unix.Lstat(p, &b) == nil && a.Ino == b.Ino && a.Dev == b.Dev {
			return func() {
				// Exclusive only when no other agent holds it.
				if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) == nil {
					_ = syscall.Rmdir(p) // fails when not empty: then it stays
				}
				unix.Close(fd)
			}, nil
		}
		unix.Close(fd)
	}
	return nil, fmt.Errorf("%s keeps changing", p)
}
