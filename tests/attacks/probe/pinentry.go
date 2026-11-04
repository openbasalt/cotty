package main

// A stand-in for pinentry-curses started by gpg-agent with GPG_TTY: a
// program outside the session that opens the session pts by name, turns
// echo off, prints a prompt and reads a line (tests/attacks/guard-exceptions.sh).

import (
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func pinentryCommand(name string, args []string) bool {
	if name != "fake-pinentry" {
		return false
	}
	fakePinentry(args)
	return true
}

// fakePinentry: fake-pinentry PTS SECS [OUT]. Exit 1 when the open is
// refused, 0 once it opened (whatever it read). With OUT, the line read
// is written there (0600) so the test can compare it with what the
// person typed.
func fakePinentry(args []string) {
	if len(args) < 2 {
		skip("usage: fake-pinentry PTS SECS [OUT]")
	}
	fd, err := unix.Open(args[0], unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		denied("open %s: %v", args[0], err)
	}
	defer unix.Close(fd)
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		escaped("opened %s, but it is not a terminal: %v", args[0], err)
	}
	t := *old
	// Raw input without echo, as curses' raw()/noecho() leave it.
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Iflag &^= unix.ICRNL | unix.IXON
	// VMIN 1 as curses leaves it (VMIN 0 would make the session shell,
	// reading the same terminal, take a timed out read for an end of file).
	t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETSW, &t); err != nil {
		escaped("opened %s, termios refused: %v", args[0], err)
	}
	defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETSW, old) }()
	_, _ = unix.Write(fd, []byte("\r\nfake-pinentry PIN: "))
	deadline := time.Now().Add(time.Duration(atoi(args[1])) * time.Second)
	var line []byte
	buf := make([]byte, 64)
	for time.Now().Before(deadline) {
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if k, _ := unix.Poll(pfd, 100); k <= 0 {
			continue
		}
		n, err := unix.Read(fd, buf)
		if err != nil && err != syscall.EINTR && err != syscall.EAGAIN {
			break
		}
		if n <= 0 {
			continue
		}
		if i := strings.IndexAny(string(buf[:n]), "\r\n"); i >= 0 {
			line = append(line, buf[:i]...)
			break
		}
		line = append(line, buf[:n]...)
	}
	_, _ = unix.Write(fd, []byte("\r\n"))
	if len(args) > 2 {
		_ = os.WriteFile(args[2], append(line, '\n'), 0o600)
	}
	escaped("opened %s and read %d bytes", args[0], len(line))
}
