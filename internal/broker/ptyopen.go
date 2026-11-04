package broker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// openPTY opens a new pty so that no other process can open its slave
// before protect has run (review N2): a new pty starts locked (opening the
// slave fails with EIO), the slave is reached only through the master
// (TIOCGPTPEER), first as an O_PATH descriptor, which opens no terminal,
// for protect; only then is the pty unlocked and the slave opened for the
// shell. A process that watches /dev/pts and retries the open finds it
// locked first and protected after.
//
// protect may be nil (no guard configured). The returned closer is what
// protect returned (nil without protect).
func openPTY(rows, cols int, protect func(ptmx *os.File, pts int) (io.Closer, error)) (ptmx, tty *os.File, closer io.Closer, err error) {
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	// A non-blocking descriptor: os.NewFile hands it to the runtime poller.
	ptmx = os.NewFile(uintptr(mfd), "/dev/ptmx")
	fail := func(e error) (*os.File, *os.File, io.Closer, error) {
		if closer != nil {
			_ = closer.Close()
		}
		_ = ptmx.Close()
		return nil, nil, nil, e
	}
	n, err := unix.IoctlGetUint32(mfd, unix.TIOCGPTN)
	if err != nil {
		return fail(fmt.Errorf("TIOCGPTN: %w", err))
	}
	path := "/dev/pts/" + strconv.FormatUint(uint64(n), 10)
	if err := unix.IoctlSetWinsize(mfd, unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(rows), Col: uint16(cols)}); err != nil {
		return fail(fmt.Errorf("TIOCSWINSZ: %w", err))
	}
	if protect != nil {
		pfd, err := ptyPeer(mfd, path, unix.O_PATH)
		if err != nil {
			return fail(err)
		}
		closer, err = protect(ptmx, pfd)
		_ = unix.Close(pfd)
		if err != nil {
			return fail(fmt.Errorf("cotty-guard could not protect the session pts: %w", err))
		}
	}
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		return fail(fmt.Errorf("unlock the pty: %w", err))
	}
	tfd, err := ptyPeer(mfd, path, unix.O_RDWR)
	if err != nil {
		return fail(err)
	}
	return ptmx, os.NewFile(uintptr(tfd), path), closer, nil
}

// ptyPeer opens the slave of the pty master mfd through the master
// (TIOCGPTPEER, Linux 4.13), falling back to its path on older kernels.
func ptyPeer(mfd int, path string, mode int) (int, error) {
	flags := mode | unix.O_NOCTTY | unix.O_CLOEXEC
	fd, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mfd), uintptr(unix.TIOCGPTPEER), uintptr(flags))
	if errno == 0 {
		return int(fd), nil
	}
	if !errors.Is(errno, unix.ENOTTY) && !errors.Is(errno, unix.EINVAL) {
		return -1, fmt.Errorf("TIOCGPTPEER: %w", errno)
	}
	tfd, err := unix.Open(path, flags, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w", path, err)
	}
	return tfd, nil
}
