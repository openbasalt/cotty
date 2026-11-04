//go:build linux

package daemon

// The pts exception list (docs/guard.md, The pts exception list): a
// root-owned file naming the executables that may open a protected
// session pts without it being their controlling terminal, such as a
// pinentry-curses started by gpg-agent with GPG_TTY. This file holds the
// parts that do not touch the kernel (parsing and the ownership checks),
// so they are unit tested on any host.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxExceptions is the size of the pts_exceptions map.
const maxExceptions = 256

// maxExceptionsFile bounds the configuration file.
const maxExceptionsFile = 64 << 10

// parseExceptions reads the list: one absolute path per line, blank lines
// and lines starting with # ignored. A line that is not a clean absolute
// path is reported and skipped; duplicates count once.
func parseExceptions(r io.Reader) (paths []string, problems []string) {
	sc := bufio.NewScanner(io.LimitReader(r, maxExceptionsFile))
	seen := map[string]bool{}
	n := 0
	for sc.Scan() {
		n++
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		switch {
		case !filepath.IsAbs(l):
			problems = append(problems, fmt.Sprintf("line %d: %q is not an absolute path", n, l))
			continue
		case filepath.Clean(l) != l:
			problems = append(problems, fmt.Sprintf("line %d: %q is not a clean path (write it as %s)", n, l, filepath.Clean(l)))
			continue
		case strings.ContainsAny(l, " \t"):
			problems = append(problems, fmt.Sprintf("line %d: %q holds a space (one path per line, nothing else)", n, l))
			continue
		}
		if seen[l] {
			continue
		}
		if len(paths) >= maxExceptions {
			problems = append(problems, fmt.Sprintf("line %d: more than %d entries; the rest is ignored", n, maxExceptions))
			break
		}
		seen[l] = true
		paths = append(paths, l)
	}
	if err := sc.Err(); err != nil {
		problems = append(problems, err.Error())
	}
	return paths, problems
}

// errNoExceptions is returned by readExceptionsFile when the file does not
// exist (no exception: the default).
var errNoExceptions = errors.New("no exception list")

// readExceptionsFile opens the list without following a symbolic link and
// checks that nobody but root can change it: the file must be a regular
// file owned by owner (root) and not writable by group or others, and so
// must every directory above it. Anything else refuses the whole list,
// with an error that says why.
func readExceptionsFile(path string, owner uint32) ([]string, []string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, errNoExceptions
	}
	if err != nil {
		return nil, nil, fmt.Errorf("refusing %s: %v; no exception applies", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("refusing %s: %v; no exception applies", path, err)
	}
	if err := closedToOthers(fi, owner, false); err != nil {
		return nil, nil, fmt.Errorf("refusing %s: %v (it must be a regular file owned by root and not writable by group or others); no exception applies", path, err)
	}
	if err := dirsClosed(filepath.Dir(path), owner); err != nil {
		return nil, nil, fmt.Errorf("refusing %s: %v; no exception applies", path, err)
	}
	paths, problems := parseExceptions(f)
	return paths, problems, nil
}

// closedToOthers checks one file: owned by owner, not writable by group
// or others, a directory when dir is set and a regular file otherwise.
func closedToOthers(fi fs.FileInfo, owner uint32, dir bool) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no ownership information")
	}
	switch {
	case dir && !fi.IsDir():
		return errors.New("not a directory")
	case !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("not a regular file (%s)", fi.Mode().Type())
	case st.Uid != owner:
		return fmt.Errorf("owned by uid %d", st.Uid)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("mode %04o is writable by group or others", fi.Mode().Perm())
	}
	return nil
}

// dirsClosed checks dir and every directory above it.
func dirsClosed(dir string, owner uint32) error {
	for d := dir; ; d = filepath.Dir(d) {
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		if err := closedToOthers(fi, owner, true); err != nil {
			return fmt.Errorf("directory %s: %v", d, err)
		}
		if d == "/" || d == "." {
			return nil
		}
	}
}

// exceptionExe is a listed executable, resolved.
type exceptionExe struct {
	Path string // as listed
	Real string // after symbolic links
	Dev  uint64 // st_dev, userspace encoding (what stat shows)
	Ino  uint64
	// KDev is the device of the file's superblock in the kernel's
	// encoding (super_block.s_dev, what the programs read). On btrfs it
	// differs from st_dev, which names the subvolume.
	KDev uint64
	// Gen is the inode generation (FS_IOC_GETVERSION); AnyGen when the
	// filesystem does not report one (the programs then match device and
	// inode only, which only filesystems with one inode number space per
	// superblock may do).
	Gen    uint32
	AnyGen bool
}

// resolveException finds the file a listed path names. Symbolic links are
// followed (a distribution's /usr/bin/pinentry is often one); the file
// they end at must be a root-owned executable regular file closed to
// group and others, in directories closed the same way, so that nobody
// but root can put another file there. The kernel then matches the
// executable a process runs by this file's device and inode: a copy at
// another path is another file and does not pass; a symbolic link to the
// listed file, or a hard link, runs this very file and does.
func resolveException(path string, owner uint32) (exceptionExe, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return exceptionExe{}, err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return exceptionExe{}, err
	}
	if err := closedToOthers(fi, owner, false); err != nil {
		return exceptionExe{}, fmt.Errorf("%s: %v", real, err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		return exceptionExe{}, fmt.Errorf("%s is not executable", real)
	}
	if err := dirsClosed(filepath.Dir(real), owner); err != nil {
		return exceptionExe{}, fmt.Errorf("%s: %v", real, err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	e := exceptionExe{Path: path, Real: real, Dev: st.Dev, Ino: st.Ino}
	if err := kernelIdentity(&e); err != nil {
		return exceptionExe{}, fmt.Errorf("%s: %v", real, err)
	}
	return e, nil
}

// fsIocGetversion is FS_IOC_GETVERSION, _IOR('v', 1, long): the encoding
// of FS_IOC_GETFLAGS, _IOR('f', 1, long), with type 'v' (x/sys/unix has
// no constant for it; this keeps every architecture's encoding).
const fsIocGetversion = unix.FS_IOC_GETFLAGS&^0xff00 | 'v'<<8

// Filesystems whose superblock holds several inode number spaces
// (subvolumes): an exception there needs the inode generation.
const (
	btrfsMagic    = 0x9123683e
	bcachefsMagic = 0xca451a4e
)

// kernelIdentity fills in what the programs compare: the superblock's
// device (from the mount the file is on, /proc/self/mountinfo, which shows
// super_block.s_dev) and the inode generation.
func kernelIdentity(e *exceptionExe) error {
	f, err := os.OpenFile(e.Real, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	fd := int(f.Fd())
	var sx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_MNT_ID, &sx); err != nil {
		return fmt.Errorf("statx: %v", err)
	}
	if sx.Mask&unix.STATX_MNT_ID == 0 || sx.Ino != e.Ino {
		return errors.New("the kernel gave no mount id (Linux 5.8 or later is needed), or the file changed")
	}
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	kdev, ok := mountDev(string(mi), sx.Mnt_id)
	if !ok {
		return fmt.Errorf("mount %d is not in /proc/self/mountinfo", sx.Mnt_id)
	}
	e.KDev = kdev
	gen, err := unix.IoctlGetInt(fd, fsIocGetversion)
	if err == nil {
		e.Gen = uint32(gen)
		return nil
	}
	var sfs unix.Statfs_t
	if serr := unix.Fstatfs(fd, &sfs); serr != nil {
		return serr
	}
	if uint32(sfs.Type) == btrfsMagic || uint32(sfs.Type) == bcachefsMagic {
		return fmt.Errorf("no inode generation on a filesystem with subvolumes: %v", err)
	}
	e.AnyGen = true
	return nil
}

// mountDev finds mount id in mountinfo text and returns its device
// (field 3, major:minor of the superblock) in the kernel's encoding.
func mountDev(mountinfo string, id uint64) (uint64, bool) {
	for _, l := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		if mid, err := strconv.ParseUint(f[0], 10, 64); err != nil || mid != id {
			continue
		}
		maj, min, ok := strings.Cut(f[2], ":")
		if !ok {
			return 0, false
		}
		a, err1 := strconv.ParseUint(maj, 10, 32)
		b, err2 := strconv.ParseUint(min, 10, 32)
		if err1 != nil || err2 != nil {
			return 0, false
		}
		return a<<20 | b, true
	}
	return 0, false
}
