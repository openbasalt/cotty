//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseExceptions(t *testing.T) {
	in := `# pinentry for gpg-agent with GPG_TTY
/usr/bin/pinentry-curses

  /usr/bin/pinentry-tty  
/usr/bin/pinentry-curses
pinentry-curses
/usr/bin/../bin/pinentry
/usr/bin/pinentry-curses --debug
`
	paths, problems := parseExceptions(strings.NewReader(in))
	want := []string{"/usr/bin/pinentry-curses", "/usr/bin/pinentry-tty"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("paths %q, want %q", paths, want)
	}
	if len(problems) != 3 {
		t.Errorf("problems %q, want 3 (relative, unclean, with arguments)", problems)
	}
	if p, pr := parseExceptions(strings.NewReader("")); len(p) != 0 || len(pr) != 0 {
		t.Errorf("empty file: %q %q", p, pr)
	}
}

func TestParseExceptionsLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxExceptions+5; i++ {
		b.WriteString("/usr/bin/p" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + "/" + strings.Repeat("y", i) + "\n")
	}
	paths, problems := parseExceptions(strings.NewReader(b.String()))
	if len(paths) != maxExceptions || len(problems) == 0 {
		t.Errorf("%d paths, %d problems; want %d and a note", len(paths), len(problems), maxExceptions)
	}
}

// writeList writes the list into a fresh directory closed to others and
// returns its path. The tests stand in the current user for root (the
// owner checks take the owner uid as a parameter).
func writeList(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "guard-exceptions.conf")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadExceptionsFilePermissions(t *testing.T) {
	me := uint32(os.Getuid())
	// The test's temporary directories sit under directories of other
	// owners (/tmp is root's and world-writable): check the file itself
	// and its own directory, as dirsClosed would above it.
	ok := writeList(t, "/usr/bin/pinentry-curses\n", 0o644)
	f, err := os.Open(ok)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := f.Stat()
	f.Close()
	if err := closedToOthers(fi, me, false); err != nil {
		t.Errorf("a 0644 file of the owner refused: %v", err)
	}
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666} {
		p := writeList(t, "/usr/bin/pinentry-curses\n", mode)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := closedToOthers(fi, me, false); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Errorf("mode %04o accepted (%v)", mode, err)
		}
	}
	if err := closedToOthers(fi, me+1, false); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("a file of another owner accepted (%v)", err)
	}
	// The whole file is refused when its directories are not closed: /tmp
	// (world-writable, sticky) is above every test directory.
	if _, _, err := readExceptionsFile(ok, me); err == nil || !strings.Contains(err.Error(), "no exception applies") {
		t.Errorf("a list under a world-writable directory accepted (%v)", err)
	}
	// A symbolic link is never followed.
	link := filepath.Join(filepath.Dir(ok), "link.conf")
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readExceptionsFile(link, me); err == nil || err == errNoExceptions {
		t.Errorf("a symbolic link was followed (%v)", err)
	}
	// Absent: no exception, and no error to report.
	if _, _, err := readExceptionsFile(filepath.Join(filepath.Dir(ok), "absent.conf"), me); err != errNoExceptions {
		t.Errorf("absent file: %v, want errNoExceptions", err)
	}
	// A directory in place of the file.
	if _, _, err := readExceptionsFile(filepath.Dir(ok), me); err == nil {
		t.Error("a directory accepted as the list")
	}
}

// A root-owned system file passes the ownership checks with root as the
// owner; a user's file does not (the guard trusts only root's files).
func TestResolveException(t *testing.T) {
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip(err)
	}
	e, err := resolveException("/bin/sh", 0)
	if err != nil {
		t.Skipf("/bin/sh is not a root-owned file in root-owned directories here: %v", err)
	}
	if e.Real != sh || e.Ino == 0 {
		t.Errorf("resolved %+v, want %s", e, sh)
	}
	own := filepath.Join(t.TempDir(), "pinentry-curses")
	if err := os.WriteFile(own, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if _, err := resolveException(own, 0); err == nil {
			t.Error("a user's executable accepted as an exception")
		}
	}
	if _, err := resolveException("/nonexistent/pinentry", 0); err == nil {
		t.Error("a missing executable accepted")
	}
	noexec := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(noexec, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveException(noexec, uint32(os.Getuid())); err == nil {
		t.Error("a file without execute permission accepted")
	}
}

func TestMountDev(t *testing.T) {
	mi := `67 1 0:32 /root / rw,relatime shared:1 - btrfs /dev/vda3 rw,subvol=/root
56 67 0:32 /home /home rw,relatime shared:160 - btrfs /dev/vda3 rw,subvol=/home
164 57 253:2 / /boot/efi rw,relatime shared:175 - vfat /dev/vda2 rw
`
	if d, ok := mountDev(mi, 164); !ok || d != 253<<20|2 {
		t.Errorf("mount 164: %d %v", d, ok)
	}
	if d, ok := mountDev(mi, 67); !ok || d != 32 {
		t.Errorf("mount 67: %d %v", d, ok)
	}
	if _, ok := mountDev(mi, 1); ok {
		t.Error("a parent id taken for a mount id")
	}
}
