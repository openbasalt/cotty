package guard

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/audit"
)

func TestTagRoundTrip(t *testing.T) {
	if FormatTag(0) != "" {
		t.Fatal("agent 0 must have no tag")
	}
	for _, id := range []uint64{1, 5769, 1<<63 | 12345} {
		got, err := ParseTag(FormatTag(id))
		if err != nil || got != id {
			t.Fatalf("round trip %d: %d %v", id, got, err)
		}
	}
	if _, err := ParseTag("person"); err == nil {
		t.Fatal("bad tag accepted")
	}
}

func TestKernelDev(t *testing.T) {
	// st_dev 0:59 (the userspace encoding) is 59 in the kernel's.
	if got := KernelDev(unix.Mkdev(0, 59)); got != 59 {
		t.Fatalf("0:59 -> %d", got)
	}
	// 259:3 -> 259<<20 | 3.
	if got := KernelDev(unix.Mkdev(259, 3)); got != 259<<20|3 {
		t.Fatalf("259:3 -> %d", got)
	}
	// Minors above 255 use the split encoding in userspace.
	if got := KernelDev(unix.Mkdev(8, 300)); got != 8<<20|300 {
		t.Fatalf("8:300 -> %d", got)
	}
}

func TestWithoutCapability(t *testing.T) {
	got := withoutCapability([]string{"lockdown", "capability", "yama", "apparmor"})
	if len(got) != 3 || got[0] != "lockdown" || got[2] != "apparmor" {
		t.Fatalf("%v", got)
	}
}

func TestReadFactsRuns(t *testing.T) {
	f := ReadFacts()
	if f.Explain == "" {
		t.Fatal("no explanation")
	}
	if f.LSMKnown && !f.BPFLSM && f.BootParam == "" {
		t.Fatal("missing boot parameter advice")
	}
}

func TestDedup(t *testing.T) {
	d := NewDedup(time.Second)
	now := time.Now()
	x := Denial{TGID: 10, Hook: 2, Reason: 2, Target: 5}
	if !d.Admit(x, now) {
		t.Fatal("first denial dropped")
	}
	if d.Admit(x, now.Add(100*time.Millisecond)) {
		t.Fatal("repeat admitted")
	}
	if !d.Admit(x, now.Add(2*time.Second)) {
		t.Fatal("repeat after the window dropped")
	}
	y := x
	y.Target = 6
	if !d.Admit(y, now.Add(100*time.Millisecond)) {
		t.Fatal("different target dropped")
	}
}

func TestDenialRecord(t *testing.T) {
	r := Denial{Agent: 42, Hook: 2, Reason: 2, TGID: uint32(os.Getpid()), Target: 1, Dev: 22, Ino: 4026531841, Comm: "cat", Name: "environ"}.Record()
	if r.Event != "guard.denial" || r.Outcome != "denied" || r.Subject.Role != "agent" {
		t.Fatalf("%+v", r)
	}
	if r.Data["agent"] != "agent:42" || r.Data["hook"] != "file_open" || r.Data["name"] != "environ" {
		t.Fatalf("%+v", r.Data)
	}
	if r.UID != os.Getuid() {
		t.Fatalf("uid %d", r.UID)
	}
}

func TestMessagesWithDescriptors(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := WriteMsg(fds[0], Request{Op: OpTagOf}, []int{int(f.Fd())}); err != nil {
		t.Fatal(err)
	}
	var req Request
	got, err := ReadMsg(fds[1], &req)
	if err != nil {
		t.Fatal(err)
	}
	defer CloseFDs(got)
	if req.Op != OpTagOf || len(got) != 1 {
		t.Fatalf("%+v %v", req, got)
	}
	var a, b unix.Stat_t
	_ = unix.Fstat(int(f.Fd()), &a)
	_ = unix.Fstat(got[0], &b)
	if a.Ino != b.Ino || a.Dev != b.Dev {
		t.Fatal("received a different file")
	}
	unix.Close(fds[0])
	if _, err := ReadMsg(fds[1], &req); err != ErrClosed {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestOpenSockets(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fds, skipped := openSockets([]string{sock, dir, plain, filepath.Join(dir, "missing"), "", sock}, true)
	defer CloseFDs(fds)
	if len(fds) != 2 {
		t.Fatalf("want the socket and the directory, got %d fds", len(fds))
	}
	if len(skipped) != 1 {
		t.Fatalf("want only the plain file reported, got %v", skipped)
	}
	// Guarded entries are directories only.
	gfds, gskipped := openSockets([]string{sock, dir}, false)
	defer CloseFDs(gfds)
	if len(gfds) != 1 || len(gskipped) != 1 {
		t.Fatalf("guarded: want the directory only, got %d fds, skipped %v", len(gfds), gskipped)
	}
}

func TestDialWithoutDaemon(t *testing.T) {
	old := socketPath
	socketPath = filepath.Join(t.TempDir(), "none.sock")
	defer func() { socketPath = old }()
	if _, err := Dial(); err != ErrNotRunning {
		t.Fatalf("want ErrNotRunning, got %v", err)
	}
	g := New()
	if g.Loaded() {
		t.Fatal("loaded without a daemon")
	}
	if tag, err := g.Tag(os.Getpid()); tag != "" || err != nil {
		t.Fatalf("tag %q err %v", tag, err)
	}
	if tag, notes, err := ForAgent("/x/cotty-agent-1.scope", nil, nil); tag != "" || notes != nil || err != nil {
		t.Fatalf("ForAgent without a guard: %q %v %v", tag, notes, err)
	}
}

func TestDialRefusesNonRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root")
	}
	old := socketPath
	socketPath = filepath.Join(t.TempDir(), "fake.sock")
	defer func() { socketPath = old }()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: socketPath}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(); err == nil || err == ErrNotRunning {
		t.Fatalf("a socket served by a non-root process was trusted: %v", err)
	}
}

// An exception use is reported as an allowed access, not as a denial.
func TestExceptionRecord(t *testing.T) {
	r := Denial{Allowed: true, Hook: 2, Reason: ReasonPTSException, TGID: 1, Target: 42,
		Dev: 25<<20 | 3, Ino: 7, Comm: "pinentry-curses", Exe: "/usr/bin/pinentry-curses"}.Record()
	if r.Event != audit.GuardException || r.Outcome != "allowed" || r.Subject.Exe != "/usr/bin/pinentry-curses" {
		t.Fatalf("record %+v", r)
	}
	if r.Data["broker"] != uint32(42) || r.Data["pts"] != "25:3 ino 7" {
		t.Errorf("data %v", r.Data)
	}
	if d := (Denial{Hook: 2, Reason: 3}).Record(); d.Event != audit.GuardDenial || d.Outcome != "denied" {
		t.Errorf("a denial recorded as %s/%s", d.Event, d.Outcome)
	}
}
