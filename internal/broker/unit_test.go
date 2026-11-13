package broker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

func TestIsSecret(t *testing.T) {
	list := DefaultSecretPrograms
	cases := []struct {
		name string
		st   ttyState
		prog *proto.Program
		want bool
	}{
		{"getpass", ttyState{ok: true, echo: false, icanon: true}, nil, true},
		{"cooked", ttyState{ok: true, echo: true, icanon: true}, nil, false},
		{"readline", ttyState{ok: true, echo: false, icanon: false}, &proto.Program{Name: "bash"}, false},
		{"vim", ttyState{ok: true, echo: false, icanon: false}, &proto.Program{Name: "vim", Exe: "/usr/bin/vim"}, false},
		{"pinentry", ttyState{ok: true, echo: false, icanon: false}, &proto.Program{Name: "pinentry-curses", Exe: "/usr/bin/pinentry-curses"}, true},
		{"unreadable", ttyState{}, nil, false},
	}
	for _, c := range cases {
		if got := isSecret(c.st, []*proto.Program{c.prog}, list); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestKeys(t *testing.T) {
	cases := map[string]string{"Enter": "\r", "C-c": "\x03", "C-]": "\x1d", "M-x": "\x1bx", "F5": "\x1b[15~", "Up": "\x1b[A"}
	for k, want := range cases {
		b, err := keyBytes(k, false)
		if err != nil || string(b) != want {
			t.Errorf("%s: %q %v", k, b, err)
		}
	}
	if b, _ := keyBytes("Up", true); string(b) != "\x1bOA" {
		t.Errorf("app cursor Up: %q", b)
	}
	if _, err := keyBytes("C-?!", false); err == nil {
		t.Error("bad key accepted")
	}
}

func TestConfirmText(t *testing.T) {
	for _, s := range []string{"ls -la\r", "x\x7f", "git commit -m 'café'", "[ $a = b ] || echo differ", "echo $((1 + 2))"} {
		if !confirmTextOK(s, true) {
			t.Errorf("%q refused under confirm", s)
		}
	}
	for _, s := range []string{"\x0f", "\x1b[A", "a\x18\x05",
		// Completion runs programs the agent may have written (COT-1).
		"./configure --\t", "make \t",
		// History expansion draws earlier commands, private ones too (COT-3).
		"echo !!", "!-1 ", "echo !?TOKEN?", "!$", "echo hi!", "^e^e ", "x^y",
		// Every '!', even one a shell would not expand where it stands: the
		// editing keys the agent keeps (Left, Backspace, more text) can
		// turn "! " or "!=" into a history reference that magic-space then
		// expands without an Enter.
		"[ $a != b ]", "if ! true; then :; fi", "echo ! ", "echo !=", "!(x)", "echo '!'",
	} {
		if confirmTextOK(s, true) {
			t.Errorf("%q allowed under confirm", s)
		}
	}
	// Outside a UTF-8 locale readline's convert-meta reads 0x85 as M-C-e
	// (shell-expand-line, which runs command substitutions).
	if confirmTextOK("$(touch x)\u00c5", false) || !confirmTextOK("$(touch x)\u00c5", true) {
		t.Error("eighth-bit bytes: wrong decision for the locale")
	}
}

func TestConfirmKeys(t *testing.T) {
	// COT-1, COT-3: completion and history recall are not sent without
	// approval.
	for _, k := range []string{"Tab", "BTab", "Up", "Down", "PgUp", "PgDn", "Esc", "M-.", "M-_", "C-p", "C-r", "C-x", "C-e", "M-?", "F1"} {
		if confirmKeys[k] {
			t.Errorf("%s allowed under confirm", k)
		}
	}
	for _, k := range []string{"Enter", "Backspace", "Delete", "Space", "Left", "Right", "Home", "End", "C-c"} {
		if !confirmKeys[k] {
			t.Errorf("%s refused under confirm", k)
		}
	}
}

func TestLocaleIsUTF8(t *testing.T) {
	cases := []struct {
		env  []string
		want bool
	}{
		{[]string{"LANG=en_US.UTF-8"}, true},
		{[]string{"LANG=C.utf8"}, true},
		{[]string{"LANG=C"}, false},
		{nil, false},
		{[]string{"LANG=en_US.UTF-8", "LC_ALL=C"}, false},
		{[]string{"LANG=C", "LC_CTYPE=pt_BR.UTF-8"}, true},
		{[]string{"LC_ALL=pt_BR.UTF-8", "LC_CTYPE=C"}, true},
	}
	for _, c := range cases {
		if got := localeIsUTF8(c.env); got != c.want {
			t.Errorf("%v: %v", c.env, got)
		}
	}
}

func TestCodes(t *testing.T) {
	a, b := newCode(), newCode()
	if a == b || len(a) != 11 || a[5] != '-' {
		t.Fatalf("codes %q %q", a, b)
	}
	if proto.NormCode(a) != proto.NormCode(" "+strings.ToLower(a[:5]+a[6:])+" ") {
		t.Error("normalization")
	}
	if proto.NormCode(a) == proto.NormCode(b) {
		t.Error("different codes equal")
	}
}

func TestDescribeProgramSelf(t *testing.T) {
	// The test binary is a user-owned file: amber.
	p := describeProgram(os.Getpid(), os.Getuid())
	if p == nil || p.Trust != proto.TrustOther || p.Name == "" {
		t.Fatalf("%+v", p)
	}
	if !isInterpreter("python3.13") || !isInterpreter("bash") || isInterpreter("sudo") {
		t.Error("interpreter list")
	}
}

// TestDescribeRenamedProgram (review N3): a trusted program started under
// a forged name (a symlink called sudo) is named after its executable,
// with the forged name next to it, never as the forged name alone.
func TestDescribeRenamedProgram(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	real, err := filepath.EvalSymlinks(sleep)
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "sudo")
	if err := os.Symlink(real, fake); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(fake, "30")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	var p *proto.Program
	for range 50 {
		p = describeProgram(cmd.Process.Pid, os.Getuid())
		if p != nil && p.Exe != "" && !strings.HasSuffix(p.Exe, ".test") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	want := filepath.Base(real) + " (as sudo)"
	if p == nil || p.Name != want {
		t.Fatalf("renamed %s judged %+v, want name %q", real, p, want)
	}
	if programName("systemd-ask-password", "systemd-ask-pas") != "systemd-ask-password" ||
		programName("sudo", "sudo") != "sudo" || programName("head", "sudo") != "head (as sudo)" {
		t.Error("programName")
	}
	// The secret program list still matches the name a program was started under.
	st := ttyState{ok: true, echo: false, icanon: false}
	if !isSecret(st, []*proto.Program{{Name: "pinentry-curses (as pinentry)", Exe: "/usr/bin/pinentry-curses"}}, []string{"pinentry"}) {
		t.Error("secret program by start name")
	}
}

// TestRawSetuidPrompt: in raw mode with echo off, a setuid-root member
// with no child is a password prompt (sudo-rs); once it has started the
// command (sudo vim, sudo -i) it is not, and neither is an ordinary raw
// mode program.
func TestRawSetuidPrompt(t *testing.T) {
	raw := ttyState{ok: true, echo: false, icanon: false}
	leaf := exec.Command("sleep", "30")
	if err := leaf.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { _ = leaf.Process.Kill(); _ = leaf.Wait() }()
	parent := exec.Command("sh", "-c", "sleep 30; true")
	if err := parent.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { _ = parent.Process.Kill(); _ = parent.Wait() }()
	for range 100 {
		if hasChildren(parent.Process.Pid) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hasChildren(leaf.Process.Pid) || !hasChildren(parent.Process.Pid) {
		t.Fatalf("hasChildren: leaf %v parent %v", hasChildren(leaf.Process.Pid), hasChildren(parent.Process.Pid))
	}
	prompt := &proto.Program{PID: leaf.Process.Pid, Name: "sudo", SetuidRoot: true}
	relay := &proto.Program{PID: parent.Process.Pid, Name: "sudo", SetuidRoot: true}
	plain := &proto.Program{PID: leaf.Process.Pid, Name: "vim"}
	if !isSecret(raw, []*proto.Program{prompt}, nil) {
		t.Error("setuid prompt without a child not detected")
	}
	if isSecret(raw, []*proto.Program{relay}, nil) {
		t.Error("setuid relay with a child (sudo vim) taken for a prompt")
	}
	if isSecret(raw, []*proto.Program{plain}, nil) {
		t.Error("ordinary raw program taken for a prompt")
	}
	if isSecret(ttyState{ok: true, echo: true}, []*proto.Program{prompt}, nil) {
		t.Error("echo on taken for a prompt")
	}
}

// TestLateExecPromptDetected (review T3): a raw-mode prompt program that
// a script execs long after its group took the terminal (`make install`
// calling sudo-rs after a second) is judged on fresh members, not on the
// list described while the group was young. The secret program rule
// shares the path with the setuid rule and needs no root binary.
func TestLateExecPromptDetected(t *testing.T) {
	prompt := promptCopy(t)
	job := exec.Command("sh", "-c", "sleep 0.7; exec "+prompt+" 30")
	job.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := job.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { _ = job.Process.Kill(); _ = job.Wait() }()

	b := testBroker(t)
	b.classifier.ShellPID = 0 // any session
	b.cfg.SecretPrograms = []string{"pinentry-tty"}
	raw := ttyState{ok: true, echo: false, icanon: false, pgid: job.Process.Pid}
	if b.observeTTY(raw) {
		t.Fatal("the script itself taken for a prompt")
	}
	start := time.Now()
	for {
		exe, _ := os.Readlink("/proc/" + strconv.Itoa(job.Process.Pid) + "/exe")
		if filepath.Base(exe) == "pinentry-tty" && time.Since(start) > 600*time.Millisecond {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("the job never execed the prompt program (exe %q)", exe)
		}
		// Polls in between, as the broker's timer does.
		b.observeTTY(raw)
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(2 * describeEvery)
	if !b.observeTTY(raw) {
		b.mu.Lock()
		defer b.mu.Unlock()
		t.Fatalf("late exec prompt not detected; members %v", programNames(b.fgMembers))
	}
}

func programNames(ps []*proto.Program) []string {
	var out []string
	for _, p := range ps {
		if p != nil {
			out = append(out, p.Name)
		}
	}
	return out
}
