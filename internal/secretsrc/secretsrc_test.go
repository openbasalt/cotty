package secretsrc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fake returns a generated fake value; tests never use real secrets.
func fake(tag string) string { return "fake-" + tag + "-" + strings.Repeat("x9", 6) }

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestReadEnvKey(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "store.env")
	a, b, c := fake("a"), fake("b"), fake("c")
	writeFile(t, p, "# comment\n\nA="+a+"\nexport B = \""+b+"\"\nC='"+c+"'\nEMPTY=\nA="+a+"2\n", 0o600)
	for key, want := range map[string]string{"A": a + "2", "B": b, "C": c} {
		got, err := ReadEnvKey(p, key)
		if err != nil || string(got) != want {
			t.Errorf("%s: got %q, %v", key, got, err)
		}
	}
	if v, err := ReadEnvKey(p, "EMPTY"); err != nil || len(v) != 0 {
		t.Errorf("EMPTY: %q %v", v, err)
	}
	if _, err := ReadEnvKey(p, "MISSING"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}

	// Group or world readable files are refused, and so are symlinks and
	// directories.
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		writeFile(t, p, "A="+a+"\n", mode)
		if _, err := ReadEnvKey(p, "A"); err == nil || strings.Contains(err.Error(), a) {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
	writeFile(t, p, "A="+a+"\n", 0o600)
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEnvKey(link, "A"); err == nil {
		t.Errorf("symlink accepted")
	}
	if _, err := ReadEnvKey(dir, "A"); err == nil {
		t.Errorf("directory accepted")
	}

	// Parse errors name the line, never the content.
	writeFile(t, p, "A="+a+"\n"+b+"\n", 0o600)
	_, err := ReadEnvKey(p, "A")
	if err == nil || !strings.Contains(err.Error(), ":2:") || strings.Contains(err.Error(), b) {
		t.Errorf("parse error: %v", err)
	}
}

func TestParseRef(t *testing.T) {
	good := map[string]Ref{
		"file:GITHUB_TOKEN":                  {Scheme: SchemeFile, Arg: "GITHUB_TOKEN"},
		"pass:dev/npm":                       {Scheme: SchemePass, Arg: "dev/npm"},
		"cmd:hub-key":                        {Scheme: SchemeCmd, Arg: "hub-key"},
		"secret-service:service=db,user=app": {Scheme: SchemeSecretService, Attrs: [][2]string{{"service", "db"}, {"user", "app"}}},
	}
	for s, want := range good {
		got, err := ParseRef(s)
		if err != nil || fmt.Sprint(got) != fmt.Sprint(want) || got.String() != s {
			t.Errorf("ParseRef(%q) = %+v, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "file:", "nope:x", "file:a b", "pass:-x", "pass:../x", "secret-service:", "secret-service:a", "secret-service:a=-b", "cmd:a/b"} {
		if _, err := ParseRef(s); err == nil {
			t.Errorf("ParseRef(%q) accepted", s)
		}
	}
}

const sampleConf = `# cotty secrets
[settings]
env_file = /tmp/x.env

[secrets]
GITHUB_TOKEN = file:GITHUB_TOKEN   # key in env_file
DB = secret-service:service=db,user=app
NPM = pass:dev/npm
HUB = cmd:hub-key

[commands]
hub-key = ["ai-hub", "secret", "get", "a b"]
`

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig("c", sampleConf)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnvFile != "/tmp/x.env" || len(cfg.Secrets) != 4 || cfg.Secrets[0].Name != "GITHUB_TOKEN" || len(cfg.Commands["hub-key"]) != 4 || cfg.Commands["hub-key"][3] != "a b" {
		t.Errorf("cfg: %+v", cfg)
	}
	bad := []string{
		"[nope]\n",
		"[secrets]\nA = file:A\nA = file:B\n",
		"[secrets]\nA = cmd:missing\n",
		"[commands]\nx = ai-hub get\n",
		"[commands]\nx = []\n",
		"A = file:A\n",
		"[secrets]\nnot an entry\n",
		"[settings]\nwhat = 1\n",
		"[secrets]\nbad name = file:A\n",
	}
	for _, s := range bad {
		if _, err := ParseConfig("c", s); err == nil {
			t.Errorf("accepted: %q", s)
		}
	}
}

func TestLoadConfigPermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cotty.conf")
	writeFile(t, p, sampleConf, 0o644) // readable is fine, it holds no values
	if _, err := LoadConfig(p); err != nil {
		t.Errorf("0644: %v", err)
	}
	for _, mode := range []os.FileMode{0o664, 0o646} {
		writeFile(t, p, sampleConf, mode)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("mode %o accepted", mode)
		}
	}
	if _, err := LoadConfig(filepath.Join(dir, "none")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

func TestResolverWithFakeRunner(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "store.env")
	gh, db, npm, hub := fake("gh"), fake("db"), fake("npm"), fake("hub")
	writeFile(t, env, "GITHUB_TOKEN="+gh+"\n", 0o600)
	conf := strings.Replace(sampleConf, "/tmp/x.env", env, 1) + "[secrets]\nBROKEN = cmd:fail\n[commands]\nfail = [\"false\"]\n"
	cfg, err := ParseConfig("c", conf)
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	run := func(_ context.Context, argv []string) ([]byte, error) {
		calls = append(calls, argv)
		switch argv[0] {
		case "secret-tool":
			return []byte(db + "\n"), nil
		case "pass":
			return []byte(npm + "\nurl: example.org\nuser: x\n"), nil
		case "ai-hub":
			return []byte(hub + "\r\n"), nil
		}
		return nil, errors.New(argv[0] + " failed: exit status 1")
	}
	r := NewResolver(cfg, Options{Run: run})
	all, err := r.ResolveAll(context.Background())
	if len(all) != 4 {
		t.Fatalf("resolved %d: %v", len(all), err)
	}
	want := map[string]string{"GITHUB_TOKEN": gh, "DB": db, "NPM": npm, "HUB": hub}
	for _, s := range all {
		if string(s.Value) != want[s.Name] {
			t.Errorf("%s: got %q", s.Name, s.Value)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "BROKEN") {
		t.Errorf("want BROKEN error, got %v", err)
	}
	wantArgv := map[string]string{
		"secret-tool": "secret-tool lookup service db user app",
		"pass":        "pass show dev/npm",
		"ai-hub":      "ai-hub secret get a b",
	}
	for _, c := range calls {
		if w, ok := wantArgv[c[0]]; ok && strings.Join(c, " ") != w {
			t.Errorf("argv %q, want %q", c, w)
		}
	}
	v, err := r.Resolve(context.Background(), "HUB")
	if err != nil || string(v) != hub {
		t.Errorf("Resolve: %q %v", v, err)
	}
	if _, err := r.Resolve(context.Background(), "NOPE"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	// Formatting never prints the value.
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		if s := fmt.Sprintf(f, all); strings.Contains(s, "fake-") || strings.Contains(s, fmt.Sprintf("%x", gh)) {
			t.Errorf("%s leaks: %s", f, s)
		}
	}
	// An empty value is an error.
	empty := NewResolver(cfg, Options{Run: func(context.Context, []string) ([]byte, error) { return []byte("\n"), nil }})
	if _, err := empty.Resolve(context.Background(), "HUB"); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty: %v", err)
	}
}

func TestExecRunner(t *testing.T) {
	ctx := context.Background()
	v := fake("exec")
	out, err := ExecRunner(ctx, []string{"printf", "%s\n", v})
	if err != nil || string(out) != v+"\n" {
		t.Fatalf("printf: %q %v", out, err)
	}
	// Failures report the exit status, never stdout or stderr.
	_, err = ExecRunner(ctx, []string{"sh", "-c", "echo " + v + "; echo " + v + " >&2; exit 3"})
	if err == nil || strings.Contains(err.Error(), v) || !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("failure: %v", err)
	}
	if _, err := ExecRunner(ctx, []string{"head", "-c", "70000", "/dev/zero"}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too large: %v", err)
	}
	if _, err := ExecRunner(ctx, []string{"cotty-no-such-program-xyz"}); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("missing: %v", err)
	}
	tctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := ExecRunner(tctx, []string{"sleep", "5"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("timeout: %v", err)
	}
}

// S33: on a timeout the whole process group goes, not only the program.
func TestExecRunnerKillsGroup(t *testing.T) {
	old := inTerminalForeground
	inTerminalForeground = func() bool { return false }
	defer func() { inTerminalForeground = old }()
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := ExecRunner(ctx, []string{"sh", "-c", "sleep 30 & echo $! > " + pidFile + "; wait"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v", d)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(2 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d still alive", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Nit: an inline comment after the value is not part of it.
func TestReadEnvKeyInlineComment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "store.env")
	a, b, c, d := fake("a"), fake("b"), fake("c"), fake("d")
	writeFile(t, p, "A="+a+" # rotated monthly\nB=\""+b+" #in\" # note\nC='"+c+"'\t# x\nD="+d+"#nospace\n", 0o600)
	for key, want := range map[string]string{"A": a, "B": b + " #in", "C": c, "D": d + "#nospace"} {
		if got, err := ReadEnvKey(p, key); err != nil || string(got) != want {
			t.Errorf("%s: got %q, %v", key, got, err)
		}
	}
}
