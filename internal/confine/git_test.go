package confine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeGitDir makes the files that make a directory look like a git one.
func fakeGitDir(t *testing.T, d, config string) {
	t.Helper()
	writeFile(t, filepath.Join(d, "HEAD"), "ref: refs/heads/main\n")
	if err := os.MkdirAll(filepath.Join(d, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(d, "config"), config)
}

func bindMap(bs []Bind) map[string]Bind {
	m := map[string]Bind{}
	for _, b := range bs {
		m[b.Target] = b
	}
	return m
}

func TestGitGuard(t *testing.T) {
	home := t.TempDir()
	proj, _ := filepath.EvalSymlinks(t.TempDir())
	g := filepath.Join(proj, ".git")
	fakeGitDir(t, g, "[core]\n\thooksPath = .husky/_\n\tfsmonitor = \"./tools/fsmon.sh --x\"\n[include]\n\tpath = ../extra.gitconfig\n[alias]\n\tx = !sh scripts/a.sh\n")
	writeFile(t, filepath.Join(proj, "tools/fsmon.sh"), "#!/bin/sh\n")
	writeFile(t, filepath.Join(proj, "scripts/a.sh"), "#!/bin/sh\n")
	fakeGitDir(t, filepath.Join(g, "modules/lib/a"), "[core]\n\tworktree = ../../../../lib/a\n")
	writeFile(t, filepath.Join(g, "worktrees/wt/commondir"), "../..\n")
	writeFile(t, filepath.Join(g, "worktrees/wt/gitdir"), "/elsewhere/wt/.git\n")
	writeFile(t, filepath.Join(g, "worktrees/wt/HEAD"), "ref: refs/heads/x\n")
	fakeGitDir(t, filepath.Join(proj, "vendor/nested/.git"), "")
	writeFile(t, filepath.Join(proj, "sub/.git"), "gitdir: ../.git/modules/lib/a\n")

	gg := newGitGuard(proj, home, []Bind{{Source: proj, Target: proj, RW: true, Dir: true}}, false)
	found := gg.protectProject(false, nil)
	m := bindMap(gg.binds)
	ro := func(rel string) {
		t.Helper()
		if b, ok := m[filepath.Join(proj, rel)]; !ok || b.RW {
			t.Errorf("%s not read-only: %+v", rel, b)
		}
	}
	pinned := func(rel string) {
		t.Helper()
		if b, ok := m[filepath.Join(proj, rel)]; !ok || !b.RW || b.Source != b.Target {
			t.Errorf("%s not pinned: %+v", rel, b)
		}
	}
	for _, r := range []string{".git/config", ".git/hooks", ".git/config.worktree", "extra.gitconfig", ".husky/_",
		"tools/fsmon.sh", "scripts/a.sh", ".git/modules/lib/a/config", ".git/modules/lib/a/hooks",
		".git/worktrees/wt/commondir", ".git/worktrees/wt/gitdir", ".git/worktrees/wt/config.worktree",
		"vendor/nested/.git/config", "vendor/nested/.git/hooks", "sub/.git", ".husky"} {
		ro(r)
	}
	for _, r := range []string{".git", ".git/modules", ".git/modules/lib", ".git/modules/lib/a", ".git/worktrees",
		".git/worktrees/wt", "vendor/nested/.git", "vendor/nested", "vendor", "tools", "scripts"} {
		pinned(r)
	}
	// Placeholders exist outside now.
	for _, r := range []string{".husky/_", "extra.gitconfig", ".git/hooks", ".git/config.worktree"} {
		if _, err := os.Stat(filepath.Join(proj, r)); err != nil {
			t.Errorf("placeholder %s: %v", r, err)
		}
	}
	// Git directories without commondir are watched.
	w := strings.Join(gg.watch, " ")
	if !strings.Contains(w, g) || !strings.Contains(w, filepath.Join(g, "modules/lib/a")) {
		t.Errorf("watch %v", gg.watch)
	}
	if strings.Contains(w, "worktrees/wt") {
		t.Errorf("worktree with commondir watched: %v", gg.watch)
	}
	if len(found) != 3 {
		t.Errorf("found %v", found)
	}
	// Nothing outside the writable area is bound.
	for _, b := range gg.binds {
		if !underAny(b.Target, []string{proj}) {
			t.Errorf("bind outside the project: %+v", b)
		}
	}
	// New repositories are reported.
	fakeGitDir(t, filepath.Join(proj, "new/.git"), "")
	if n := NewGitEntries(proj, found); len(n) != 1 || n[0] != filepath.Join(proj, "new/.git") {
		t.Errorf("new entries %v", n)
	}
}

func TestGitGuardNoRepo(t *testing.T) {
	proj, _ := filepath.EvalSymlinks(t.TempDir())
	gg := newGitGuard(proj, t.TempDir(), []Bind{{Source: proj, Target: proj, RW: true, Dir: true}}, false)
	gg.protectProject(false, nil)
	if b, ok := bindMap(gg.binds)[filepath.Join(proj, ".git")]; !ok || b.RW || gg.initGuard == "" {
		t.Fatalf("no read-only .git placeholder: %+v", gg.binds)
	}
	if !dirEmpty(filepath.Join(proj, ".git")) {
		t.Fatal("placeholder not empty")
	}
	// The second plan (after the re-execution) sees the empty placeholder.
	gg = newGitGuard(proj, t.TempDir(), []Bind{{Source: proj, Target: proj, RW: true, Dir: true}}, false)
	gg.protectProject(false, nil)
	if b := bindMap(gg.binds)[filepath.Join(proj, ".git")]; b.RW || gg.initGuard == "" || len(gg.binds) != 1 {
		t.Fatalf("second plan: %+v", gg.binds)
	}
	// Opted out: nothing.
	proj2, _ := filepath.EvalSymlinks(t.TempDir())
	gg = newGitGuard(proj2, t.TempDir(), []Bind{{Source: proj2, Target: proj2, RW: true, Dir: true}}, false)
	gg.protectProject(true, nil)
	if len(gg.binds) != 0 {
		t.Fatalf("allow-git-init: %+v", gg.binds)
	}
}

func TestGitGuardReadOnlyWins(t *testing.T) {
	proj, _ := filepath.EvalSymlinks(t.TempDir())
	writeFile(t, filepath.Join(proj, "ro/x/y.sh"), "")
	gg := newGitGuard(proj, t.TempDir(), []Bind{
		{Source: proj, Target: proj, RW: true, Dir: true},
		{Source: filepath.Join(proj, "ro"), Target: filepath.Join(proj, "ro"), Dir: true},
	}, false)
	gg.protect(filepath.Join(proj, "ro/x/y.sh"), false, false, "")
	if len(gg.binds) != 0 {
		t.Fatalf("binds under a read-only bind: %+v", gg.binds)
	}
}

func TestParseGitConfig(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c")
	writeFile(t, f, "[core]\n\tHooksPath = \"a b\" ; comment\n[includeIf \"gitdir:~/w/\"]\n\tpath = ~/w.inc\n[filter.lfs]\n\tclean = git-lfs \\\n clean -- %f\n\tbare\n")
	es, err := parseGitConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range es {
		got[e.key] = e.value
	}
	if got["core.hookspath"] != "a b" || got["includeif.path"] != "~/w.inc" || got["filter.clean"] != "git-lfs  clean -- %f" || got["filter.bare"] != "true" {
		t.Fatalf("%#v", got)
	}
}

func TestCommandPaths(t *testing.T) {
	got := commandPaths(`!sh ./x.sh --flag=~/y.sh https://a/b $HOME/h.sh "q/r"`)
	want := "./x.sh ~/y.sh ~/h.sh q/r"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %q", got)
	}
	f := filepath.Join(t.TempDir(), "s.json")
	writeFile(t, f, `{"statusLine":{"command":"~/.claude/s.sh"},"hooks":{"Stop":[{"command":"bash /abs/h.sh"}]}}`)
	if p := commandPathsIn(f, "/home/u"); strings.Join(p, " ") != "/home/u/.claude/s.sh /abs/h.sh" {
		t.Fatalf("got %q", p)
	}
}

func TestCheckSocketRoots(t *testing.T) {
	roots := socketRoots([]string{"XDG_RUNTIME_DIR=/run/user/1000"})
	for _, bad := range []string{"/tmp", "/var/tmp", "/run", "/run/user", "/run/user/1000", "/run/user/1000/x", "/dev/shm",
		"/dev/shm/x", "/var", "/tmp/.X11-unix", "/tmp/tmux-1000", "/tmp/ssh-abc", "/var/run", "/dev"} {
		if checkSocketRoots(bad, roots) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	for _, good := range []string{"/tmp/myproject", "/var/tmp/build", "/home/u/src", "/srv/app", "/opt/x"} {
		if err := checkSocketRoots(good, roots); err != nil {
			t.Errorf("%s refused: %v", good, err)
		}
	}
}

func TestCheckAgentDir(t *testing.T) {
	base := t.TempDir()
	good := filepath.Join(base, "cotty", "agent")
	if err := os.MkdirAll(good, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkAgentDir(good, "", os.Getuid()); err != nil {
		t.Errorf("good: %v", err)
	}
	for _, bad := range []string{base, filepath.Join(base, "cotty")} {
		if checkAgentDir(bad, "", os.Getuid()) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := os.Chmod(good, 0o755); err != nil {
		t.Fatal(err)
	}
	if checkAgentDir(good, "", os.Getuid()) == nil {
		t.Error("open mode accepted")
	}
}

func TestProtectPlaceholders(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "src", "p")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, ".claude", ".credentials.json"), "{}")
	self, _ := os.Executable()
	env := []string{"HOME=" + home, "PATH=/usr/bin"}
	pl, err := BuildPlan(Options{Project: proj, Profile: "claude", Argv: []string{"claude"}, NoMCP: true}, env, self)
	if err != nil {
		t.Fatal(err)
	}
	realHome, _ := filepath.EvalSymlinks(home)
	m := bindMap(pl.Spec.Binds)
	for _, r := range []string{".claude/settings.json", ".claude/agents", ".claude/plugins", ".claude/CLAUDE.md", ".claude/local"} {
		b, ok := m[filepath.Join(realHome, r)]
		if !ok || b.RW {
			t.Errorf("%s not bound read-only: %+v", r, b)
		}
	}
	if b, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json")); err != nil || string(b) != "{}\n" {
		t.Errorf("settings placeholder %q %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(home, ".claude", "agents")); err != nil || !fi.IsDir() {
		t.Errorf("agents placeholder: %v", err)
	}
	// A dry run creates nothing.
	home2 := t.TempDir()
	proj2 := filepath.Join(home2, "p")
	if err := os.MkdirAll(filepath.Join(home2, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(proj2, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(Options{Project: proj2, Profile: "claude", Argv: []string{"claude"}, DryRun: true}, []string{"HOME=" + home2}, self); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home2, ".claude", "settings.json")); err == nil {
		t.Error("dry run created a placeholder")
	}
	if _, err := os.Stat(filepath.Join(proj2, ".git")); err == nil {
		t.Error("dry run created .git")
	}
}

func TestGitGuardHookManagers(t *testing.T) {
	proj, _ := filepath.EvalSymlinks(t.TempDir())
	g := filepath.Join(proj, ".git")
	fakeGitDir(t, g, "[core]\n\tbare = false\n")
	// Shims of pre-commit and lefthook, no configuration yet; a sample
	// that names husky does not count.
	writeFile(t, filepath.Join(g, "hooks/pre-commit"), "#!/usr/bin/env bash\n# File generated by pre-commit: https://pre-commit.com\n")
	writeFile(t, filepath.Join(g, "hooks/pre-push"), "#!/bin/sh\nexec lefthook run pre-push\n")
	writeFile(t, filepath.Join(g, "hooks/post-merge.sample"), "husky\n")
	gg := newGitGuard(proj, t.TempDir(), []Bind{{Source: proj, Target: proj, RW: true, Dir: true}}, false)
	gg.protectProject(false, nil)
	m := bindMap(gg.binds)
	for _, r := range []string{".pre-commit-config.yaml", "lefthook.yml", "lefthook-local.yml"} {
		if b, ok := m[filepath.Join(proj, r)]; !ok || b.RW {
			t.Errorf("%s not read-only: %+v", r, b)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(proj, ".pre-commit-config.yaml")); string(b) != "repos: []\n" {
		t.Errorf("pre-commit placeholder %q", b)
	}
	if _, err := os.Stat(filepath.Join(proj, ".husky")); err == nil {
		t.Error("a husky placeholder without a husky shim")
	}

	// Existing configuration, and the scripts it names by path.
	proj2, _ := filepath.EvalSymlinks(t.TempDir())
	fakeGitDir(t, filepath.Join(proj2, ".git"), "[core]\n\thooksPath = .husky/_\n")
	writeFile(t, filepath.Join(proj2, ".husky/pre-commit"), "npx lint-staged\n./scripts/lint.sh --fix\n")
	writeFile(t, filepath.Join(proj2, ".pre-commit-config.yaml"), "repos:\n- repo: local\n  hooks:\n  - id: x\n    entry: ./tools/check.sh\n    language: system\n")
	writeFile(t, filepath.Join(proj2, "lefthook.yml"), "pre-commit:\n  commands:\n    a:\n      run: \"bash ./tools/a.sh {staged_files}\"\n")
	writeFile(t, filepath.Join(proj2, ".lefthook/pre-commit/x.sh"), "#!/bin/sh\n")
	for _, f := range []string{"scripts/lint.sh", "tools/check.sh", "tools/a.sh"} {
		writeFile(t, filepath.Join(proj2, f), "#!/bin/sh\n")
	}
	gg = newGitGuard(proj2, t.TempDir(), []Bind{{Source: proj2, Target: proj2, RW: true, Dir: true}}, false)
	gg.protectProject(false, nil)
	m = bindMap(gg.binds)
	for _, r := range []string{".husky", ".husky/_", ".pre-commit-config.yaml", "lefthook.yml", ".lefthook",
		"scripts/lint.sh", "tools/check.sh", "tools/a.sh"} {
		if b, ok := m[filepath.Join(proj2, r)]; !ok || b.RW {
			t.Errorf("%s not read-only: %+v", r, b)
		}
	}
	if _, ok := m[filepath.Join(proj2, "lefthook-local.yml")]; ok {
		t.Error("lefthook-local.yml placeholder without a lefthook shim")
	}
}

func TestGitGuardLinks(t *testing.T) {
	proj, _ := filepath.EvalSymlinks(t.TempDir())
	g := filepath.Join(proj, ".git")
	fakeGitDir(t, g, "")
	if err := os.MkdirAll(filepath.Join(proj, "shared-hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../shared-hooks", filepath.Join(g, "hooks")); err != nil {
		t.Fatal(err)
	}
	gg := newGitGuard(proj, t.TempDir(), []Bind{{Source: proj, Target: proj, RW: true, Dir: true}}, false)
	gg.protectProject(false, nil)
	if len(gg.refusals) != 1 || !strings.Contains(gg.refusals[0], "hooks") {
		t.Fatalf("refusals %v", gg.refusals)
	}
	gg = newGitGuard(proj, t.TempDir(), []Bind{{Source: proj, Target: proj, RW: true, Dir: true}}, false)
	gg.allowLinks = true
	gg.protectProject(false, nil)
	if len(gg.refusals) != 0 || len(gg.notes) == 0 {
		t.Fatalf("allowed: refusals %v notes %v", gg.refusals, gg.notes)
	}
	if b, ok := bindMap(gg.binds)[filepath.Join(proj, "shared-hooks")]; !ok || b.RW {
		t.Errorf("link target not read-only: %+v", gg.binds)
	}
	// A .git that is a link is refused too.
	proj2, _ := filepath.EvalSymlinks(t.TempDir())
	fakeGitDir(t, filepath.Join(proj2, "real.git"), "")
	if err := os.Symlink("real.git", filepath.Join(proj2, ".git")); err != nil {
		t.Fatal(err)
	}
	gg = newGitGuard(proj2, t.TempDir(), []Bind{{Source: proj2, Target: proj2, RW: true, Dir: true}}, false)
	gg.protectProject(false, nil)
	if len(gg.refusals) != 1 {
		t.Fatalf(".git link: refusals %v", gg.refusals)
	}
}

func TestGitScanLimits(t *testing.T) {
	proj, _ := filepath.EvalSymlinks(t.TempDir())
	fakeGitDir(t, filepath.Join(proj, ".git"), "")
	fakeGitDir(t, filepath.Join(proj, "node_modules/pkg/.git"), "")
	deep := "a/b/c/d/e/f/g/sub"
	writeFile(t, filepath.Join(proj, deep, ".git"), "gitdir: ../../../../../../../../.git/modules/sub\n")
	fakeGitDir(t, filepath.Join(proj, ".git/modules/sub"), "")
	writeFile(t, filepath.Join(proj, ".gitmodules"), "[submodule \"sub\"]\n\tpath = "+deep+"\n\turl = ../sub\n[submodule \"evil\"]\n\tpath = ../outside\n")
	found, nDeep, truncated := scanGitTree(proj)
	if len(found) != 1 || nDeep == 0 || truncated {
		t.Fatalf("found %v deep %d truncated %v", found, nDeep, truncated)
	}
	gg := newGitGuard(proj, t.TempDir(), []Bind{{Source: proj, Target: proj, RW: true, Dir: true}}, false)
	gg.protectProject(false, nil)
	m := bindMap(gg.binds)
	if b, ok := m[filepath.Join(proj, deep, ".git")]; !ok || b.RW {
		t.Errorf("submodule gitfile from .gitmodules not read-only")
	}
	if _, ok := m[filepath.Join(proj, "node_modules/pkg/.git/config")]; ok {
		t.Error("node_modules scanned")
	}
	if !strings.Contains(strings.Join(gg.notes, " "), "levels below the project") {
		t.Errorf("no depth note: %v", gg.notes)
	}
}

func TestGitConfigScriptPlaceholders(t *testing.T) {
	proj, _ := filepath.EvalSymlinks(t.TempDir())
	fakeGitDir(t, filepath.Join(proj, ".git"), "[core]\n\tfsmonitor = ./tools/fsmon.sh\n[alias]\n\tl = !git log origin/main\n\tf = log --format=%h/%s\n[remote \"o\"]\n\turl = ./other/repo\n")
	gg := newGitGuard(proj, t.TempDir(), []Bind{{Source: proj, Target: proj, RW: true, Dir: true}}, false)
	gg.protectProject(false, nil)
	if b, ok := bindMap(gg.binds)[filepath.Join(proj, "tools/fsmon.sh")]; !ok || b.RW {
		t.Errorf("missing fsmonitor script not protected: %+v", gg.binds)
	}
	if _, err := os.Stat(filepath.Join(proj, "tools/fsmon.sh")); err != nil {
		t.Errorf("no placeholder: %v", err)
	}
	for _, r := range []string{"origin", "%h", "other"} {
		if _, err := os.Stat(filepath.Join(proj, r)); err == nil {
			t.Errorf("placeholder for a word that is not a program: %s", r)
		}
	}
}

func TestRehideUnder(t *testing.T) {
	binds := []Bind{
		{Source: "/var/lib", Target: "/var/lib", Dir: true},
		{Source: "/srv/x", Target: "/srv/x", Dir: true},
		{Source: "/home/u/.lnk", Target: "/home/u/.lnk", Dir: false},
	}
	got := rehideUnder([]string{"/home/u", "/var/lib/incus", "/var/lib/mysql", "/var/log/journal"}, binds)
	if strings.Join(got, " ") != "/var/lib/incus /var/lib/mysql" {
		t.Fatalf("got %v", got)
	}
	if checkHiddenSockets("/var/lib/mysql/data") == nil || checkHiddenSockets("/var/lib/incus") == nil {
		t.Error("a path in a hidden socket directory accepted")
	}
	if err := checkHiddenSockets("/var/lib"); err != nil {
		t.Errorf("/var/lib refused: %v", err)
	}
}
