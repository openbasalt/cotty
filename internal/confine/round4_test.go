package confine

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// linkHome makes a home with a project and returns home (as given),
// its real path, the project and a plan builder for the claude profile.
func linkHome(t *testing.T) (string, string, func(project string) (*Plan, error)) {
	t.Helper()
	home := t.TempDir()
	realHome, _ := filepath.EvalSymlinks(home)
	self, _ := os.Executable()
	env := []string{"HOME=" + home, "PATH=/usr/bin"}
	return home, realHome, func(project string) (*Plan, error) {
		return BuildPlan(Options{Project: project, Profile: "claude", Argv: []string{"claude"}, NoMCP: true}, env, self)
	}
}

func roBindAt(pl *Plan, target string) bool {
	for _, b := range pl.Spec.Binds {
		if b.Target == target && !b.RW {
			return true
		}
	}
	return false
}

// TestProtectLinkStaysReadOnly (review round 4, item 1): a protected
// path that is a link to a file the agent can write anyway (the dotfiles
// repository as the project, or a file next to it in the writable
// ~/.claude) is mounted read-only over the link and at the target.
func TestProtectLinkStaysReadOnly(t *testing.T) {
	home, realHome, build := linkHome(t)
	dot := filepath.Join(realHome, "dotfiles")
	writeFile(t, filepath.Join(dot, "claude", "settings.json"), "{}")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(realHome, ".claude", "settings.json")
	target := filepath.Join(dot, "claude", "settings.json")
	if err := os.Symlink("../dotfiles/claude/settings.json", link); err != nil {
		t.Fatal(err)
	}
	pl, err := build(dot)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range pl.Spec.Links {
		if l.Path == link {
			t.Errorf("protected link recreated as a plain link: %+v", l)
		}
	}
	if !roBindAt(pl, link) {
		t.Errorf("no read-only mount over the link %s: %+v", link, pl.Spec.Binds)
	}
	if !roBindAt(pl, target) {
		t.Errorf("the link's target %s stays writable in the project: %+v", target, pl.Spec.Binds)
	}

	// The target next to the link, in the writable ~/.claude.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(realHome, ".claude", "shared.json")
	writeFile(t, shared, "{}")
	if err := os.Symlink("shared.json", link); err != nil {
		t.Fatal(err)
	}
	if pl, err = build(filepath.Join(dot)); err != nil {
		t.Fatal(err)
	}
	if !roBindAt(pl, link) || !roBindAt(pl, shared) {
		t.Errorf("sibling target: link %v target %v: %+v", roBindAt(pl, link), roBindAt(pl, shared), pl.Spec.Binds)
	}
}

// TestProtectDirLinkRefused: a protected directory that is a link in a
// writable profile directory cannot be kept read-only (a directory mount
// cannot cover a link), so the start is refused with a way out.
func TestProtectDirLinkRefused(t *testing.T) {
	home, realHome, build := linkHome(t)
	dot := filepath.Join(realHome, "dotfiles")
	if err := os.MkdirAll(filepath.Join(dot, "claude", "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dot, "claude", "skills"), filepath.Join(home, ".claude", "skills")); err != nil {
		t.Fatal(err)
	}
	if _, err := build(dot); err == nil || !strings.Contains(err.Error(), ".claude/skills") {
		t.Fatalf("a link to a directory at a protected path: %v", err)
	}
}

// TestClaudeDirLinkKeepsHideAndProtect (review round 4, item 3): when
// ~/.claude is a link into a dotfiles repository that is the project,
// the link is recreated inside after the mounts; the hidden IDE directory
// and the protected files below it are placed at the link's target, not
// in a directory made in the link's place.
func TestClaudeDirLinkKeepsHideAndProtect(t *testing.T) {
	home, realHome, build := linkHome(t)
	dot := filepath.Join(realHome, "dotfiles")
	writeFile(t, filepath.Join(dot, "claude", "settings.json"), "{}")
	if err := os.Symlink(filepath.Join(dot, "claude"), filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	pl, err := build(dot)
	if err != nil {
		t.Fatal(err)
	}
	ide := filepath.Join(dot, "claude", "ide")
	if !slices.Contains(pl.Spec.HideDirs, ide) {
		t.Errorf("~/.claude/ide not hidden at the link's target %s: hide %v rehide %v", ide, pl.Spec.HideDirs, pl.Spec.Rehide)
	}
	if !roBindAt(pl, filepath.Join(dot, "claude", "settings.json")) {
		t.Errorf("settings.json below the link not read-only at the target: %+v", pl.Spec.Binds)
	}
	under := filepath.Join(realHome, ".claude") + "/"
	for _, b := range pl.Spec.Binds {
		if strings.HasPrefix(b.Target, under) {
			t.Errorf("mount point below the recreated link: %+v", b)
		}
	}
	for _, h := range append(append([]string(nil), pl.Spec.HideDirs...), pl.Spec.Rehide...) {
		if strings.HasPrefix(h, under) {
			t.Errorf("hidden directory below the recreated link: %s", h)
		}
	}
}

// TestSkippedRWRootCreatesNothing (review round 4, item 4): when a
// writable profile directory is a link to a place no agent may see, it is
// skipped, and nothing below it is created or bound through the link.
func TestSkippedRWRootCreatesNothing(t *testing.T) {
	home, realHome, build := linkHome(t)
	proj := filepath.Join(realHome, "src", "p")
	ssh := filepath.Join(realHome, ".ssh")
	writeFile(t, filepath.Join(ssh, "id_ed25519"), "KEY")
	writeFile(t, filepath.Join(realHome, ".claude.json"), `{"numStartups": 1}`) // the profile seeds it into ~/.claude
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ssh, filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	pl, err := build(proj)
	if err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(ssh)
	if len(ents) != 1 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("created in ~/.ssh through the ~/.claude link: %v", names)
	}
	if len(pl.Placeholders) > 0 {
		t.Errorf("placeholders: %v", pl.Placeholders)
	}
	for _, b := range pl.Spec.Binds {
		if strings.HasPrefix(b.Source, filepath.Join(realHome, ".claude")) || strings.HasPrefix(b.Source, ssh) {
			t.Errorf("bound through the skipped link: %+v", b)
		}
	}
	if len(pl.Spec.HideDirs) > 0 {
		t.Errorf("hidden through the skipped link: %v", pl.Spec.HideDirs)
	}
}

// TestLinksInsideProtectedDirs: GNU stow --no-folding leaves ~/.claude/skills
// a real directory of links into the dotfiles repository. The links
// cannot be replaced (the directory is read-only inside), and their
// targets are read-only too when the agent could write them otherwise.
func TestLinksInsideProtectedDirs(t *testing.T) {
	home, realHome, build := linkHome(t)
	dot := filepath.Join(realHome, "dotfiles")
	skill := filepath.Join(dot, "claude", "skills", "deploy")
	writeFile(t, filepath.Join(skill, "SKILL.md"), "# deploy")
	skills := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(skills, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(skill, filepath.Join(skills, "deploy")); err != nil {
		t.Fatal(err)
	}
	pl, err := build(dot)
	if err != nil {
		t.Fatal(err)
	}
	if !roBindAt(pl, skill) {
		t.Errorf("the skill linked from ~/.claude/skills stays writable in the project: %+v", pl.Spec.Binds)
	}
}
