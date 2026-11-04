package confine

// Hook managers: Husky, pre-commit and lefthook install small shims as git
// hooks (in .git/hooks or under core.hooksPath) that run files from the
// work tree: Husky v9's stubs in .husky/_ run .husky/<hook>, pre-commit
// reads .pre-commit-config.yaml (and runs `repo: local` entries), lefthook
// reads lefthook.yml and the scripts in .lefthook/. The shims are
// protected as hooks; the files they run are protected here, so the
// person's next `git commit` does not run what the agent wrote.
//
// Not covered (documented in docs/confinement.md): programs those files
// start without naming them by path (`npx lint-staged`, `make check`,
// package.json scripts), configuration spellings not listed below, and
// older Husky versions that read package.json.

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Hook manager configuration, relative to the work tree. Directories end
// in "/".
var (
	huskyFiles     = []string{".husky/"}
	preCommitFiles = []string{".pre-commit-config.yaml"}
	lefthookFiles  = []string{
		"lefthook.yml", "lefthook.yaml", "lefthook.json", "lefthook.toml",
		".lefthook.yml", ".lefthook.yaml", ".lefthook.json", ".lefthook.toml",
		"lefthook-local.yml", "lefthook-local.yaml", ".lefthook-local.yml", ".lefthook-local.yaml",
		".lefthook/", ".lefthook-local/",
	}
)

// hookShims names the hook managers whose shims are installed in dirs,
// found by their markers in the hook files.
func hookShims(dirs []string) map[string]bool {
	markers := map[string][]string{
		"husky":      {"husky"},
		"pre-commit": {"pre-commit.com", "pre_commit"},
		"lefthook":   {"lefthook"},
	}
	found := map[string]bool{}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for i, e := range ents {
			if i >= 200 || strings.HasSuffix(e.Name(), ".sample") || !e.Type().IsRegular() {
				continue
			}
			b := readHead(filepath.Join(d, e.Name()), 64<<10)
			low := strings.ToLower(b)
			for mgr, ms := range markers {
				for _, m := range ms {
					if strings.Contains(low, m) {
						found[mgr] = true
					}
				}
			}
		}
	}
	return found
}

// readHead returns at most n bytes of the file p.
func readHead(p string, n int64) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, n))
	return string(b)
}

// protectHookManagers protects the hook manager configuration of worktree
// (when it exists), creates read-only placeholders for the configuration
// of a manager whose shim is installed in hookDirs, and protects scripts
// that configuration names by path.
func (g *gitGuard) protectHookManagers(worktree string, hookDirs []string) {
	if !g.isWritable(worktree) {
		return
	}
	shims := hookShims(hookDirs)
	// A hooksPath inside .husky is Husky's own layout.
	for _, d := range hookDirs {
		if underAny(d, []string{filepath.Join(worktree, ".husky")}) {
			shims["husky"] = true
		}
	}
	type mgr struct {
		name  string
		files []string
		// placeholders: created read-only when the manager's shim is
		// installed and the file is missing (relative path, content).
		placeholders [][2]string
	}
	for _, m := range []mgr{
		{"husky", huskyFiles, [][2]string{{".husky/", ""}}},
		{"pre-commit", preCommitFiles, [][2]string{{".pre-commit-config.yaml", "repos: []\n"}}},
		{"lefthook", lefthookFiles, [][2]string{{"lefthook.yml", "{}\n"}, {"lefthook-local.yml", "{}\n"}}},
	} {
		name := m.name
		for _, rel := range m.files {
			p := filepath.Join(worktree, strings.TrimSuffix(rel, "/"))
			fi, err := os.Lstat(p)
			if err != nil {
				continue
			}
			g.protect(p, fi.IsDir(), false, "")
			g.protectHookScripts(p, worktree)
		}
		if !shims[name] {
			continue
		}
		for _, ph := range m.placeholders {
			p := filepath.Join(worktree, strings.TrimSuffix(ph[0], "/"))
			if _, err := os.Lstat(p); err == nil {
				continue
			}
			if name == "lefthook" && ph[0] == "lefthook.yml" && anyExists(worktree, lefthookFiles[:8]) {
				continue // a main configuration exists under another name
			}
			if name == "lefthook" && ph[0] == "lefthook-local.yml" && anyExists(worktree, lefthookFiles[8:12]) {
				continue
			}
			g.protect(p, strings.HasSuffix(ph[0], "/"), true, ph[1])
		}
	}
}

func anyExists(dir string, rels []string) bool {
	for _, r := range rels {
		if _, err := os.Lstat(filepath.Join(dir, r)); err == nil {
			return true
		}
	}
	return false
}

// hookCommandRe matches a YAML key whose value is a command in pre-commit
// (entry) and lefthook (run, script) configuration.
var hookCommandRe = regexp.MustCompile(`^\s*-?\s*(entry|run|script|command)\s*[:=]\s*(.+)$`)

var unquoteRe = strings.NewReplacer(`"`, "", "'", "", "{", " ", "}", " ", ",", " ")

// protectHookScripts protects the existing scripts that a hook manager
// file (or every file of a hook manager directory) names by path: the
// command values of YAML configuration, every line of a Husky hook file.
func (g *gitGuard) protectHookScripts(p, worktree string) {
	var files []string
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		ents, _ := os.ReadDir(p)
		for i, e := range ents {
			if i < 200 && e.Type().IsRegular() {
				files = append(files, filepath.Join(p, e.Name()))
			}
		}
	} else {
		files = []string{p}
	}
	for _, f := range files {
		yaml := strings.HasSuffix(f, ".yml") || strings.HasSuffix(f, ".yaml")
		sc := bufio.NewScanner(strings.NewReader(readHead(f, 1<<20)))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			if yaml || strings.HasSuffix(f, ".json") || strings.HasSuffix(f, ".toml") {
				m := hookCommandRe.FindStringSubmatch(unquoteRe.Replace(line))
				if m == nil {
					continue
				}
				line = m[2]
			}
			for _, w := range commandPaths(line) {
				if q := g.expand(w, worktree); q != "" {
					if fi, err := os.Stat(q); err == nil && fi.Mode().IsRegular() {
						g.protect(q, false, false, "")
					}
				}
			}
		}
	}
}
