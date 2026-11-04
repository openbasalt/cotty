package confine

// Protection of what git runs with the person's rights.
//
// A confined agent may write the project, and the person later runs git
// there, unconfined. Everything git reads that names a program (hooks,
// config values such as core.fsmonitor, core.hooksPath, filters, aliases,
// includes, the commondir indirection) must stay as the person left it.
// The rules, applied to every git directory of the project:
//
//   - the git directory itself and every directory between the writable
//     root and a protected path become mount points (a read-write
//     self-bind), so renaming them around their read-only children fails
//     with EBUSY;
//   - config, config.worktree, hooks/, commondir, gitdir are bound
//     read-only; config.worktree and hooks/ are created first (empty)
//     when missing, so they cannot be planted later;
//   - submodule git directories (.git/modules/...) and linked worktree
//     directories (.git/worktrees/*) get the same treatment;
//   - core.hooksPath, files named by include.path and includeIf.*.path,
//     and scripts named by any config value (a first word with a "/")
//     that lie in a writable area are read-only too;
//   - a git directory without a commondir file is watched while the agent
//     runs: creating one would redirect git to a config the agent wrote,
//     and a file cannot be pre-created there (git would then refuse to
//     work), so the launcher stops the agent instead (gitwatch_linux.go);
//   - a project without .git gets an empty read-only .git directory, so
//     `git init` inside cannot plant hooks (opt out: --allow-git-init);
//   - nested repositories (a .git below the project root, to a bounded
//     depth, vendored dependency directories skipped) and the submodule
//     paths .gitmodules names are protected like the top one; ones the
//     agent creates are reported when it exits; a scan cut short by its
//     limits says so in a note;
//   - hook managers (Husky, pre-commit, lefthook) run files from the work
//     tree: their configuration (.husky/, .pre-commit-config.yaml, the
//     lefthook files) is read-only, created first when a hook shim of
//     theirs is installed and the configuration is missing, and scripts
//     those files name by path are read-only too (hookmgr.go);
//   - a protected git file that is a symbolic link (the .git entry,
//     config, hooks, core.hooksPath) makes the launch fail unless the
//     person passes --allow-git-links: the link sits in a writable
//     directory and the agent could replace it.

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Limits of the scan for nested repositories and submodule directories.
const (
	gitScanDepth   = 6
	gitScanEntries = 50000
	gitMaxNesting  = 8
)

// gitScanSkip are directories the nested repository scan does not enter:
// installed dependencies and caches that tools rewrite, never repositories
// the person runs git in.
var gitScanSkip = map[string]bool{
	"node_modules": true, "bower_components": true, "jspm_packages": true, "__pycache__": true,
	".venv": true, ".tox": true, ".nox": true, ".mypy_cache": true, ".pytest_cache": true,
	".ruff_cache": true, ".gradle": true, ".terraform": true, ".next": true, ".nuxt": true,
	".svelte-kit": true, ".parcel-cache": true, ".turbo": true,
}

// gitGuard collects the binds, placeholders and watches that protect the
// git directories of a project.
type gitGuard struct {
	project  string
	home     string
	writable []string // real paths the agent can write (project, rw binds)
	readonly []string // targets of read-only binds (they win below them)
	dryRun   bool
	// allowLinks accepts protected git files that are symbolic links (with
	// a note) instead of refusing the launch.
	allowLinks bool

	binds     []Bind
	byPath    map[string]int // target -> index in binds
	watch     []string       // git directories without commondir
	initGuard string         // the empty read-only .git of a project without one
	created   []string       // placeholders created outside
	notes     []string
	refusals  []string        // reasons the launch must not go on
	seen      map[string]bool // git directories already handled
	hookDirs  []string        // core.hooksPath values of the git directory being handled
	configs   map[string]bool // config files already parsed
}

// newGitGuard starts from the binds planned so far: directories bound
// read-write onto themselves are writable areas, read-only binds win
// below them.
func newGitGuard(project, home string, binds []Bind, dryRun bool) *gitGuard {
	g := &gitGuard{
		project: project, home: home, dryRun: dryRun,
		byPath: map[string]int{}, seen: map[string]bool{}, configs: map[string]bool{},
	}
	for _, b := range binds {
		switch {
		case !b.RW:
			g.readonly = append(g.readonly, b.Target)
		case b.Dir && b.Source == b.Target:
			g.writable = append(g.writable, b.Source)
		}
	}
	return g
}

// isWritable reports whether the agent can write p: the deepest bind
// that contains it is a writable area.
func (g *gitGuard) isWritable(p string) bool {
	w := g.writableRoot(p)
	if w == "" {
		return false
	}
	for _, r := range g.readonly {
		if underAny(p, []string{r}) && len(r) >= len(w) {
			return false
		}
	}
	return true
}

// writableRoot returns the deepest writable root that contains p.
func (g *gitGuard) writableRoot(p string) string {
	best := ""
	for _, r := range g.writable {
		if underAny(p, []string{r}) && len(r) > len(best) {
			best = r
		}
	}
	return best
}

// addBind records a bind; a read-only bind of a path wins over a
// read-write one (a pin) of the same path.
func (g *gitGuard) addBind(b Bind) {
	if !b.RW {
		g.readonly = append(g.readonly, b.Target)
	}
	if i, ok := g.byPath[b.Target]; ok {
		if !b.RW {
			g.binds[i] = b
		}
		return
	}
	g.byPath[b.Target] = len(g.binds)
	g.binds = append(g.binds, b)
}

// pin makes dir and every directory between it and its writable root a
// mount point, so none of them can be renamed or removed inside.
func pinDirs(root, dir string) []string {
	var out []string
	for d := dir; d != root && underAny(d, []string{root}); d = filepath.Dir(d) {
		out = append(out, d)
	}
	return out
}

func (g *gitGuard) pin(dir string) {
	root := g.writableRoot(dir)
	if root == "" || !g.isWritable(dir) {
		return
	}
	for _, d := range pinDirs(root, dir) {
		if fi, err := os.Lstat(d); err != nil || !fi.IsDir() {
			continue
		}
		g.addBind(Bind{Source: d, Target: d, RW: true, Dir: true, Why: "pin"})
	}
}

// protect makes p read-only inside when it lies in a writable area. A
// missing p is created first (an empty directory, or a file holding
// content) when placeholder is set.
func (g *gitGuard) protect(p string, dir, placeholder bool, content string) {
	if !g.isWritable(p) {
		return
	}
	fi, err := os.Lstat(p)
	if err != nil {
		if !placeholder || !os.IsNotExist(err) {
			return
		}
		if !g.dryRun {
			if err := makePlaceholder(p, dir, content); err != nil {
				g.notes = append(g.notes, "cannot create "+p+" to protect it: "+err.Error())
				return
			}
		}
		g.pin(filepath.Dir(p))
		g.created = append(g.created, p)
		g.addBind(Bind{Source: p, Target: p, RW: false, Dir: dir, Why: "git"})
		return
	}
	g.pin(filepath.Dir(p))
	if fi.Mode()&os.ModeSymlink != 0 {
		// The link itself sits in a writable directory and could be
		// replaced; protect what it points to and say so.
		real, err := filepath.EvalSymlinks(p)
		g.notes = append(g.notes, p+" is a symbolic link: the agent can replace the link itself; review it before you use git there")
		if err == nil && real != p {
			if rfi, err := os.Stat(real); err == nil {
				g.protect(real, rfi.IsDir(), false, "")
			}
		}
		return
	}
	g.addBind(Bind{Source: p, Target: p, RW: false, Dir: fi.IsDir(), Why: "git"})
}

// protectStrict protects a file git reads before it runs anything (the
// .git entry, config, config.worktree, hooks/, commondir, gitdir,
// core.hooksPath). Such a file that is a symbolic link cannot be made
// safe: the link lies in a writable directory and the agent could replace
// it with a file of its own. The launch is refused unless the person
// accepted that (--allow-git-links).
func (g *gitGuard) protectStrict(p string, dir, placeholder bool, content string) {
	if g.isWritable(p) && !g.allowLinks {
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			g.refusals = append(g.refusals, p+" is a symbolic link: the agent could replace it with a file of its own, which your git would use")
			return
		}
	}
	g.protect(p, dir, placeholder, content)
}

// makePlaceholder creates p (and missing parents, 0700): an empty
// directory, or a file (0600) holding content.
func makePlaceholder(p string, dir bool, content string) error {
	if dir {
		return os.MkdirAll(p, 0o700)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// protectProject handles the project's own .git and nested repositories.
// It returns the git entries (paths of .git dirs and files) found, for the
// report after the run.
func (g *gitGuard) protectProject(allowInit bool, globalConfigs []string) []string {
	top := filepath.Join(g.project, ".git")
	fi, err := os.Lstat(top)
	// An empty .git directory is the placeholder of an earlier run (or of
	// the run before the re-execution under systemd-run).
	empty := err == nil && fi.IsDir() && dirEmpty(top)
	switch {
	case (os.IsNotExist(err) || empty) && !allowInit:
		// An empty read-only .git: git inside finds no repository here, and
		// `git init` cannot create one that the person's git would use.
		if !g.dryRun && !empty {
			if err := os.Mkdir(top, 0o700); err != nil && !os.IsExist(err) {
				g.notes = append(g.notes, "cannot create an empty .git to keep `git init` out: "+err.Error())
			}
		}
		g.addBind(Bind{Source: top, Target: top, RW: false, Dir: true, Why: "git"})
		g.initGuard = top
	case err == nil && !empty:
		g.protectEntry(g.project, globalConfigs)
	}
	found, deep, truncated := scanGitTree(g.project)
	for _, e := range found {
		if e != top {
			g.protectEntry(filepath.Dir(e), globalConfigs)
		}
	}
	// Submodule checkouts .gitmodules names, wherever they are (the scan
	// above is bounded).
	for _, wt := range append([]string{g.project}, entryWorktrees(found)...) {
		for _, sub := range submodulePaths(wt) {
			g.protectEntry(sub, globalConfigs)
		}
	}
	if truncated {
		g.notes = append(g.notes, "the project has more than "+strconv.Itoa(gitScanEntries)+" entries: the search for nested git repositories stopped early; repositories it did not reach are not protected and new ones there are not reported")
	}
	if deep > 0 {
		g.notes = append(g.notes, strconv.Itoa(deep)+" directories lie more than "+strconv.Itoa(gitScanDepth)+" levels below the project and were not searched for nested git repositories: one there is not protected unless .gitmodules names it")
	}
	sort.Strings(g.watch)
	return found
}

// entryWorktrees returns the work trees of .git entries.
func entryWorktrees(entries []string) []string {
	var out []string
	for _, e := range entries {
		out = append(out, filepath.Dir(e))
	}
	return out
}

// submodulePaths returns the submodule checkout directories the
// .gitmodules file of worktree names, kept inside worktree.
func submodulePaths(worktree string) []string {
	entries, err := parseGitConfig(filepath.Join(worktree, ".gitmodules"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.section != "submodule" || e.name != "path" || e.value == "" || filepath.IsAbs(e.value) {
			continue
		}
		p := filepath.Join(worktree, e.value)
		if p != worktree && underAny(p, []string{worktree}) {
			out = append(out, p)
		}
	}
	return out
}

// protectEntry protects worktree/.git, a directory or a gitfile.
func (g *gitGuard) protectEntry(worktree string, globalConfigs []string) {
	e := filepath.Join(worktree, ".git")
	fi, err := os.Lstat(e)
	if err != nil {
		return
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		if g.isWritable(e) && !g.allowLinks {
			g.refusals = append(g.refusals, e+" is a symbolic link: the agent could replace it with a git directory of its own, whose hooks and config your git would use")
			return
		}
		g.notes = append(g.notes, e+" is a symbolic link: the agent can replace the link itself; review it before you use git there")
		if real, err := filepath.EvalSymlinks(e); err == nil {
			g.protectGitDir(real, worktree, globalConfigs, 0)
		}
	case fi.IsDir():
		g.protectGitDir(e, worktree, globalConfigs, 0)
	case fi.Mode().IsRegular():
		// A gitfile ("gitdir: PATH"): a linked worktree or a submodule
		// checkout. The file itself decides where git looks.
		g.protect(e, false, false, "")
		if gd := readGitfile(e); gd != "" {
			g.protectGitDir(gd, worktree, globalConfigs, 0)
		}
	}
}

// readGitfile returns the git directory a gitfile names, resolved
// relative to the file's directory.
func readGitfile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 4096 {
		return ""
	}
	v, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
	if !ok {
		return ""
	}
	return resolveFrom(filepath.Dir(p), strings.TrimSpace(v))
}

func resolveFrom(base, p string) string {
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// protectGitDir protects one git directory and what hangs off it.
func (g *gitGuard) protectGitDir(gd, worktree string, globalConfigs []string, depth int) {
	if gd == "" || depth > gitMaxNesting || g.seen[gd] {
		return
	}
	g.seen[gd] = true
	if fi, err := os.Stat(gd); err != nil || !fi.IsDir() {
		return
	}
	if g.isWritable(gd) {
		g.pin(gd)
		g.protectStrict(filepath.Join(gd, "config"), false, true, "")
		g.protectStrict(filepath.Join(gd, "config.worktree"), false, true, "")
		g.protectStrict(filepath.Join(gd, "hooks"), true, true, "")
		g.protectStrict(filepath.Join(gd, "gitdir"), false, false, "")
		if _, err := os.Lstat(filepath.Join(gd, "commondir")); err == nil {
			g.protectStrict(filepath.Join(gd, "commondir"), false, false, "")
		} else {
			g.watch = append(g.watch, gd)
		}
	}
	// The common directory holds config and hooks for linked worktrees.
	if cd := readTrimmed(filepath.Join(gd, "commondir")); cd != "" {
		g.protectGitDir(resolveFrom(gd, cd), "", globalConfigs, depth+1)
	}
	// The work tree: core.worktree (submodules), the gitdir backlink
	// (linked worktrees), or the caller's.
	cfg := filepath.Join(gd, "config")
	if wt := gitConfigValue(cfg, "core.worktree"); wt != "" {
		worktree = resolveFrom(gd, wt)
	} else if bl := readTrimmed(filepath.Join(gd, "gitdir")); bl != "" {
		worktree = filepath.Dir(resolveFrom(gd, bl))
	}
	if worktree == "" && filepath.Base(gd) == ".git" {
		worktree = filepath.Dir(gd)
	}
	files := append([]string{cfg, filepath.Join(gd, "config.worktree")}, globalConfigs...)
	g.hookDirs = nil
	for _, f := range files {
		g.protectConfig(f, worktree, 0)
	}
	if worktree != "" {
		g.protectHookManagers(worktree, append([]string{filepath.Join(gd, "hooks")}, g.hookDirs...))
	}
	for _, sub := range gitSubdirs(filepath.Join(gd, "modules")) {
		g.protectGitDir(sub, "", globalConfigs, depth+1)
	}
	if ents, err := os.ReadDir(filepath.Join(gd, "worktrees")); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				g.protectGitDir(filepath.Join(gd, "worktrees", e.Name()), "", globalConfigs, depth+1)
			}
		}
	}
}

// gitSubdirs returns the git directories below root (submodule names may
// contain "/"), without descending into them.
func gitSubdirs(root string) []string {
	var out []string
	n := 0
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		ents, err := os.ReadDir(d)
		if err != nil || depth > gitScanDepth {
			return
		}
		for _, e := range ents {
			if n++; n > gitScanEntries || !e.IsDir() {
				continue
			}
			p := filepath.Join(d, e.Name())
			if isGitDir(p) {
				out = append(out, p)
				continue
			}
			walk(p, depth+1)
		}
	}
	walk(root, 0)
	return out
}

// isGitDir reports whether d looks like a git directory.
func isGitDir(d string) bool {
	if fi, err := os.Stat(filepath.Join(d, "HEAD")); err != nil || fi.IsDir() {
		return false
	}
	_, err := os.Stat(filepath.Join(d, "objects"))
	_, err2 := os.Stat(filepath.Join(d, "commondir"))
	return err == nil || err2 == nil
}

// scanGitEntries returns every .git (directory, file or link) in project
// down to gitScanDepth levels, the top one included (see scanGitTree).
func scanGitEntries(project string) []string {
	out, _, _ := scanGitTree(project)
	return out
}

// scanGitTree returns every .git (directory, file or link) in project down
// to gitScanDepth levels, the top one included. It does not descend into
// .git directories nor into gitScanSkip directories. deep counts the
// directories left out for their depth; truncated reports that the entry
// budget ran out before the walk ended.
func scanGitTree(project string) (out []string, deep int, truncated bool) {
	n := 0
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		ents, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range ents {
			if n++; n > gitScanEntries {
				truncated = true
				return
			}
			p := filepath.Join(d, e.Name())
			switch {
			case e.Name() == ".git":
				out = append(out, p)
			case !e.IsDir() || gitScanSkip[e.Name()]:
			case depth < gitScanDepth:
				walk(p, depth+1)
				if truncated {
					return
				}
			default:
				deep++
			}
		}
	}
	walk(project, 0)
	sort.Strings(out)
	return out, deep, truncated
}

// NewGitEntries returns the .git entries in project that were not in
// before: repositories created while the agent ran.
func NewGitEntries(project string, before []string) []string {
	known := map[string]bool{}
	for _, b := range before {
		known[b] = true
	}
	var out []string
	for _, e := range scanGitEntries(project) {
		if !known[e] {
			out = append(out, e)
		}
	}
	return out
}

// protectConfig parses one git config file (and what it includes) and
// protects the paths it names that lie in a writable area.
func (g *gitGuard) protectConfig(file, worktree string, depth int) {
	if depth > 5 || g.configs[file+"\x00"+worktree] {
		return
	}
	g.configs[file+"\x00"+worktree] = true
	entries, err := parseGitConfig(file)
	if err != nil {
		return
	}
	base := filepath.Dir(file)
	for _, e := range entries {
		switch {
		case e.key == "core.hookspath":
			if p := g.expand(e.value, worktree); p != "" {
				g.protectStrict(p, true, true, "")
				g.hookDirs = append(g.hookDirs, p)
			}
		case e.section == "include" && e.name == "path", e.section == "includeif" && e.name == "path":
			if p := g.expandFrom(e.value, base); p != "" {
				g.protect(p, false, true, "")
				g.protectConfig(p, worktree, depth+1)
			}
		default:
			// A command that names a script by path ("./x.sh",
			// "!sh scripts/a"): in the work tree it would run with the
			// person's rights. The program of a command-valued key that
			// does not exist yet and is written as a path ("./x.sh",
			// "~/bin/x") gets an empty read-only placeholder, so the agent
			// cannot create it.
			for i, p := range commandPaths(e.value) {
				q := g.expand(p, worktree)
				if q == "" {
					continue
				}
				if fi, err := os.Stat(q); err == nil && fi.Mode().IsRegular() {
					g.protect(q, false, false, "")
				} else if os.IsNotExist(err) && i == 0 && isCommandKey(e) && explicitPath(p) {
					g.protect(q, false, true, "")
				}
			}
		}
	}
}

// commandNames are, per config section, the names whose value is a
// command ("*": every name, as for alias.* and pager.*).
var commandNames = map[string]map[string]bool{
	"alias": {"*": true}, "pager": {"*": true},
	"filter":    {"clean": true, "smudge": true, "process": true},
	"diff":      {"textconv": true, "command": true, "external": true},
	"merge":     {"driver": true},
	"mergetool": {"cmd": true, "path": true},
	"difftool":  {"cmd": true, "path": true},
	"gpg":       {"program": true},
}

// commandKeys are other config keys whose value is a command.
var commandKeys = map[string]bool{
	"core.fsmonitor": true, "core.sshcommand": true, "core.editor": true, "core.pager": true, "core.askpass": true,
	"sequence.editor": true, "interactive.difffilter": true, "uploadpack.packobjectshook": true, "sendemail.smtpserver": true,
}

// isCommandKey reports whether the value of e is a command git runs.
func isCommandKey(e gitConfigEntry) bool {
	if n, ok := commandNames[e.section]; ok && (n["*"] || n[e.name]) {
		return true
	}
	return commandKeys[e.key]
}

// explicitPath reports whether a command word is written as a path
// ("./x", "../x", "~/x", "/x"), not a word that only contains a "/"
// (a branch name, a format string).
func explicitPath(w string) bool {
	for _, pre := range []string{"./", "../", "~/", "/"} {
		if strings.HasPrefix(w, pre) {
			return !strings.ContainsAny(w, "%:@")
		}
	}
	return false
}

// expand resolves a config path value: "~/" is the person's home, a
// relative path is relative to the work tree.
func (g *gitGuard) expand(v, worktree string) string {
	switch {
	case v == "":
		return ""
	case strings.HasPrefix(v, "~/"):
		return resolveFrom(g.home, v[2:])
	case filepath.IsAbs(v):
		return resolveFrom("/", v)
	case worktree != "":
		return resolveFrom(worktree, v)
	}
	return ""
}

// expandFrom resolves an include path: relative to the including file.
func (g *gitGuard) expandFrom(v, base string) string {
	if strings.HasPrefix(v, "~/") || filepath.IsAbs(v) {
		return g.expand(v, "")
	}
	return resolveFrom(base, v)
}

// commandPaths returns the words of a command line that look like paths
// ("./x.sh --flag", "!sh scripts/a", "~/bin/x", "$HOME/h.sh"); URLs and
// options are left out.
func commandPaths(v string) []string {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "!"))
	var out []string
	for _, w := range strings.Fields(v) {
		w = strings.Trim(w, `"';&|()`)
		if _, after, ok := strings.Cut(w, "="); ok && strings.HasPrefix(w, "--") {
			w = after
		}
		for _, pre := range []string{"$HOME/", "${HOME}/"} {
			if strings.HasPrefix(w, pre) {
				w = "~/" + w[len(pre):]
			}
		}
		if !strings.Contains(w, "/") || strings.Contains(w, "://") || strings.HasPrefix(w, "-") || strings.ContainsAny(w, "*?$`") {
			continue
		}
		out = append(out, w)
	}
	return out
}

// commandPathsIn returns the absolute paths of the scripts a settings
// file names in its string values (JSON, TOML, YAML: anything quoted):
// hook commands, status line commands, key helpers, MCP server commands.
func commandPathsIn(file, home string) []string {
	b, err := os.ReadFile(file)
	if err != nil || len(b) > 4<<20 {
		return nil
	}
	var out []string
	for _, m := range quotedRe.FindAllStringSubmatch(string(b), -1) {
		lit := m[1] + m[2]
		for _, p := range commandPaths(strings.ReplaceAll(lit, `\/`, "/")) {
			switch {
			case strings.HasPrefix(p, "~/"):
				out = append(out, filepath.Join(home, p[2:]))
			case filepath.IsAbs(p):
				out = append(out, filepath.Clean(p))
			}
		}
	}
	return out
}

var quotedRe = regexp.MustCompile(`"((?:[^"\\\n]|\\.){1,1000})"|'([^'\n]{1,1000})'`)

func readTrimmed(p string) string {
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 4096 {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// gitConfigEntry is one "key = value" of a git config file. key is
// "section.name" (lower case, subsection left out), section and name are
// its parts (lower case).
type gitConfigEntry struct {
	section, sub, name, key, value string
}

// parseGitConfig reads a git config file: sections ([core], [include],
// [includeIf "gitdir:..."], [section.sub]), "name = value" lines, bare
// names (true), quoted values, escapes, comments and continuation lines.
// It is lenient: it only needs to find the values that name programs.
func parseGitConfig(file string) ([]gitConfigEntry, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []gitConfigEntry
	section, sub := "", ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	pending := ""
	for sc.Scan() {
		line := pending + sc.Text()
		pending = ""
		if strings.HasSuffix(line, "\\") && !strings.HasSuffix(line, "\\\\") {
			pending = strings.TrimSuffix(line, "\\")
			continue
		}
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		if t[0] == '[' {
			end := strings.IndexByte(t, ']')
			if end < 0 {
				continue
			}
			h := strings.TrimSpace(t[1:end])
			sub = ""
			if i := strings.IndexAny(h, " \t"); i >= 0 {
				sub = strings.Trim(strings.TrimSpace(h[i:]), `"`)
				h = h[:i]
			} else if i := strings.IndexByte(h, '.'); i >= 0 {
				sub = h[i+1:]
				h = h[:i]
			}
			section = strings.ToLower(h)
			t = strings.TrimSpace(t[end+1:])
			if t == "" || t[0] == '#' || t[0] == ';' {
				continue
			}
		}
		name, val, hasVal := strings.Cut(t, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !hasVal {
			val = "true"
		}
		e := gitConfigEntry{section: section, sub: sub, name: name, key: section + "." + name, value: unquoteGitValue(val)}
		out = append(out, e)
	}
	return out, sc.Err()
}

// unquoteGitValue removes quotes, handles escapes and drops a trailing
// comment outside quotes.
func unquoteGitValue(v string) string {
	var b strings.Builder
	inQ := false
	v = strings.TrimSpace(v)
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '"':
			inQ = !inQ
		case c == '\\' && i+1 < len(v):
			i++
			switch v[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(v[i])
			}
		case (c == '#' || c == ';') && !inQ:
			return strings.TrimSpace(b.String())
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

// gitConfigValue returns the last value of key in file.
func gitConfigValue(file, key string) string {
	entries, err := parseGitConfig(file)
	if err != nil {
		return ""
	}
	v := ""
	for _, e := range entries {
		if e.key == key {
			v = e.value
		}
	}
	return v
}

func dirEmpty(d string) bool {
	f, err := os.Open(d)
	if err != nil {
		return false
	}
	defer f.Close()
	names, _ := f.Readdirnames(1)
	return len(names) == 0
}
