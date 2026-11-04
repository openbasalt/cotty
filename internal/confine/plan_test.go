package confine

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCheckProject(t *testing.T) {
	home := "/home/u"
	for _, bad := range []string{"/", "/home", "/home/u", "/home/u/.ssh", "/home/u/.ssh/x", "/home/u/.gnupg"} {
		if checkProject(bad, home) == nil {
			t.Errorf("%s accepted as project", bad)
		}
	}
	for _, good := range []string{"/home/u/src/app", "/srv/app", "/tmp/x"} {
		if err := checkProject(good, home); err != nil {
			t.Errorf("%s refused: %v", good, err)
		}
	}
}

func TestSortBinds(t *testing.T) {
	bs := sortBinds([]Bind{
		{Target: "/h/.claude/settings.json"}, {Target: "/h/.claude"}, {Target: "/h/p"}, {Target: "/h/.claude", RW: true},
	})
	if len(bs) != 3 || bs[len(bs)-1].Target != "/h/.claude/settings.json" {
		t.Fatalf("order %v", bs)
	}
	for _, b := range bs {
		if b.Target == "/h/.claude" && b.RW {
			t.Fatal("a read-write duplicate replaced a read-only bind")
		}
	}
	bs = sortBinds([]Bind{{Target: "/h/x", RW: true, Why: "a"}, {Target: "/h/x", RW: true, Why: "b"}})
	if len(bs) != 1 || bs[0].Why != "b" {
		t.Fatalf("later duplicate did not win: %v", bs)
	}
}

func TestInjectMCP(t *testing.T) {
	argv, _, ok := injectMCP("claude", []string{"claude", "-p", "hi"}, map[string]string{}, "/run/user/1/cotty/bin/cotty")
	if !ok || argv[3] != "--mcp-config" || !strings.Contains(argv[4], `"args":["mcp"]`) || argv[2] != "hi" {
		t.Fatalf("claude: %q", argv)
	}
	argv, _, _ = injectMCP("claude", []string{"claude", "x", "--", "y"}, map[string]string{}, "/b")
	if argv[2] != "--mcp-config" || argv[4] != "--" {
		t.Fatalf("claude with --: %q", argv)
	}
	if _, _, ok := injectMCP("claude", []string{"claude", "mcp", "list"}, map[string]string{}, "/b"); ok {
		t.Fatal("claude subcommand got --mcp-config")
	}
	argv, _, _ = injectMCP("codex", []string{"codex", "exec", "hi"}, map[string]string{}, "/b")
	if argv[1] != "-c" || argv[2] != `mcp_servers.cotty.command="/b"` || argv[5] != "exec" {
		t.Fatalf("codex: %q", argv)
	}
	_, env, _ := injectMCP("opencode", []string{"opencode"}, map[string]string{}, "/b")
	if !strings.Contains(env["OPENCODE_CONFIG_CONTENT"], `"command":["/b","mcp"]`) {
		t.Fatalf("opencode: %v", env)
	}
	if _, _, ok := injectMCP("manual", []string{"gemini"}, map[string]string{}, "/b"); ok {
		t.Fatal("manual injected")
	}
}

func TestBuildPlan(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "src", "app")
	for _, d := range []string{proj, filepath.Join(home, ".ssh"), filepath.Join(home, ".claude")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[user]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"seeded":1,"primaryApiKey":"sk-x","mcpServers":{"gh":{"command":"gh-mcp","env":{"GITHUB_TOKEN":"t"}}},"projects":{"/p":{"mcpServers":{"a":{}},"allowedTools":[]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	agentDir := filepath.Join(t.TempDir(), "cotty", "agent")
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	env := []string{"HOME=" + home, "PATH=/usr/bin", "SSH_AUTH_SOCK=/x", "XDG_RUNTIME_DIR="}
	pl, err := BuildPlan(Options{Project: proj, Argv: []string{"claude", "-p", "hi"}, AgentDir: agentDir}, env, self)
	if err != nil {
		t.Fatal(err)
	}
	sp := pl.Spec
	if sp.Profile != "claude" {
		t.Errorf("profile %s, want claude (guessed)", sp.Profile)
	}
	targets := map[string]Bind{}
	for _, b := range sp.Binds {
		targets[b.Target] = b
	}
	realHome, _ := filepath.EvalSymlinks(home)
	if b, ok := targets[filepath.Join(realHome, "src", "app")]; !ok || !b.RW {
		t.Errorf("project bind missing or read-only: %v", sp.Binds)
	}
	if b, ok := targets[filepath.Join(realHome, ".gitconfig")]; !ok || b.RW {
		t.Errorf(".gitconfig not read-only: %v", sp.Binds)
	}
	if _, ok := targets[filepath.Join(realHome, ".ssh")]; ok {
		t.Error(".ssh bound")
	}
	if !underAny(realHome, sp.Hide) || !underAny("/run", sp.Hide) || !underAny("/tmp", sp.Hide) {
		t.Errorf("hide list %v", sp.Hide)
	}
	if GetEnv(sp.Env, "SSH_AUTH_SOCK") != "" {
		t.Error("SSH_AUTH_SOCK kept")
	}
	if !strings.HasPrefix(GetEnv(sp.Env, "PATH"), filepath.Dir(sp.SelfBin)+":") {
		t.Errorf("PATH %s", GetEnv(sp.Env, "PATH"))
	}
	if _, err := BuildPlan(Options{Project: realHome, Argv: []string{"x"}, AgentDir: agentDir}, env, self); err == nil {
		t.Error("home accepted as project")
	}

	// Claude Code keeps its settings in the bound ~/.claude directory,
	// seeded once from ~/.claude.json; ~/.claude.json is not bound.
	if got := GetEnv(sp.Env, "CLAUDE_CONFIG_DIR"); got != filepath.Join(home, ".claude") {
		t.Errorf("CLAUDE_CONFIG_DIR %q", got)
	}
	if b, err := os.ReadFile(filepath.Join(home, ".claude", ".claude.json")); err != nil || !strings.Contains(string(b), `"seeded": 1`) ||
		strings.Contains(string(b), "sk-x") || strings.Contains(string(b), "mcpServers") || !strings.Contains(string(b), "allowedTools") {
		t.Errorf("seed: %q %v", b, err)
	}
	if _, ok := targets[filepath.Join(realHome, ".claude.json")]; ok {
		t.Error("~/.claude.json bound as a file")
	}

	// The agent endpoint directory is bound read-only, the agent learns
	// where it is, and the MCP server is wired in.
	ad := GetEnv(sp.Env, "COTTY_AGENT_DIR")
	if ad == "" || ad != sp.AgentDir {
		t.Fatalf("COTTY_AGENT_DIR %q, spec %q", ad, sp.AgentDir)
	}
	if b, ok := targets[ad]; !ok || b.RW || !b.Dir || b.Source != agentDir {
		t.Errorf("agent dir bind %+v", b)
	}
	if !pl.MCP || !strings.Contains(strings.Join(sp.Argv, " "), "--mcp-config") {
		t.Errorf("mcp not injected: %v", sp.Argv)
	}

	// cotty's own state and configuration are never given to an agent.
	for _, p := range []string{".local/state/cotty", ".config/cotty", ".local"} {
		d := filepath.Join(home, p)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildPlan(Options{Project: d, Argv: []string{"x"}, AgentDir: agentDir}, env, self); err == nil {
			t.Errorf("%s accepted as project", p)
		}
		if _, err := BuildPlan(Options{Project: proj, Argv: []string{"x"}, ExtraRO: []string{d}, AgentDir: agentDir}, env, self); err == nil {
			t.Errorf("%s accepted as --ro", p)
		}
	}
}

// TestHomeLinkTargetChecked (review C0): a link at a profile home path,
// left by an agent on an earlier run in a writable directory, never gets
// its target bound when the target is a place no agent may see. A
// protected path that is such a link refuses the start; a read-only one
// is skipped with a note.
func TestHomeLinkTargetChecked(t *testing.T) {
	home := t.TempDir()
	realHome, _ := filepath.EvalSymlinks(home)
	proj := filepath.Join(home, "src", "p")
	for _, d := range []string{proj, filepath.Join(home, ".ssh"), filepath.Join(home, ".claude"), filepath.Join(home, ".local", "share")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(home, ".ssh", "id_ed25519"), "KEY")
	self, _ := os.Executable()
	env := []string{"HOME=" + home, "PATH=/usr/bin"}
	build := func() (*Plan, error) {
		return BuildPlan(Options{Project: proj, Profile: "claude", Argv: []string{"claude"}, NoMCP: true}, env, self)
	}

	// Protected path: refused.
	local := filepath.Join(home, ".claude", "local")
	if err := os.Symlink(filepath.Join(home, ".ssh"), local); err != nil {
		t.Fatal(err)
	}
	if _, err := build(); err == nil || !strings.Contains(err.Error(), ".claude/local") {
		t.Fatalf("protected link to ~/.ssh: %v", err)
	}
	if err := os.Remove(local); err != nil {
		t.Fatal(err)
	}

	// Read-only path: not bound.
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(home, ".local", "share", "claude")); err != nil {
		t.Fatal(err)
	}
	pl, err := build()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range pl.Spec.Binds {
		if underAny(b.Source, []string{filepath.Join(realHome, ".ssh")}) {
			t.Errorf("~/.ssh bound through a home link: %+v", b)
		}
	}
	for _, l := range pl.Spec.Links {
		if strings.Contains(l.Target, ".ssh") {
			t.Errorf("link to ~/.ssh recreated inside: %+v", l)
		}
	}
}

// TestHomeHide (review C1): ~/.claude/ide is covered inside (created
// empty outside when missing), a link there refuses the start, and
// --show-hidden leaves it visible.
func TestHomeHide(t *testing.T) {
	home := t.TempDir()
	realHome, _ := filepath.EvalSymlinks(home)
	proj := filepath.Join(home, "src", "p")
	for _, d := range []string{proj, filepath.Join(home, ".claude")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	self, _ := os.Executable()
	env := []string{"HOME=" + home, "PATH=/usr/bin"}
	opts := Options{Project: proj, Profile: "claude", Argv: []string{"claude"}, NoMCP: true}
	ide := filepath.Join(realHome, ".claude", "ide")
	pl, err := BuildPlan(opts, env, self)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pl.Spec.HideDirs, ide) {
		t.Errorf("~/.claude/ide not covered: %v", pl.Spec.HideDirs)
	}
	if fi, err := os.Lstat(ide); err != nil || !fi.IsDir() {
		t.Errorf("~/.claude/ide not created: %v", err)
	}
	opts.ShowHidden = true
	if pl, err = BuildPlan(opts, env, self); err != nil || slices.Contains(pl.Spec.HideDirs, ide) {
		t.Errorf("--show-hidden: %v %v", pl.Spec.HideDirs, err)
	}
	opts.ShowHidden = false
	if err := os.Remove(ide); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(proj, ide); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(opts, env, self); err == nil {
		t.Error("a link at ~/.claude/ide accepted")
	}
}
