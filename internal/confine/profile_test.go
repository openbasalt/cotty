package confine

import (
	"strings"
	"testing"
)

func TestBuiltinProfilesParse(t *testing.T) {
	names := ListProfiles()
	for _, want := range []string{"claude", "codex", "gemini", "cursor-agent", "aider", "opencode", "generic"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("built-in profile %s missing (have %v)", want, names)
		}
	}
	for _, n := range names {
		if _, err := LoadProfile(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}

func TestProfileRejects(t *testing.T) {
	cases := map[string]string{
		"credential store": "[agent]\nname = x\n[home]\nrw = .ssh/\n",
		"keyring":          "[agent]\nname = x\n[home]\nro = .local/share/keyrings\n",
		"absolute home":    "[agent]\nname = x\n[home]\nrw = /etc\n",
		"parent":           "[agent]\nname = x\n[home]\nrw = ../other\n",
		"home itself":      "[agent]\nname = x\n[home]\nrw = .\n",
		"reserved env":     "[agent]\nname = x\n[env]\nHOME = /tmp\n",
		"unknown section":  "[agent]\nname = x\n[egress]\nallow = a\n",
		"bad mcp":          "[agent]\nname = x\n[mcp]\nstyle = magic\n",
		"command path":     "[agent]\nname = x\ncommand = /usr/bin/x\n",
		"root path":        "[agent]\nname = x\n[paths]\nro = /\n",
		"keep all":         "[agent]\nname = x\n[scrub]\nkeep = *\n",
		"keep short":       "[agent]\nname = x\n[scrub]\nkeep = A*\n",
	}
	for name, src := range cases {
		if _, err := ParseProfile(strings.NewReader(src), name); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProfileParse(t *testing.T) {
	src := `[agent]
name = demo
command = demo
args = --a --b
match = demo demo2
[home]
rw = .demo/
ro = .local/bin/demo
protect = .demo/settings.json
[paths]
ro = /opt/demo
dev = kvm
[sockets]
allow = /run/demo.sock
[env]
DEMO = 1
[scrub]
keep = GH_TOKEN
drop = DEMO_SECRET*
[mcp]
style = codex
`
	p, err := ParseProfile(strings.NewReader(src), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if p.Command != "demo" || len(p.Args) != 2 || len(p.Match) != 2 || p.HomeRW[0] != ".demo/" ||
		p.HomeProtect[0] != ".demo/settings.json" || p.PathRO[0] != "/opt/demo" || p.Devices[0] != "kvm" ||
		p.Sockets[0] != "/run/demo.sock" || p.Env["DEMO"] != "1" || p.ScrubKeep[0] != "GH_TOKEN" ||
		p.ScrubDrop[0] != "DEMO_SECRET*" || p.MCPStyle != "codex" {
		t.Fatalf("unexpected profile %+v", p)
	}
}
