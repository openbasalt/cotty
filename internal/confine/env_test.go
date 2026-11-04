package confine

import (
	"strings"
	"testing"
)

func TestScrubEnv(t *testing.T) {
	env := []string{
		"PATH=/usr/bin", "SSH_AUTH_SOCK=/run/user/1000/ssh", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
		"DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", "KITTY_LISTEN_ON=unix:/tmp/k", "TMUX=/tmp/tmux-1000/default,1,0",
		"KONSOLE_DBUS_SERVICE=:1.2", "AWS_SECRET_ACCESS_KEY=x", "GH_TOKEN=y", "ANTHROPIC_API_KEY=z",
		"COTTY_AGENT=claude", "MY_SECRET_ONE=1", "LANG=C", "LC_ALL=C.UTF-8", "HF_TOKEN=h", "DATABASE_URL=postgres://u:p@h/db",
		"PGPASSWORD=p", "STRIPE_SECRET_KEY=s", "TF_VAR_x=1", "SWAYSOCK=/run/user/1000/sway", "NIRI_SOCKET=/n",
		"TERM_SESSION_ID=t", "GNOME_TERMINAL_SCREEN=/org/x", "OPENROUTER_API_KEY=o", "GOPATH=/g", "HTTPS_PROXY=http://p:3128",
	}
	out := strings.Join(ScrubEnv(env, []string{"GH_TOKEN", "COTTY_AGENT", "ANTHROPIC_*"}, []string{"MY_SECRET*", "GOPATH"}), "\n")
	for _, gone := range []string{"SSH_AUTH_SOCK", "DBUS_SESSION", "DISPLAY", "WAYLAND", "KITTY", "TMUX", "KONSOLE", "AWS_", "COTTY_AGENT", "MY_SECRET",
		"HF_TOKEN", "DATABASE_URL", "PGPASSWORD", "STRIPE_", "TF_VAR_", "SWAYSOCK", "NIRI_SOCKET", "TERM_SESSION_ID", "GNOME_TERMINAL", "OPENROUTER", "GOPATH"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s survived:\n%s", gone, out)
		}
	}
	for _, kept := range []string{"PATH=", "GH_TOKEN=y", "ANTHROPIC_API_KEY=z", "LANG=C", "LC_ALL=C.UTF-8", "HTTPS_PROXY="} {
		if !strings.Contains(out, kept) {
			t.Errorf("%s removed:\n%s", kept, out)
		}
	}
}

func TestScrubEnvEmptyPrefix(t *testing.T) {
	if out := ScrubEnv([]string{"GH_TOKEN=y", "PATH=/b"}, []string{"*"}, nil); strings.Join(out, ",") != "PATH=/b" {
		t.Fatalf("keep * passed %v", out)
	}
}

func TestConfiguredDisplays(t *testing.T) {
	got := strings.Join(configuredDisplays([]string{"DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0",
		"DBUS_SESSION_BUS_ADDRESS=unix:abstract=/tmp/dbus-x,guid=1"}), " ")
	for _, want := range []string{"DISPLAY=:0", "WAYLAND_DISPLAY=", "DBUS_SESSION_BUS_ADDRESS=unix:abstract"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s missing from %q", want, got)
		}
	}
	if got := configuredDisplays([]string{"DISPLAY=localhost:10.0", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"}); len(got) != 0 {
		t.Errorf("TCP display or path bus counted: %v", got)
	}
	if got := configuredDisplays([]string{"DISPLAY=unix:1"}); len(got) != 1 {
		t.Errorf("unix:1 not counted: %v", got)
	}
}

func TestSetEnv(t *testing.T) {
	out := SetEnv([]string{"A=1", "B=2"}, map[string]string{"B": "3", "C": "4"})
	if strings.Join(out, ",") != "A=1,B=3,C=4" {
		t.Fatal(out)
	}
}
