package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbasalt/cotty/internal/secretsrc"
)

func TestSecretsConfEdit(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "secrets.conf")
	env := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(conf, []byte("[settings]\nenv_file = "+env+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := envFileSet(env, "TOKEN", []byte(" spaced value ")); err != nil {
		t.Fatal(err)
	}
	if err := envFileSet(env, "OTHER", []byte("'quoted'")); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name, ref string
		argv      []string
	}{{"TOKEN", "file:TOKEN", nil}, {"OTHER", "file:OTHER", nil}, {"HUB", "cmd:HUB", []string{"hub", "get", "x y"}}} {
		if err := confAdd(conf, step.name, step.ref, step.argv); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := secretsrc.LoadConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secrets) != 3 || strings.Join(cfg.Commands["HUB"], "|") != "hub|get|x y" {
		t.Fatalf("config %+v", cfg)
	}
	for k, want := range map[string]string{"TOKEN": " spaced value ", "OTHER": "'quoted'"} {
		v, err := secretsrc.ReadEnvKey(env, k)
		if err != nil || string(v) != want {
			t.Fatalf("%s: %q %v", k, v, err)
		}
	}
	if fi, _ := os.Stat(env); fi.Mode().Perm() != 0o600 {
		t.Errorf("env file mode %v", fi.Mode().Perm())
	}
	if err := confRemove(conf, "HUB", "HUB"); err != nil {
		t.Fatal(err)
	}
	if err := envFileRemove(env, "TOKEN"); err != nil {
		t.Fatal(err)
	}
	if err := confRemove(conf, "TOKEN", ""); err != nil {
		t.Fatal(err)
	}
	cfg, err = secretsrc.LoadConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secrets) != 1 || cfg.Secrets[0].Name != "OTHER" || len(cfg.Commands) != 0 {
		t.Fatalf("after remove %+v", cfg)
	}
	if _, err := secretsrc.ReadEnvKey(env, "TOKEN"); err == nil {
		t.Fatal("TOKEN still in the env file")
	}
}

func TestParseArgv(t *testing.T) {
	if a, _ := parseArgv(`ai-hub secret get k`); strings.Join(a, "|") != "ai-hub|secret|get|k" {
		t.Fatal(a)
	}
	if a, _ := parseArgv(`["a b", "c"]`); strings.Join(a, "|") != "a b|c" {
		t.Fatal(a)
	}
	if _, err := parseArgv(" "); err == nil {
		t.Fatal("empty accepted")
	}
}

// Values the env reader would cut at an inline comment or unquote are
// written so they read back whole.
func TestEnvFileSetRoundTrip(t *testing.T) {
	env := filepath.Join(t.TempDir(), "secrets.env")
	values := map[string]string{
		"HASH":   "abc #def-123456",
		"TAB":    "abc\t#def-123456",
		"DQ":     `"starts-with-quote`,
		"MIXED":  `a"b'c-123456`,
		"INSIDE": `x"y #z-123456`,
	}
	for k, v := range values {
		if err := envFileSet(env, k, []byte(v)); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	for k, want := range values {
		v, err := secretsrc.ReadEnvKey(env, k)
		if err != nil || string(v) != want {
			t.Errorf("%s: %q %v", k, v, err)
		}
	}
	if err := envFileSet(env, "BOTH", []byte(`a"b'c #d`)); err == nil {
		t.Errorf("value that cannot round-trip accepted")
	}
}
