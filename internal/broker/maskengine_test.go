package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/secretsrc"
)

const testValue = "s3cr3t-VALUE-0123456789"

// testEngine is an Engine whose secrets.conf names TOKEN (loaded at start)
// and LATER (only by name), both read through a fake command runner.
func testEngine(t *testing.T) *Engine {
	t.Helper()
	cfg, err := secretsrc.ParseConfig("test.conf", `
[secrets]
TOKEN = cmd:token
LATER = cmd:later
[commands]
token = ["token"]
later = ["later"]
`)
	if err != nil {
		t.Fatal(err)
	}
	run := func(_ context.Context, argv []string) ([]byte, error) {
		switch argv[0] {
		case "token":
			return []byte(testValue + "\n"), nil
		case "later":
			return []byte("later-secret-987654\n"), nil
		}
		return nil, errors.New("no such command")
	}
	cfg.Secrets = cfg.Secrets[:1] // LATER is not in the list at start
	e := NewEngine(EngineConfig{Resolver: secretsrc.NewResolver(cfg, secretsrc.Options{Run: run}), Width: 10})
	t.Cleanup(e.Close)
	// Later reads see the full configuration (as after `cotty secrets add`).
	full, _ := secretsrc.ParseConfig("test.conf", "[secrets]\nTOKEN = cmd:token\nLATER = cmd:later\n[commands]\ntoken = [\"token\"]\nlater = [\"later\"]\n")
	e.load = func() (*secretsrc.Resolver, error) {
		return secretsrc.NewResolver(full, secretsrc.Options{Run: run}), nil
	}
	return e
}

func TestEngineMasksWrappedScreen(t *testing.T) {
	e := testEngine(t)
	// The value wraps across three 10-column rows.
	rows := []string{"$ echo " + testValue[:3], testValue[3:13], testValue[13:] + " done"}
	res := e.MaskScreen("", rows, 10)
	joined := strings.Join(res.Rows, "")
	if strings.Contains(joined, testValue[3:13]) || len(res.Hits) == 0 || res.Hits[0].Name != "TOKEN" {
		t.Fatalf("not masked: %q %v", res.Rows, res.Hits)
	}
	if !strings.Contains(joined, "[masked:TOKEN]") {
		t.Fatalf("no replacement: %q", res.Rows)
	}
	// Half scrolled out: the head is in the scrollback above.
	res = e.MaskScreen("$ echo "+testValue[:8], []string{testValue[8:], "$ "}, 10)
	if strings.Contains(res.Rows[0], testValue[8:]) {
		t.Fatalf("tail of a value scrolled half out stays visible: %q", res.Rows)
	}
}

func TestEngineCommittedEdges(t *testing.T) {
	e := testEngine(t)
	// Head in the context (an earlier read), tail in this read.
	res := e.MaskLines("x "+testValue[:9], []string{testValue[9:], "next"}, nil, "")
	if strings.Contains(strings.Join(res.Rows, "\n"), testValue[9:]) || len(res.Rows) != 2 {
		t.Fatalf("tail leaked: %q", res.Rows)
	}
	// Head in this read, tail still on the screen.
	res = e.MaskLines("", []string{"y " + testValue[:12]}, []bool{true}, testValue[12:]+"\n$ ")
	if strings.Contains(res.Rows[0], testValue[:12]) {
		t.Fatalf("head leaked: %q", res.Rows)
	}
}

func TestEngineAddByName(t *testing.T) {
	e := testEngine(t)
	if out, _ := e.MaskText("a later-secret-987654 b"); !strings.Contains(out, "later-secret") {
		t.Fatalf("LATER masked before it was asked for: %q", out)
	}
	if err := e.AddByName("LATER"); err != nil {
		t.Fatal(err)
	}
	if out, _ := e.MaskText("a later-secret-987654 b"); out != "a [masked:LATER] b" {
		t.Fatalf("LATER not masked: %q", out)
	}
	if err := e.AddByName("NOPE"); !errors.Is(err, ErrUnknownSecret) {
		t.Fatalf("unknown name: %v", err)
	}
	for _, s := range []string{fmt.Sprint(e.eng), fmt.Sprintf("%#v", e.eng), fmt.Sprintf("%+v", e.eng)} {
		if strings.Contains(s, testValue) || strings.Contains(s, "later-secret") {
			t.Fatalf("engine prints a value: %s", s)
		}
	}
}

func TestEngineNoConfig(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigPath: t.TempDir() + "/missing.conf"})
	defer e.Close()
	if err := e.AddByName("X"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("no config: %v", err)
	}
	// Built-in rules still run.
	if out, _ := e.MaskText("ghp_" + strings.Repeat("a1B2", 9)); !strings.Contains(out, "[masked:") {
		t.Fatalf("built-in rule did not run: %q", out)
	}
}

func TestJoinWrapped(t *testing.T) {
	lines := []string{"abc", "defgh", "ij", "klm"}
	wrapped := []bool{false, true, false, true}
	if text := joinWrapped(lines, wrapped); text != "abc\ndefghij\nklm" {
		t.Fatalf("join %q", text)
	}
}

// S28, S33: a failing source is not run again before its backoff ends; a
// value too short for the list gives the agent a generic error; a value
// already on the list is read again after reloadAfter and a rotated value
// is masked next to the old one.
func TestEngineAddByNameThrottleAndRotation(t *testing.T) {
	cfg, err := secretsrc.ParseConfig("test.conf", "[secrets]\nBAD = cmd:bad\nSHORT = cmd:short\nROT = cmd:rot\n[commands]\nbad = [\"bad\"]\nshort = [\"short\"]\nrot = [\"rot\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	rot := "rotating-value-AAAA-1"
	run := func(_ context.Context, argv []string) ([]byte, error) {
		calls[argv[0]]++
		switch argv[0] {
		case "short":
			return []byte("abc"), nil
		case "rot":
			return []byte(rot), nil
		}
		return nil, errors.New("keyring locked")
	}
	r := secretsrc.NewResolver(cfg, secretsrc.Options{Run: run})
	e := &Engine{eng: NewEngine(EngineConfig{ConfigPath: t.TempDir() + "/none"}).eng, logf: func(string, ...any) {},
		loaded: map[string]time.Time{}, failed: map[string]failure{}}
	t.Cleanup(e.Close)
	e.load = func() (*secretsrc.Resolver, error) { return r, nil }
	now := time.Unix(1000, 0)
	e.now = func() time.Time { return now }

	for range 3 {
		if err := e.AddByName("BAD"); !errors.Is(err, ErrNotMaskable) {
			t.Fatalf("BAD: %v", err)
		}
	}
	if calls["bad"] != 1 {
		t.Errorf("failing source ran %d times inside its backoff", calls["bad"])
	}
	now = now.Add(backoffFirst + time.Second)
	_ = e.AddByName("BAD")
	if calls["bad"] != 2 {
		t.Errorf("source not retried after the backoff: %d", calls["bad"])
	}

	err = e.AddByName("SHORT")
	if !errors.Is(err, ErrNotMaskable) || strings.Contains(err.Error(), "short") || strings.Contains(err.Error(), "minimum") {
		t.Errorf("short value error tells too much: %v", err)
	}

	if err := e.AddByName("ROT"); err != nil {
		t.Fatal(err)
	}
	old := rot
	rot = "rotating-value-BBBB-2"
	_ = e.AddByName("ROT") // within reloadAfter: not read again
	if calls["rot"] != 1 {
		t.Errorf("value read again too soon: %d", calls["rot"])
	}
	now = now.Add(reloadAfter + time.Second)
	if err := e.AddByName("ROT"); err != nil {
		t.Fatal(err)
	}
	if out, _ := e.MaskText(old + " " + rot); out != "[masked:ROT] [masked:ROT]" {
		t.Errorf("rotation: %q", out)
	}
}
