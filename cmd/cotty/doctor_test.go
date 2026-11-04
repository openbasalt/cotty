package main

import (
	"strings"
	"testing"

	"github.com/openbasalt/cotty/internal/confine"
)

func TestSessionsSummary(t *testing.T) {
	check := func(name, status string) confine.Check { return confine.Check{Name: name, Status: status} }
	for _, tc := range []struct {
		name     string
		layer2   string
		checks   []confine.Check
		want     string
		wantNote string
	}{
		{"guard running", "confined", []confine.Check{check("binary", "ok"), check("guard", "ok")}, "strong available for new sessions (cotty-guard running)", "before cotty-guard started stay at their level"},
		{"guard running, partial layer 2", "partial", []confine.Check{check("binary", "ok"), check("guard", "ok")}, "strong available", "stay at their level"},
		{"guard not running", "confined", []confine.Check{check("binary", "ok"), check("guard", "info")}, "confined (cotty-guard not running)", "before cotty-guard starts stay confined"},
		{"guard not answering", "confined", []confine.Check{check("binary", "ok"), check("guard", "warn")}, "confined (cotty-guard not answering)", ""},
		{"untrusted binary", "confined", []confine.Check{check("binary", "warn"), check("guard", "ok")}, "weak", ""},
		{"no namespaces", "unavailable", []confine.Check{check("binary", "ok"), check("guard", "ok")}, "unavailable", ""},
	} {
		got, note := sessionsSummary(tc.layer2, tc.checks)
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: summary %q, want %q", tc.name, got, tc.want)
		}
		if !strings.Contains(note, tc.wantNote) {
			t.Errorf("%s: note %q, want it to contain %q", tc.name, note, tc.wantNote)
		}
	}
}
