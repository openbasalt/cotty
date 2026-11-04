package mask

import (
	"fmt"
	"strings"
	"testing"
)

// benchScreen builds a 200x60 screen of shell-like text with nSecrets
// secrets of 40 bytes, ten of which appear on the screen (two wrapped).
func benchScreen(b *testing.B, nSecrets int, opts Options) (*Engine, []string) {
	b.Helper()
	r := newRand(99)
	e := New(opts)
	values := make([]string, nSecrets)
	for i := range values {
		values[i] = string(fakeValue(r, 40))
		mustAdd(b, e, fmt.Sprintf("SECRET_%03d", i), []byte(values[i]))
	}
	words := []string{"drwxr-xr-x", "user", "4096", "Nov", "README.md", "go.mod", "internal/", "$", "ls", "-la", "export", "PATH=/usr/bin:/bin", "ok", "github.com/openbasalt/cotty"}
	var sb strings.Builder
	for sb.Len() < 200*60 {
		sb.WriteString(words[r.IntN(len(words))])
		sb.WriteByte(' ')
		if len(values) > 0 && r.IntN(80) == 0 {
			sb.WriteString(values[r.IntN(len(values))])
			sb.WriteByte(' ')
		}
	}
	text := sb.String()[:200*60]
	rows := make([]string, 60)
	for i := range rows {
		rows[i] = text[i*200 : (i+1)*200]
	}
	return e, rows
}

func benchmarkRows(b *testing.B, n int, opts Options) {
	e, rows := benchScreen(b, n, opts)
	e.MaskRows(rows) // build the matcher outside the timing
	b.SetBytes(200 * 60)
	b.ResetTimer()
	for b.Loop() {
		e.MaskRows(rows)
	}
}

func BenchmarkMaskRows500(b *testing.B) { benchmarkRows(b, 500, Options{Width: 200}) }
func BenchmarkMaskRows500NoRules(b *testing.B) {
	benchmarkRows(b, 500, Options{Width: 200, NoBuiltinRules: true})
}
func BenchmarkMaskRows500Partial(b *testing.B) {
	benchmarkRows(b, 500, Options{Width: 200, PartialMin: 12})
}
func BenchmarkMaskRows0(b *testing.B) { benchmarkRows(b, 0, Options{Width: 200}) }

func BenchmarkBuild500(b *testing.B) {
	e, rows := benchScreen(b, 500, Options{})
	for b.Loop() {
		e.mu.Lock()
		e.dirty = true
		e.mu.Unlock()
		e.MaskRows(rows[:1])
	}
}
