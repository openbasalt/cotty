package mask

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// The structured fuzz targets build text out of two disjoint alphabets:
// secrets (and therefore every encoded variant of them) only use
// secretAlphabet bytes, and the filler between them only uses fillerRunes.
// After masking and removing the [masked:NAME] replacements, no byte of the
// secret alphabet may be left: any one would be a piece of a secret
// occurrence that escaped the mask. That covers prefixes, suffixes, wrapped
// rows, adjacent and overlapping secrets in one check, and is stronger than
// "no substring of MinLen bytes survives".

const secretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" + ".-_~ /+=%"

// fillerRunes holds punctuation that no variant produces (base64 uses
// + / = - _, percent encoding uses % and hex digits) plus non-ASCII text.
var fillerRunes = []rune("!#(),;<>|\t\"'*?@[]{}^`\\:&$éß日本語→€ ​")

var replRE = regexp.MustCompile(`\[masked:[A-Za-z0-9_.-]+\]`)

type fuzzGen struct {
	b []byte
	i int
}

func (g *fuzzGen) next() byte {
	if g.i >= len(g.b) {
		return 0
	}
	c := g.b[g.i]
	g.i++
	return c
}

func (g *fuzzGen) intn(n int) int { return int(g.next()) % n }

func (g *fuzzGen) str(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[g.intn(len(alphabet))]
	}
	return string(b)
}

// buildCase reads secrets and a text from data. It returns the engine
// options' flags, the secrets that were added and the text.
func buildCase(t testing.TB, data []byte, opts Options) (*Engine, string, [][]byte) {
	g := &fuzzGen{b: data}
	if g.next()&1 == 1 {
		opts.Entropy = true
	}
	if g.next()&1 == 1 {
		opts.PartialMin = 8 + g.intn(8)
	}
	e := New(opts)
	var values [][]byte
	var allVars [][][]byte
	names := []string{"S0", "S1", "S2", "S3"}
	n := 1 + g.intn(4)
	for k := 0; k < n; k++ {
		var v string
		length := 6 + g.intn(30)
		switch mode := g.intn(4); {
		case mode == 0:
			v = g.str("ab1", length) // self-overlapping values
		case mode == 2 && len(values) > 0:
			prev := string(values[g.intn(len(values))])
			v = prev[1+g.intn(len(prev)-1):] + g.str(secretAlphabet, 1+g.intn(8))
		case mode == 3 && len(values) > 0:
			prev := string(values[g.intn(len(values))])
			v = prev[:1+g.intn(len(prev)-1)] + g.str(secretAlphabet, 1+g.intn(8))
		default:
			v = g.str(secretAlphabet, length)
		}
		if len(v) < 6 {
			v += g.str("xyz", 6-len(v))
		}
		if err := e.AddSecret(names[k], []byte(v)); err != nil {
			continue
		}
		values = append(values, []byte(v))
		a, vars := buildVariants([]byte(v))
		var vs [][]byte
		for _, x := range vars {
			vs = append(vs, append([]byte(nil), x.b...))
		}
		a.free()
		allVars = append(allVars, vs)
	}
	var b strings.Builder
	for segs := 1 + g.intn(12); segs > 0; segs-- {
		if g.intn(3) == 0 || len(allVars) == 0 {
			for j := g.intn(8); j > 0; j-- {
				b.WriteRune(fillerRunes[g.intn(len(fillerRunes))])
			}
			continue
		}
		vs := allVars[g.intn(len(allVars))]
		b.Write(vs[g.intn(len(vs))])
	}
	return e, b.String(), values
}

func checkNoSecretBytes(t *testing.T, in, out, alphabet string) {
	t.Helper()
	stripped := replRE.ReplaceAllString(out, "\x00")
	if i := strings.IndexAny(stripped, alphabet); i >= 0 {
		t.Fatalf("secret byte %q survived at %d\n in: %q\nout: %q", stripped[i], i, in, out)
	}
}

func FuzzMaskText(f *testing.F) {
	f.Add([]byte{0, 0, 1, 1, 10, 1, 0, 2, 2, 1, 0, 1})
	f.Add([]byte{0, 1, 3, 0, 20, 1, 2, 3, 4, 5, 6, 2, 9, 3, 1, 1, 7, 1, 0})
	f.Add([]byte("overlapping and adjacent secrets with unicode filler"))
	f.Fuzz(func(t *testing.T, data []byte) {
		e, text, _ := buildCase(t, data, Options{})
		defer e.Close()
		out, hits := e.MaskText(text)
		checkNoSecretBytes(t, text, out, secretAlphabet)
		if out != text && len(hits) == 0 {
			t.Fatalf("text changed without hits")
		}
	})
}

func FuzzMaskRows(f *testing.F) {
	f.Add([]byte{0, 0, 1, 1, 10, 1, 0, 2, 2, 1, 0, 1}, uint8(7), true)
	f.Add([]byte("wrapped secrets across rows"), uint8(1), false)
	f.Add([]byte{1, 0, 3, 1, 30, 1, 2, 2, 0, 2, 2, 1, 2, 3, 1, 2}, uint8(13), true)
	f.Fuzz(func(t *testing.T, data []byte, w uint8, setWidth bool) {
		width := 1 + int(w)%60
		opts := Options{}
		if setWidth {
			opts.Width = width
		}
		e, text, _ := buildCase(t, data, opts)
		defer e.Close()
		// Wrap the text at width runes, as a terminal does.
		var rows []string
		runes := []rune(text)
		for i := 0; i < len(runes); i += width {
			rows = append(rows, string(runes[i:min(len(runes), i+width)]))
		}
		out, _ := e.MaskRows(rows)
		if len(out) != len(rows) {
			t.Fatalf("row count %d -> %d", len(rows), len(out))
		}
		for i := range out {
			if !utf8.ValidString(out[i]) {
				t.Fatalf("row %d not valid UTF-8: %q", i, out[i])
			}
		}
		// Spaces of the input around spans are not evidence of a leak.
		checkNoSecretBytes(t, text, strings.Join(out, ""), strings.ReplaceAll(secretAlphabet, " ", ""))
	})
}

// FuzzMaskArbitrary uses arbitrary text around the secrets. The filler may
// now contain fragments of secrets on its own, so the check is weaker: no
// complete variant of any secret may remain in the output.
func FuzzMaskArbitrary(f *testing.F) {
	f.Add([]byte("seed"), "some text\nwith lines", uint8(3), uint8(10))
	f.Add([]byte("abcdefghij"), "abcdefghijabcdefghij", uint8(0), uint8(4))
	f.Fuzz(func(t *testing.T, sec []byte, filler string, at uint8, w uint8) {
		g := &fuzzGen{b: sec}
		value := g.str(secretAlphabet[:62], 6+g.intn(20))
		e := New(Options{})
		defer e.Close()
		if e.AddSecret("S", []byte(value)) != nil {
			return
		}
		a, vars := buildVariants([]byte(value))
		defer a.free()
		pos := int(at) % (len(filler) + 1)
		v := vars[int(at)%len(vars)].b
		text := filler[:pos] + string(v) + filler[pos:]

		check := func(out string) {
			for _, x := range vars {
				if strings.Contains(out, string(x.b)) {
					t.Fatalf("variant %s survived\n in: %q\nout: %q", x.kind, text, out)
				}
			}
		}
		out, _ := e.MaskText(text)
		check(out)

		width := 1 + int(w)%50
		var rows []string
		for i := 0; i < len(text); i += width {
			rows = append(rows, text[i:min(len(text), i+width)])
		}
		rowsOut, _ := e.MaskRows(rows)
		check(strings.Join(rowsOut, ""))
	})
}

// FuzzMaskLines cuts the text into hard lines, wraps them at a width and
// reads them in two pieces (with the other piece as context): one output
// line per input line, and no secret byte left.
func FuzzMaskLines(f *testing.F) {
	f.Add([]byte{0, 0, 1, 1, 10, 1, 0, 2, 2, 1, 0, 1}, uint8(7), uint8(1))
	f.Add([]byte{1, 0, 3, 1, 30, 1, 2, 2, 0, 2, 2, 1, 2, 3, 1, 2}, uint8(13), uint8(3))
	f.Fuzz(func(t *testing.T, data []byte, w uint8, cut uint8) {
		width := 1 + int(w)%60
		e, text, _ := buildCase(t, data, Options{})
		defer e.Close()
		var lines []string
		var wrapped []bool
		for _, hard := range strings.Split(text, "\n") {
			runes := []rune(hard)
			if len(runes) == 0 {
				lines, wrapped = append(lines, ""), append(wrapped, false)
				continue
			}
			for i := 0; i < len(runes); i += width {
				lines = append(lines, string(runes[i:min(len(runes), i+width)]))
				wrapped = append(wrapped, i+width < len(runes))
			}
		}
		k := int(cut) % (len(lines) + 1)
		join := func(ls []string, ws []bool) string {
			var b strings.Builder
			for i, l := range ls {
				b.WriteString(l)
				if !ws[i] {
					b.WriteByte('\n')
				}
			}
			return b.String()
		}
		a := e.MaskLines("", lines[:k], wrapped[:k], join(lines[k:], wrapped[k:]))
		b := e.MaskLines(join(lines[:k], wrapped[:k]), lines[k:], wrapped[k:], "")
		if len(a.Rows) != k || len(b.Rows) != len(lines)-k {
			t.Fatalf("line count: %d+%d for %d", len(a.Rows), len(b.Rows), len(lines))
		}
		out := strings.Join(a.Rows, "") + strings.Join(b.Rows, "")
		checkNoSecretBytes(t, text, out, strings.ReplaceAll(secretAlphabet, " ", ""))
	})
}
