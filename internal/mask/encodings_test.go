package mask

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Base64 of a value preceded by any prefix (user:VALUE, as in a basic auth
// header) is masked at each of the three alignments, and also when more
// bytes follow the value.
func TestBase64ShiftedAlignments(t *testing.T) {
	value := string(fakeValue(newRand(41), 24))
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "PASS", []byte(value))
	for _, prefix := range []string{"", "u:", "us:", "use:", "user:", "admin:"} {
		for _, suffix := range []string{"", "\"}", "x"} {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
				blob := enc.EncodeToString([]byte(prefix + value + suffix))
				out, hits := e.MaskText("Authorization: Basic " + blob + "\n")
				if len(hits) == 0 {
					t.Errorf("prefix %q suffix %q: not masked: %q", prefix, suffix, out)
				}
			}
		}
	}
}

func TestJSONEscapedValue(t *testing.T) {
	value := `pa"ss\wo<r>d&/x9`
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "J", []byte(value))
	b, _ := json.Marshal(map[string]string{"v": value}) // Go: < > &
	if out, hits := e.MaskText(string(b)); len(hits) == 0 {
		t.Errorf("go json: %q", out)
	}
	minimal := `{"v":"pa\"ss\\wo<r>d&/x9"}`
	if out, hits := e.MaskText(minimal); len(hits) == 0 {
		t.Errorf("minimal json: %q", out)
	}
	slash := `{"v":"pa\"ss\\wo<r>d&\/x9"}`
	if out, hits := e.MaskText(slash); len(hits) == 0 {
		t.Errorf("php json: %q", out)
	}
}

func TestMultiLineValue(t *testing.T) {
	value := "line-one-AAAA\nline-two-BBBB\nline-three-CC"
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "ML", []byte(value))
	// On screen the rows are joined without line ends.
	rows := []string{"$ cat f", "line-one-AAAA", "line-two-BBBB", "line-three-CC", "$ "}
	out, hits := e.MaskRows(rows)
	if len(hits) == 0 || strings.Contains(strings.Join(out, "|"), "two-BBBB") {
		t.Errorf("screen: %q", out)
	}
	// In committed lines hard line ends are "\n".
	m := e.MaskLines("", rows, nil, "")
	if len(m.Hits) == 0 || len(m.Rows) != len(rows) || strings.Contains(strings.Join(m.Rows, "|"), "two-BBBB") {
		t.Errorf("lines: %q", m.Rows)
	}
}

// base64 wraps its output at 76 columns: in committed lines those are hard
// line ends.
func TestBase64WrappedAt76(t *testing.T) {
	value := string(fakeValue(newRand(42), 90))
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "LONG", []byte(value))
	enc := base64.StdEncoding.EncodeToString([]byte(value + "\n"))
	var lines []string
	for i := 0; i < len(enc); i += 76 {
		lines = append(lines, enc[i:min(len(enc), i+76)])
	}
	m := e.MaskLines("$ echo \"$X\" | base64\n", lines, nil, "$ ")
	if len(m.Rows) != len(lines) {
		t.Fatalf("line count %d -> %d", len(lines), len(m.Rows))
	}
	joined := strings.Join(m.Rows, "")
	for i := 0; i+12 <= len(enc); i += 6 {
		if strings.Contains(joined, enc[i:i+12]) {
			t.Fatalf("base64 piece survived: %q", m.Rows)
		}
	}
	if !strings.HasPrefix(m.Rows[0], "[masked:LONG]") || len(m.Hits) != 1 || m.Hits[0].Row != 0 {
		t.Errorf("rows %q hits %+v", m.Rows, m.Hits)
	}
}

// MaskLines keeps one output line per input line, whatever the spans do
// (a wrapped group, a span across hard line ends).
func TestMaskLinesKeepsLineCount(t *testing.T) {
	value := string(fakeValue(newRand(43), 30))
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "V", []byte(value))
	lines := []string{"before", "x " + value[:8], value[8:20], value[20:] + " after", "next"}
	wrapped := []bool{false, true, true, false, false}
	m := e.MaskLines("", lines, wrapped, "")
	want := []string{"before", "x [masked:V]", "", " after", "next"}
	if strings.Join(m.Rows, "|") != strings.Join(want, "|") {
		t.Errorf("got %q want %q", m.Rows, want)
	}
	// Lookahead: the head is in the read, the tail after it.
	m = e.MaskLines("", []string{"y " + value[:12]}, []bool{true}, value[12:]+"\n$ ")
	if m.Rows[0] != "y [masked:V]" {
		t.Errorf("lookahead: %q", m.Rows)
	}
	// Context: the tail is in the read, the head before it.
	m = e.MaskLines("z "+value[:12], []string{value[12:] + " ok"}, nil, "")
	if m.Rows[0] != "[masked:V] ok" {
		t.Errorf("context: %q", m.Rows)
	}
}

func TestMaskGridEdits(t *testing.T) {
	value := string(fakeValue(newRand(44), 30))
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "V", []byte(value))
	rows := []string{"$ export X=" + value[:9], value[9:] + " # set"}
	m := e.MaskGrid("", rows, 20)
	if len(m.Edits) != 2 {
		t.Fatalf("edits %+v", m.Edits)
	}
	a, b := m.Edits[0], m.Edits[1]
	if a.Row != 0 || a.InStart != 11 || a.InEnd != 20 || a.OutStart != 11 || a.OutEnd != 11+len("[masked:V]") {
		t.Errorf("edit 0 %+v", a)
	}
	if b.Row != 1 || b.InStart != 0 || b.InEnd != 21 || b.OutStart != 0 || b.OutEnd != 0 {
		t.Errorf("edit 1 %+v", b)
	}
	if m.Rows[1] != " # set" {
		t.Errorf("row 1 %q", m.Rows[1])
	}
}

func TestAddSecretVersion(t *testing.T) {
	r := newRand(45)
	oldV, newV := fakeValue(r, 20), fakeValue(r, 20)
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "ROT", oldV)
	if err := e.AddSecretVersion("ROT", newV); err != nil {
		t.Fatal(err)
	}
	if err := e.AddSecretVersion("ROT", newV); err != nil {
		t.Fatal(err)
	}
	out, hits := e.MaskText(string(oldV) + " " + string(newV))
	if out != "[masked:ROT] [masked:ROT]" || len(hits) != 2 {
		t.Errorf("both values: %q", out)
	}
	if n := e.Names(); len(n) != 1 {
		t.Errorf("names %v", n)
	}
	for range 6 {
		_ = e.AddSecretVersion("ROT", fakeValue(r, 20))
	}
	if _, hits := e.MaskText(string(oldV)); len(hits) != 0 {
		t.Errorf("oldest value should be dropped after %d versions", maxVersions)
	}
	// AddSecret replaces every value.
	mustAdd(t, e, "ROT", oldV)
	if _, hits := e.MaskText(string(newV)); len(hits) != 0 {
		t.Errorf("AddSecret should replace")
	}
}

func TestAssess(t *testing.T) {
	cases := []struct {
		v     string
		short bool
		weak  bool
	}{
		{"abc12", true, false},
		{"Summer2024!", false, true},
		{"aaaaaaaaaaaaaaaa", false, true},
		{"qwerty-something-long", false, true},
		{string(fakeValue(newRand(46), 32)), false, false},
	}
	for _, c := range cases {
		short, warns := Assess([]byte(c.v))
		if short != c.short || (len(warns) > 0) != c.weak {
			t.Errorf("%d bytes: short %v warnings %q", len(c.v), short, warns)
		}
		for _, w := range warns {
			if strings.Contains(w, c.v) {
				t.Errorf("warning quotes the value")
			}
		}
	}
}
