package confine

import (
	"bytes"
	"strings"
	"testing"
)

func filterAll(chunks ...string) (string, int) {
	var f TermFilter
	var out []byte
	for _, c := range chunks {
		out = f.Filter(out, []byte(c))
	}
	return string(out), f.Dropped()
}

func TestTermFilterPassesOrdinaryOutput(t *testing.T) {
	in := "hello \x1b[1;31mred\x1b[0m\r\n\x1b(B\x1b7\x1b8 ação ✓ \x1b[?1049h\t\a"
	out, d := filterAll(in)
	if out != in || d != 0 {
		t.Fatalf("got %q (dropped %d), want unchanged", out, d)
	}
}

func TestTermFilterAllowedOSC(t *testing.T) {
	for _, in := range []string{
		"\x1b]0;title\a",
		"\x1b]2;título “x”\x1b\\",
		"\x1b]7;file://host/home/x\x1b\\",
		"\x1b]8;;https://example.com\x1b\\link\x1b]8;;\x1b\\",
		"\x1b]133;A\a",
	} {
		if out, d := filterAll(in); out != in || d != 0 {
			t.Errorf("%q: got %q (dropped %d)", in, out, d)
		}
	}
}

func TestTermFilterDropsDangerous(t *testing.T) {
	for name, in := range map[string]string{
		"osc52 write":       "\x1b]52;c;ZXZpbA==\a",
		"osc52 read":        "\x1b]52;c;?\x1b\\",
		"osc5113 transfer":  "\x1b]5113;ac=send;id=1\x1b\\",
		"osc1337 file":      "\x1b]1337;File=name=eA==:ZXZpbA==\a",
		"kitty remote":      "\x1bP@kitty-cmd{\"cmd\":\"launch\",\"args\":[\"sh\"]}\x1b\\",
		"kitty graphics":    "\x1b_Ga=T,f=100;AAAA\x1b\\",
		"pm":                "\x1b^private\x1b\\",
		"sos":               "\x1bXstring\x1b\\",
		"decrqss":           "\x1bP$qm\x1b\\",
		"osc 4 color query": "\x1b]4;1;?\a",
		"c1 osc":            "\x9d52;c;ZXZpbA==\x9c",
		"c1 dcs":            "\x90@kitty-cmd{}\x9c",
		"osc with control":  "\x1b]0;a\nb\a",
	} {
		out, d := filterAll("A" + in + "B")
		if out != "AB" || d == 0 {
			t.Errorf("%s: got %q (dropped %d), want \"AB\"", name, out, d)
		}
	}
}

func TestTermFilterSplitAcrossReads(t *testing.T) {
	seqs := []string{
		"x\x1b]52;c;ZXZpbA==\x1b\\y",
		"x\x1bP@kitty-cmd{\"cmd\":\"ls\"}\x1b\\y",
		"x\x1b]0;ok title\x1b\\y",
		"x\x1b[38;5;200mz\x1b[0my",
		"x\x1b_Gq=2;AAAA\x07y",
	}
	for _, in := range seqs {
		want, _ := filterAll(in)
		// Every split point, and byte by byte.
		for i := 0; i <= len(in); i++ {
			if got, _ := filterAll(in[:i], in[i:]); got != want {
				t.Fatalf("%q split at %d: got %q, want %q", in, i, got, want)
			}
		}
		parts := strings.Split(in, "")
		if got, _ := filterAll(parts...); got != want {
			t.Fatalf("%q byte by byte: got %q, want %q", in, got, want)
		}
	}
}

func TestTermFilterUnterminatedAndNesting(t *testing.T) {
	// An OSC 52 cut short by a new sequence: the OSC is dropped, the CSI
	// after it passes.
	if out, _ := filterAll("\x1b]52;c;AAAA\x1b[1mX"); out != "\x1b[1mX" {
		t.Fatalf("got %q", out)
	}
	// A dropped string cannot smuggle a sequence: what follows ST is
	// parsed again.
	if out, _ := filterAll("\x1bPdata\x1b\\\x1b]52;c;QQ==\aZ"); out != "Z" {
		t.Fatalf("got %q", out)
	}
	// CAN aborts.
	if out, _ := filterAll("\x1b]52;c;QQ==\x18ok"); out != "ok" {
		t.Fatalf("got %q", out)
	}
	// An over-long allowed OSC is dropped.
	long := "\x1b]0;" + strings.Repeat("a", maxOSC+10) + "\aZ"
	if out, _ := filterAll(long); out != "Z" {
		t.Fatalf("long title: got %d bytes", len(out))
	}
}

func TestCopyFiltered(t *testing.T) {
	var dst bytes.Buffer
	src := strings.NewReader("a\x1b]52;c;QQ==\ab")
	if err := copyFiltered(&dst, src); err != nil {
		t.Fatal(err)
	}
	if dst.String() != "ab" {
		t.Fatalf("got %q", dst.String())
	}
}

// TestTermFilterUTF8C1 (review N12): C1 controls encoded in UTF-8 (U+0080
// to U+009F, which a terminal in UTF-8 mode decodes as the control), and
// ESC followed by a byte above ASCII, are dropped like the raw forms, also
// split across reads; ordinary two-byte characters starting with C2 pass.
func TestTermFilterUTF8C1(t *testing.T) {
	for name, in := range map[string]string{
		"utf8 osc 52":       "\xc2\x9d52;c;ZXZpbA==\xc2\x9c",
		"utf8 osc 52 bel":   "\xc2\x9d52;c;ZXZpbA==\a",
		"utf8 dcs kitty":    "\xc2\x90@kitty-cmd{}\xc2\x9c",
		"utf8 apc":          "\xc2\x9fGa=T;AAAA\xc2\x9c",
		"esc then raw osc":  "\x1b\x9d52;c;ZXZpbA==\x9c",
		"esc then utf8 osc": "\x1b\xc2\x9d52;c;ZXZpbA==\xc2\x9c",
	} {
		out, d := filterAll("A" + in + "B")
		if out != "AB" || d == 0 {
			t.Errorf("%s: got %q (dropped %d), want \"AB\"", name, out, d)
		}
		// The same, one byte per read.
		var chunks []string
		for i := range len(in) {
			chunks = append(chunks, in[i:i+1])
		}
		out, _ = filterAll(append(append([]string{"A"}, chunks...), "B")...)
		if out != "AB" {
			t.Errorf("%s split: got %q", name, out)
		}
	}
	// ESC plus an intermediate, then a C1 OSC: the OSC is dropped (the
	// intermediate sequence stays incomplete).
	if out, _ := filterAll("\x1b(\x9d52;c;ZXZpbA==\x9c"); strings.Contains(out, "52;") || strings.Contains(out, "\x9d") {
		t.Errorf("esc inter then c1 osc: %q", out)
	}
	// A UTF-8 ST inside an allowed title ends it for the terminal: the
	// title is dropped and nothing after it is taken as the title's end.
	out, _ := filterAll("\x1b]0;title\xc2\x9c\x1b]52;c;ZXZpbA==\aB")
	if strings.Contains(out, "52;") || strings.Contains(out, "]0;") {
		t.Errorf("utf8 st in a title: %q", out)
	}
	// Ordinary characters with a C2 lead byte, in text and in a title.
	for _, in := range []string{"price ¢5 £3 ©", "\x1b]2;© title\a"} {
		if out, d := filterAll(in); out != in || d != 0 {
			t.Errorf("%q: got %q (dropped %d)", in, out, d)
		}
	}
}
