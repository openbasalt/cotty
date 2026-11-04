package attach

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

// TestFilterDropsStatusRowPainters checks that sequences able to paint,
// copy into, recolour or resize the status row never reach the terminal,
// and that the filter is back in the ground state after each.
func TestFilterDropsStatusRowPainters(t *testing.T) {
	cases := map[string]string{
		"DECALN":            "\x1b#8",
		"DECCRA":            "\x1b[1;1;5;80;1;24;1;1$v",
		"DECFRA":            "\x1b[88;1;1;24;80$x",
		"DECERA":            "\x1b[1;1;24;80$z",
		"DECSERA":           "\x1b[1;1;24;80${",
		"DECCARA":           "\x1b[24;1;24;80;7$r",
		"DECRARA":           "\x1b[24;1;24;80;7$t",
		"DECSCPP":           "\x1b[132$|",
		"DECSNLS":           "\x1b[48*|",
		"DECSCL":            "\x1b[61\"p",
		"DECLRMM on":        "\x1b[?69h",
		"DECSLRM":           "\x1b[5;10s",
		"window move":       "\x1b[3;0;0t",
		"window resize":     "\x1b[8;50;100t",
		"DECSLPP":           "\x1b[48t",
		"DECCOLM":           "\x1b[?3h",
		"DECSCNM":           "\x1b[?5h",
		"KAM":               "\x1b[2h",
		"SRM local echo":    "\x1b[12l",
		"UTF-8 off":         "\x1b%@",
		"S8C1T":             "\x1b G",
		"cursor lower left": "\x1bF",
		"memory lock":       "\x1bl",
		"media copy":        "\x1b[5i",
		"DECTST":            "\x1b[4;1y",
		"XTSAVE":            "\x1b[?1049s",
		"XTRESTORE":         "\x1b[?1049r",
		"palette":           "\x1b]4;2;#00ff00\x07",
		"palette 2":         "\x1b]5;0;red\x1b\\",
		"kitty colours":     "\x1b]21;foreground=red\x1b\\",
		"iTerm2 image":      "\x1b]1337;File=inline=1:AAAA\x07",
		"sixel":             "\x1bPq#0;2;0;0;0~~~~\x1b\\",
		"soft font":         "\x1bP1;1;1{ @???\x1b\\",
		"kitty graphics":    "\x1b_Ga=T,f=100;AAAA\x1b\\",
		"PM":                "\x1b^private\x1b\\",
		"SOS":               "\x1bXstring\x1b\\",
		"malformed CSI":     "\x1b[1?h",
		"sub-param CUP":     "\x1b[99:1H",
	}
	for name, seq := range cases {
		f := newFilter(23)
		if got := string(f.Write([]byte("a" + seq + "b"))); got != "ab" {
			t.Errorf("%s: got %q", name, got)
		}
		if f.state != stGround {
			t.Errorf("%s: state %d after the sequence", name, f.state)
		}
	}
}

// TestFilterDropsQueries checks that every query the terminal would
// answer (as person input) is dropped: the broker's emulator answers them.
func TestFilterDropsQueries(t *testing.T) {
	cases := map[string]string{
		"DA1":            "\x1b[c",
		"DA1 0":          "\x1b[0c",
		"DA2":            "\x1b[>c",
		"DA3":            "\x1b[=c",
		"DSR":            "\x1b[5n",
		"CPR":            "\x1b[6n",
		"DECXCPR":        "\x1b[?6n",
		"colour scheme":  "\x1b[?996n",
		"DECRQM ANSI":    "\x1b[4$p",
		"DECRQM DEC":     "\x1b[?2026$p",
		"kitty keyboard": "\x1b[?u",
		"XTVERSION":      "\x1b[>0q",
		"XTWINOPS size":  "\x1b[14t",
		"XTWINOPS title": "\x1b[21t",
		"DECREQTPARM":    "\x1b[0x",
		"XTQMODKEYS":     "\x1b[?4m",
		"XTSMGRAPHICS":   "\x1b[?1;1;0S",
		"DECRQPSR":       "\x1b[1$w",
		"DECRQCRA":       "\x1b[1;1;1;1;24;80*y",
		"DECRQSS":        "\x1bP$qm\x1b\\",
		"XTGETTCAP":      "\x1bP+q544e\x1b\\",
		"OSC 10 query":   "\x1b]10;?\x07",
		"OSC 11 query":   "\x1b]11;?\x1b\\",
		"OSC 10 set+q":   "\x1b]10;red;?\x07",
		"OSC 4 query":    "\x1b]4;1;?\x07",
		"OSC 52 query":   "\x1b]52;c;?\x07",
		"OSC 52 write":   "\x1b]52;c;HXk=\x07",
		"OSC 50 font":    "\x1b]50;?\x07",
		"OSC 99":         "\x1b]99;p=?;\x1b\\",
		"ENQ":            "\x05",
		"DECID":          "\x1bZ",
		"in-band resize": "\x1b[?2048h",
		"palette notify": "\x1b[?2031h",
		"8-bit DA1":      "\x9bc",
	}
	for name, seq := range cases {
		f := newFilter(23)
		if got := string(f.Write([]byte("a" + seq + "b"))); got != "ab" {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

func TestFilterKeeps(t *testing.T) {
	cases := map[string]string{
		"title BEL":       "\x1b]0;title\x07",
		"title ST":        "\x1b]2;title\x1b\\",
		"hyperlink":       "\x1b]8;;https://example.org\x1b\\x\x1b]8;;\x1b\\",
		"shell mark":      "\x1b]133;A\x07",
		"default fg set":  "\x1b]10;#ffffff\x07",
		"palette reset":   "\x1b]104\x07",
		"cursor style":    "\x1b[2 q",
		"kitty push":      "\x1b[>1u",
		"kitty pop":       "\x1b[<u",
		"modify keys":     "\x1b[>4;2m",
		"mouse":           "\x1b[?1000;1006h",
		"cursor hide":     "\x1b[?25l",
		"sgr":             "\x1b[1;38;5;196m",
		"erase line":      "\x1b[2K",
		"save cursor":     "\x1b[s",
		"decsc":           "\x1b7",
		"line drawing":    "\x1b(0qqq\x1b(B",
		"double width":    "\x1b#6",
		"wide char":       "\xe4\xbd\xa0",
		"0x9b in UTF-8":   "\xe2\x9b\x94",
		"insert mode":     "\x1b[4h",
		"cursor up":       "\x1b[5A",
		"scroll up":       "\x1b[3S",
		"insert line":     "\x1b[2L",
		"tab clear":       "\x1b[3g",
		"focus reporting": "\x1b[?1004h",
	}
	for name, seq := range cases {
		f := newFilter(23)
		if got := string(f.Write([]byte(seq))); got != seq {
			t.Errorf("%s: got %q want %q", name, got, seq)
		}
	}
}

func TestFilterSplitAcrossWrites(t *testing.T) {
	for _, seq := range []string{
		"\x1b]52;c;SGVsbG8gd29ybGQ=\x07",
		"\x1bP+q544e\x1b\\",
		"\x1b[6n",
		"\x1b]11;?\x1b\\",
		"\x1b#8",
	} {
		for cut := 1; cut < len(seq); cut++ {
			f := newFilter(23)
			got := string(f.Write([]byte("a"+seq[:cut]))) + string(f.Write([]byte(seq[cut:]+"b")))
			if got != "ab" {
				t.Errorf("%q cut at %d: %q", seq, cut, got)
			}
		}
	}
	f := newFilter(23)
	got := string(f.Write([]byte("\x1b]0;ti"))) + string(f.Write([]byte("tle\x07x")))
	if got != "\x1b]0;title\x07x" {
		t.Errorf("split title: %q", got)
	}
}

// TestFilterParserBypasses covers inputs where a naive parser and the
// terminal disagree, which would let a sequence reach the status row.
func TestFilterParserBypasses(t *testing.T) {
	cases := map[string]string{
		// ESC inside a CSI starts a new sequence.
		"\x1b[1\x1b[99;1H": "\x1b[23;1H",
		// A number too large for an int is clamped, not passed as is.
		"\x1b[99999999999999999999;1H": "\x1b[23;1H",
		"\x1b[99999999999999999999d":   "\x1b[23d",
		// CAN aborts a CSI; the rest is text.
		"\x1b[99\x18;1H": ";1H",
		// C0 controls inside a CSI are executed.
		"\x1b[2\r0H": "\r\x1b[20;1H",
		// ESC ends an OSC; what follows is a real sequence.
		"\x1b]52;c;\x1b[99;1H": "\x1b[23;1H",
		// A lone C1 control is dropped; what follows is text, as for a
		// UTF-8 terminal.
		"\x90q\x9c":   "q",
		"\x9d0;x\x9c": "0;x",
		// tmux passthrough: the DCS is dropped, the doubled ESC ends it in
		// the filter as in the terminal, and the inner CUP is clamped.
		"\x1bPtmux;\x1b\x1b[99;1H\x1b\\": "\x1b[23;1H\x1b\\",
		// Leading zeros and empty parameters.
		"\x1b[;5H":  "\x1b[1;5H",
		"\x1b[024H": "\x1b[23;1H",
	}
	for in, want := range cases {
		f := newFilter(23)
		if got := string(f.Write([]byte(in))); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	// An overlong CSI is dropped up to its final byte, so its tail is not
	// read as text by the filter and as a sequence by the terminal.
	f := newFilter(23)
	long := "\x1b[" + strings.Repeat("1;", 200) + "99;1H" + "x"
	if got := string(f.Write([]byte(long))); got != "x" {
		t.Errorf("overlong CSI: %q", got)
	}
}

func TestFilterModes(t *testing.T) {
	f := newFilter(23)
	if got := string(f.Write([]byte("\x1b[?1;69;25h"))); got != "\x1b[?1;25h" {
		t.Errorf("DECLRMM in a list: %q", got)
	}
	if got := string(f.Write([]byte("\x1b[?1049:1;25l"))); got != "\x1b[?25l" {
		t.Errorf("sub-parameter mode: %q", got)
	}
	if got := string(f.Write([]byte("\x1b[?69l"))); got != "\x1b[?69l" {
		t.Errorf("DECLRMM off: %q", got)
	}
	if got := string(f.Write([]byte("\x1b[?2004h"))); got != "" || !f.paste {
		t.Errorf("bracketed paste on: %q paste %v", got, f.paste)
	}
	if got := string(f.Write([]byte("\x1b[?2004;1l"))); got != "\x1b[?1l" || f.paste {
		t.Errorf("bracketed paste off: %q paste %v", got, f.paste)
	}
	if got := string(f.Write([]byte("\x1b[2;4;12h"))); got != "\x1b[4h" || !f.insert {
		t.Errorf("ANSI modes: %q insert %v", got, f.insert)
	}
	f.Write([]byte("\x1b[?6h\x1b(0\x0e"))
	if !f.origin || string(f.g0) != "\x1b(0" || f.shift != 1 {
		t.Errorf("tracking: origin %v g0 %q shift %d", f.origin, f.g0, f.shift)
	}
	f.Write([]byte("\x1bc"))
	if f.origin || f.g0 != nil || f.shift != 0 || f.insert {
		t.Error("RIS did not reset the tracked state")
	}
}

func TestFilterAbort(t *testing.T) {
	f := newFilter(23)
	f.Write([]byte("\x1b]0;never ends"))
	if f.idle() {
		t.Fatal("idle inside a passed OSC")
	}
	if got := string(f.abort()); got != "\x18" {
		t.Fatalf("abort: %q", got)
	}
	if !f.idle() {
		t.Fatal("not idle after abort")
	}
	if got := string(f.Write([]byte("x\x07"))); got != "x\x07" {
		t.Fatalf("after abort: %q", got)
	}
	f.Write([]byte("\xe4"))
	if f.idle() {
		t.Fatal("idle after a lone UTF-8 lead byte")
	}
	f.abort()
	if !f.idle() || f.utf8Need != 0 {
		t.Fatal("UTF-8 state not reset by abort")
	}
	f.Write([]byte("\x1b[?2026h"))
	if f.idle() {
		t.Fatal("idle inside a synchronized frame")
	}
	if got := string(f.abort()); got != "\x18\x1b[?2026l" {
		t.Fatalf("abort in a frame: %q", got)
	}
	// Sequences the filter is still collecting have not reached the
	// terminal: the status line may be drawn.
	f.Write([]byte("\x1b[12;"))
	if !f.idle() {
		t.Fatal("not idle while collecting a CSI")
	}
	f.Write([]byte("\x1b]52;c;AAAA"))
	if !f.idle() {
		t.Fatal("not idle inside a dropped OSC")
	}
}

func TestFilterTouched(t *testing.T) {
	f := newFilter(23)
	f.Write([]byte("text"))
	if f.takeTouched() {
		t.Error("touched by plain text")
	}
	f.Write([]byte("\x1b[2J"))
	if !f.takeTouched() || f.takeTouched() {
		t.Error("ED 2 must touch once")
	}
	f.Write([]byte("\x1b[1J"))
	if f.takeTouched() {
		t.Error("ED 1 does not reach the status row")
	}
	f.Write([]byte("\x1b[?1049h"))
	if !f.takeTouched() {
		t.Error("buffer switch must touch")
	}
	// Margins above the last session row: the cursor can sit below the
	// region, where moves stop only at the screen's last row.
	f.Write([]byte("\x1b[1;10r"))
	if !f.takeTouched() || !f.takeTouched() {
		t.Error("partial margins must keep touching")
	}
	if got := string(f.curMargins()); got != "\x1b[1;10r" {
		t.Errorf("current margins %q", got)
	}
	f.Write([]byte("\x1b[r"))
	if f.takeTouched() {
		t.Error("full margins do not touch")
	}
}

func TestStatusDrawResetsAndRestores(t *testing.T) {
	f := newFilter(23)
	f.Write([]byte("\x1b[5;20r\x1b[?6h\x1b[4h\x1b)0\x1b(0\x0e\x1b[31m"))
	got := string(statusDraw(f, "LINE", 24, 4, 9, true))
	want := "\x1b[?25l\x1b(B\x0f\x1b[4l\x1b[?6l\x1b[0m\x1b[24;1HLINE" +
		"\x1b[5;20r\x1b[?6h\x1b(0\x0e\x1b[4h\x1b[?2004h\x1b[0m\x1b[31m\x1b[6;5H\x1b[?25h"
	if got != want {
		t.Errorf("draw:\n got %q\nwant %q", got, want)
	}
	plain := string(statusDraw(newFilter(23), "L", 24, 0, 0, false))
	if plain != "\x1b[?25l\x1b(B\x0f\x1b[4l\x1b[0m\x1b[24;1HL\x1b[1;23r\x1b[?2004h\x1b[0m\x1b[1;1H" {
		t.Errorf("plain draw: %q", plain)
	}
}

func TestStatusAttachRequestFirstAndOldest(t *testing.T) {
	st := proto.Status{State: proto.State{Shared: true, Agents: 1, Assurance: "weak",
		SecretInput: proto.SecretActive, SecretProgram: &proto.Program{Name: "sudo", Trust: proto.TrustSystem}},
		PendingAttach: []proto.AttachRequest{
			{ID: 9, PID: 900, Exe: "/usr/bin/" + strings.Repeat("x", 300), TTY: "pts/9"},
			{ID: 3, PID: 300, Exe: "/usr/bin/cotty", TTY: "pts/3"},
			{ID: 5, PID: 500, Exe: "/usr/bin/cotty", TTY: "pts/5"},
		}}
	segs := statusSegments(st, uiState{session: "w", now: time.Now()})
	if !strings.Contains(segs[0].text, "pid 300") || !strings.Contains(segs[0].text, "+2 more") {
		t.Fatalf("first segment must be the oldest request: %q", segs[0].text)
	}
	if r, _ := oldestRequest(st.PendingAttach); r.ID != 3 {
		t.Fatalf("oldest %d", r.ID)
	}
	// A long executable name of a newer request cannot push the lock out.
	line := stripSGR(renderStatus(segs, 120))
	if !strings.Contains(line, "LOCK sudo") {
		t.Fatalf("lock pushed out: %q", line)
	}
}

func TestStatusWidthInCells(t *testing.T) {
	st := proto.Status{State: proto.State{Shared: true, Agents: 1, Assurance: "weak",
		SecretInput: proto.SecretActive,
		SecretProgram: &proto.Program{Name: "‮​‍́" + strings.Repeat("你", 30),
			Trust: proto.TrustOther}}}
	for _, w := range []int{10, 21, 40, 80} {
		line := stripSGR(renderStatus(statusSegments(st, uiState{session: "w"}), w))
		if n := cells(line); n != w {
			t.Errorf("width %d: %d cells: %q", w, n, line)
		}
		for _, r := range "‮​‍́" {
			if strings.ContainsRune(line, r) {
				t.Errorf("width %d: zero-width or format character %U kept", w, r)
			}
		}
	}
}

// pipeClient returns a client whose session input is collected.
func pipeClient(t *testing.T) (*client, func() []byte) {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	got := make(chan []byte, 64)
	go func() {
		for {
			fr, err := proto.ReadFrame(c2)
			if err != nil {
				close(got)
				return
			}
			if fr.Type == proto.FrameData {
				got <- fr.Payload
			}
		}
	}()
	a := &client{cl: proto.NewClient(c1), filter: newFilter(23), msgs: make(chan string, 8)}
	collect := func() []byte {
		var all []byte
		for {
			select {
			case p := <-got:
				all = append(all, p...)
			case <-time.After(50 * time.Millisecond):
				return all
			}
		}
	}
	return a, collect
}

func TestInputPrefixIgnoredInPaste(t *testing.T) {
	a, sent := pipeClient(t)
	a.filter.paste = true
	now := time.Now()
	a.input([]byte("\x1b[200~ab\x1dyc\x1b[201~"), now)
	if got := sent(); string(got) != "\x1b[200~ab\x1dyc\x1b[201~" {
		t.Fatalf("paste forwarded %q", got)
	}
	if a.in.prefix || a.ui.message != "" {
		t.Fatal("prefix taken inside a paste")
	}
	// Markers split across reads.
	a.input([]byte("\x1b[20"), now)
	a.input([]byte("0~x\x1d?"), now)
	a.input([]byte("\x1b[2"), now)
	a.input([]byte("01~"), now)
	if got := sent(); string(got) != "\x1b[200~x\x1d?\x1b[201~" {
		t.Fatalf("split paste forwarded %q", got)
	}
	if a.ui.message != "" {
		t.Fatal("hotkey ran inside a split paste")
	}
	// After the paste the prefix works again.
	a.input([]byte("\x1d?"), now)
	if a.ui.message == "" || len(sent()) != 0 {
		t.Fatal("prefix not honoured after the paste")
	}
}

func TestInputPasteTimeoutAndStrip(t *testing.T) {
	a, sent := pipeClient(t)
	now := time.Now()
	// The program did not ask for bracketed paste: markers are stripped.
	a.input([]byte("\x1b[200~hi\x1b[201~"), now)
	if got := sent(); string(got) != "hi" {
		t.Fatalf("markers not stripped: %q", got)
	}
	// A paste whose end marker never comes stops shielding the prefix.
	a.input([]byte("\x1b[200~text"), now)
	sent()
	a.input([]byte("\x1d?"), now.Add(time.Second))
	if a.ui.message == "" {
		t.Fatal("unterminated paste kept the hotkeys off")
	}
}

func TestInputWiped(t *testing.T) {
	a, sent := pipeClient(t)
	p := []byte("pass\x1d?word")
	a.input(p, time.Now())
	if got := sent(); string(got) != "password" {
		t.Fatalf("forwarded %q", got)
	}
	if !bytes.Equal(p, make([]byte, len(p))) {
		t.Errorf("input buffer not wiped: %q", p)
	}
	if a.in.tail != [6]byte{} {
		t.Errorf("tail keeps keystrokes: %q", a.in.tail)
	}
	a.input([]byte("ab\x1b[2"), time.Now())
	sent()
	if string(a.in.tail[3:]) != "\x1b[2" || !bytes.Equal(a.in.tail[:3], []byte{0, 0, 0}) {
		t.Errorf("tail must keep only a marker prefix: %q", a.in.tail)
	}
}

// TestForcedRedraw checks that output that never leaves a sequence delays
// the status line by at most forceRedraw, then is cancelled with CAN.
func TestForcedRedraw(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	a := &client{opts: Options{Out: w}, rows: 24, cols: 40, filter: newFilter(23), session: "s",
		status: proto.Status{State: proto.State{SecretInput: proto.SecretActive,
			SecretProgram: &proto.Program{Name: "sudo", Trust: proto.TrustSystem}, Assurance: "weak"}}}
	a.emu = newLocalEmu(40, 23)
	a.output([]byte("\x1b]0;never terminated"))
	t0 := time.Now()
	if !a.redraw(t0) || !a.redraw(t0.Add(50*time.Millisecond)) {
		t.Fatal("drew inside the program's OSC")
	}
	if a.redraw(t0.Add(forceRedraw + time.Millisecond)) {
		t.Fatal("still waiting after forceRedraw")
	}
	_ = w.Close()
	out, _ := io.ReadAll(r)
	i := bytes.IndexByte(out, 0x18)
	j := bytes.Index(out, []byte("LOCK sudo"))
	if i < 0 || j < i {
		t.Fatalf("no CAN before the status line: %q", out)
	}
	if !a.filter.idle() || !a.busySince.IsZero() {
		t.Fatal("state not reset after the forced draw")
	}
}

// TestFilterUTF8C1 (review N12): C1 controls encoded in UTF-8 (U+0080 to
// U+009F) are handled as the terminal decodes them: string introducers
// are dropped, an 8-bit CSI is filtered like ESC [, and one inside a
// passed title ends it, so what follows is filtered as ground output.
// Ordinary characters with a C2 lead byte pass, also split across writes.
func TestFilterUTF8C1(t *testing.T) {
	for name, in := range map[string]string{
		"utf8 osc 52":     "\xc2\x9d52;c;ZXZpbA==\xc2\x9c",
		"utf8 dcs":        "\xc2\x90@kitty-cmd{}\xc2\x9c",
		"utf8 csi DECERA": "\xc2\x9b1;1;24;80$z",
	} {
		f := newFilter(23)
		got := string(f.Write([]byte("a" + in + "b")))
		if strings.Contains(got, "\xc2\x9d") || strings.Contains(got, "\xc2\x90") || strings.Contains(got, "\xc2\x9b") ||
			strings.Contains(got, "$z") || strings.Contains(got, "\x1b]52") {
			t.Errorf("%s: got %q", name, got)
		}
	}
	// A UTF-8 ST inside a passed title ends it; the DECALN after it is
	// filtered as ground output, not passed as title text.
	f := newFilter(23)
	got := string(f.Write([]byte("\x1b]0;title\xc2\x9c\x1b#8b")))
	if strings.Contains(got, "\x1b#8") || f.state != stGround {
		t.Errorf("utf8 st in a title: %q state %d", got, f.state)
	}
	for _, in := range []string{"price ¢5 £3 ©", "\x1b]2;© title\x07"} {
		f := newFilter(23)
		var got []byte
		for i := range len(in) {
			got = append(got, f.Write([]byte(in[i:i+1]))...)
		}
		if string(got) != in {
			t.Errorf("%q: got %q", in, got)
		}
	}
}

// TestStatusAttachRequestParents (review A3): every attach runs cotty, so
// the request names the requester's first two parents, cleaned of
// control characters.
func TestStatusAttachRequestParents(t *testing.T) {
	st := proto.Status{PendingAttach: []proto.AttachRequest{
		{ID: 1, PID: 300, Exe: "/usr/bin/cotty", TTY: "pts/3", Chain: []string{"299 script", "250 bash\x1b[2J", "1 systemd"}},
	}}
	segs := statusSegments(st, uiState{session: "w", now: time.Now()})
	if !strings.Contains(segs[0].text, "via script < bash[2J") || strings.Contains(segs[0].text, "\x1b") || strings.Contains(segs[0].text, "systemd") {
		t.Fatalf("attach request: %q", segs[0].text)
	}
}
