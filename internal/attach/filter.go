package attach

import (
	"bytes"
	"strconv"
	"strings"
)

// filter passes the session's output through to the person's terminal,
// keeping the last row for cotty's status line. The session's PTY is one
// row shorter than the terminal; the filter makes sure the program cannot
// reach, paint or freeze the status row, and cannot make the person's
// terminal answer queries (the answers would arrive as person input):
//
//   - scroll margins (DECSTBM) are clamped to the session rows, and a reset
//     of the margins becomes "rows 1 to N-1";
//   - absolute row moves (CUP, HVP, VPA) are re-emitted in canonical form,
//     clamped to the session rows;
//   - full reset (RIS), soft reset (DECSTR) and screen buffer switches are
//     followed by the margins again;
//   - sequences that paint or copy rectangles, fill the screen, resize or
//     reconfigure the terminal, change the palette, switch the character
//     encoding, lock the keyboard or turn on local echo are dropped
//     (DECALN, DECCRA/DECFRA/DECERA/DECSERA/DECCARA and every other CSI with
//     a `$`, `*`, `'` or `#` intermediate, DECSLRM, window ops, DECCOLM,
//     DECSCNM, KAM, SRM, ESC %, OSC 4/5 ...);
//   - every query the terminal would answer is dropped (DA1/2/3, DSR, CPR,
//     DECRQM, DECRQSS, XTGETTCAP, XTVERSION, XTQMODKEYS, the kitty keyboard
//     query, colour queries, window reports, ENQ, DECID ...): the broker's
//     own emulator answers them for the session;
//   - OSC 52 (clipboard), DCS, APC, PM and SOS strings (graphics, tmux
//     passthrough, soft fonts) are dropped; only a small list of OSC
//     commands (titles, cwd, hyperlinks, notifications, shell marks, colour
//     resets and default colour sets) passes;
//   - bracketed paste stays on in the person's terminal (the client needs
//     the markers to ignore its hotkey inside pasted text); the program's
//     own choice is remembered in paste.
//
// It also tracks the state the status line draw has to reset and restore
// (SGR pen, G0 charset and locking shift, insert mode, origin mode, scroll
// margins, synchronized output), so the status line can be drawn without
// DECSC/DECRC (which would clobber the program's own saved cursor).
//
// The filter's parser follows the terminal's: ESC anywhere starts a new
// sequence, CAN and SUB abort one, C0 controls inside a sequence are
// executed. When the filter drops a sequence the terminal never sees any
// of it, so both stay in the ground state.
type filter struct {
	rows int // session rows (terminal rows minus the status line)

	state int
	seq   []byte // the escape sequence being collected

	// String (OSC, DCS, APC, PM, SOS) handling.
	strKind  byte // ']' OSC, 'P' DCS, '_' APC, '^' PM, 'X' SOS
	strMode  int
	strBuf   []byte // collected header or whole string, not yet emitted
	strEsc   bool   // the previous byte in the string was ESC
	strUtf8  int    // continuation bytes still expected inside a passed string
	utf8Need int    // continuation bytes still expected in ground state
	// c2 holds a C2 lead byte back (in ground or a string) until the next
	// byte says whether the pair encodes a C1 control (U+0080 to U+009F),
	// which a terminal in UTF-8 mode decodes as the control (review N12).
	c2 bool

	// Program state the status line draw resets and restores.
	sgr     [][]byte
	g0      []byte // the program's last G0 designation (ESC ( F), nil = ASCII
	shift   int    // locking shift into GL: 0 G0 (SI), 1 G1 (SO), 2 G2, 3 G3
	insert  bool   // IRM
	origin  bool   // DECOM
	sync    bool   // synchronized output (mode 2026)
	paste   bool   // the program asked for bracketed paste
	top     int    // scroll margins, session rows
	bottom  int
	touched bool // the status row may have been erased or painted
}

const (
	stGround = iota
	stEsc
	stCSI
	stIgnore // an overlong sequence, dropped up to its final byte
	stString // OSC, DCS, APC, PM, SOS: until BEL (OSC) or ST
)

// String modes.
const (
	strCollect = iota // OSC header (the command number) still being read
	strPass           // header emitted, the rest is streamed
	strBuffer         // whole string buffered, decided at its end
	strDrop           // nothing emitted, nothing will be
)

const (
	maxSeq       = 256
	maxOSCHeader = 8
	maxOSCBuffer = 1024
)

func newFilter(rows int) *filter { return &filter{rows: rows, top: 1, bottom: rows} }

// idle reports whether the person's terminal is between sequences and
// characters, so cotty may write its own bytes (the status line) without
// corrupting the program's output. Sequences the filter is still
// collecting have not reached the terminal, so they do not count; a
// passed string, a pending UTF-8 character and synchronized output do.
func (f *filter) idle() bool {
	return !(f.state == stString && f.strMode == strPass) && f.utf8Need == 0 && !f.sync
}

// abort returns the bytes that put the person's terminal back in the
// ground state when the program left it inside a sequence or a frame for
// too long (an unterminated OSC, a lone UTF-8 lead byte, synchronized
// output never ended), and resets the filter to match: CAN cancels any
// sequence in progress, and synchronized output is ended.
func (f *filter) abort() []byte {
	out := []byte{0x18}
	if f.sync {
		out = append(out, "\x1b[?2026l"...)
	}
	f.state = stGround
	f.seq = f.seq[:0]
	clear(f.strBuf)
	f.strBuf = f.strBuf[:0]
	f.strEsc = false
	f.strUtf8 = 0
	f.utf8Need = 0
	f.c2 = false
	f.sync = false
	return out
}

// takeTouched reports (and clears) whether the last output may have
// erased or painted the status row, so the client redraws it at once.
// Scroll margins that end above the last session row count: the cursor
// can then sit below the scroll region, where line feeds and downward
// moves stop only at the screen's last row.
func (f *filter) takeTouched() bool {
	t := f.touched || f.bottom < f.rows
	f.touched = false
	return t
}

// margins is the DECSTBM that keeps the status row out of scrolling, and
// resets the tracked margins to the full session.
func (f *filter) margins() []byte {
	f.top, f.bottom = 1, f.rows
	return f.curMargins()
}

// curMargins re-sends the program's current scroll margins.
func (f *filter) curMargins() []byte {
	top, bottom := clamp(f.top, 1, f.rows), clamp(f.bottom, 1, f.rows)
	if bottom <= top {
		top, bottom = 1, f.rows
	}
	return []byte("\x1b[" + strconv.Itoa(top) + ";" + strconv.Itoa(bottom) + "r")
}

// resize sets the session rows; the margins become the full session.
func (f *filter) resize(rows int) []byte {
	f.rows = rows
	return f.margins()
}

// Write filters p and returns the bytes to send to the terminal.
func (f *filter) Write(p []byte) []byte {
	out := make([]byte, 0, len(p)+16)
	for _, c := range p {
		out = f.step(c, out)
	}
	return out
}

// step feeds one byte through the parser.
func (f *filter) step(c byte, out []byte) []byte {
	if f.c2 {
		f.c2 = false
		if c >= 0x80 && c <= 0x9f {
			if f.state == stString {
				// Any C1 control ends a string for the terminal (ST, or the
				// start of another sequence): end it here too.
				return f.endString(out)
			}
			// In the ground state: as the raw C1 byte (8-bit CSI becomes
			// ESC [, the others are dropped).
			f.utf8Need = 0
			return f.ground(c, out)
		}
		// An ordinary two-byte character: let the held lead byte through.
		if f.state == stString {
			out = f.str(0xc2, out)
		} else {
			out = f.ground(0xc2, out)
		}
	}
	if c == 0xc2 && (f.state == stGround && f.utf8Need == 0 || f.state == stString && !f.strEsc && f.strUtf8 == 0) {
		f.c2 = true
		return out
	}
	switch f.state {
	case stGround:
		return f.ground(c, out)
	case stEsc:
		switch {
		case c == 0x1b:
			f.seq = append(f.seq[:0], c)
		case c == 0x18 || c == 0x1a:
			f.toGround()
		case c < 0x20:
			out = f.ctrl(c, out)
		case c == 0x7f:
		case c >= 0x80:
			// Not a valid escape sequence: the terminal never saw the ESC.
			f.toGround()
			return f.ground(c, out)
		case c == '[':
			f.seq = append(f.seq, c)
			f.state = stCSI
		case len(f.seq) == 1 && (c == ']' || c == 'P' || c == '_' || c == '^' || c == 'X'):
			f.startString(c)
		case c >= 0x20 && c <= 0x2f:
			f.seq = append(f.seq, c)
			if len(f.seq) > 8 {
				f.seq = f.seq[:0]
				f.state = stIgnore
			}
		default:
			f.seq = append(f.seq, c)
			out = append(out, f.esc(f.seq)...)
			f.toGround()
		}
	case stCSI, stIgnore:
		switch {
		case c == 0x1b:
			f.seq = append(f.seq[:0], c)
			f.state = stEsc
		case c == 0x18 || c == 0x1a:
			f.toGround()
		case c < 0x20:
			out = f.ctrl(c, out)
		case c == 0x7f:
		case c >= 0x80:
			f.toGround()
			return f.ground(c, out)
		case c >= 0x40 && c <= 0x7e:
			if f.state == stCSI {
				f.seq = append(f.seq, c)
				out = append(out, f.csi(f.seq)...)
			}
			f.toGround()
		default:
			if f.state == stCSI {
				f.seq = append(f.seq, c)
				if len(f.seq) > maxSeq {
					// Overlong: drop it whole, up to its final byte.
					f.seq = f.seq[:0]
					f.state = stIgnore
				}
			}
		}
	case stString:
		return f.str(c, out)
	}
	return out
}

func (f *filter) toGround() {
	f.state = stGround
	f.seq = f.seq[:0]
}

// ground handles a byte outside any sequence.
func (f *filter) ground(c byte, out []byte) []byte {
	switch {
	case c == 0x1b:
		f.utf8Need = 0
		f.state = stEsc
		f.seq = append(f.seq[:0], c)
		return out
	case c < 0x80:
		f.utf8Need = 0
		if c < 0x20 || c == 0x7f {
			return f.ctrl(c, out)
		}
		return append(out, c)
	case c < 0xc0:
		if f.utf8Need > 0 {
			f.utf8Need--
			return append(out, c)
		}
		if c == 0x9b {
			// 8-bit CSI: treat as ESC [.
			f.state = stCSI
			f.seq = append(f.seq[:0], 0x1b, '[')
			return out
		}
		if c < 0xa0 {
			// A lone C1 control (8-bit DCS, OSC, ST ...): dropped.
			return out
		}
		return append(out, c)
	case c >= 0xf8:
		f.utf8Need = 0
	case c >= 0xf0:
		f.utf8Need = 3
	case c >= 0xe0:
		f.utf8Need = 2
	default:
		f.utf8Need = 1
	}
	return append(out, c)
}

// ctrl handles a C0 control byte (executed in any state).
func (f *filter) ctrl(c byte, out []byte) []byte {
	switch c {
	case 0x05:
		// ENQ: the terminal would answer with its answerback string.
		return out
	case 0x0e:
		f.shift = 1
	case 0x0f:
		f.shift = 0
	}
	return append(out, c)
}

// esc rewrites one complete escape sequence (ESC intermediates final).
func (f *filter) esc(seq []byte) []byte {
	final := seq[len(seq)-1]
	inter := seq[1 : len(seq)-1]
	if len(inter) == 0 {
		switch final {
		case 'c':
			// RIS resets the margins, the pen, the modes and the charsets.
			f.resetState()
			f.touched = true
			return append(append([]byte(nil), seq...), f.margins()...)
		case 'n':
			f.shift = 2
		case 'o':
			f.shift = 3
		case '7', '8', 'D', 'E', 'H', 'M', 'N', 'O', '=', '>', '\\', '6', '9', 'V', 'W':
		default:
			// DECID (Z) answers; ESC F moves to the screen's lower left
			// corner; ESC l/m lock memory; the rest is unknown.
			return nil
		}
		return seq
	}
	switch inter[0] {
	case '#':
		if len(inter) == 1 && final >= '3' && final <= '6' {
			// Double height or width lines: only the cursor's row.
			return seq
		}
		// DECALN (ESC # 8) fills the whole screen, status row included.
		return nil
	case '(':
		f.g0 = append([]byte(nil), seq...)
		return seq
	case ')', '*', '+', '-', '.', '/':
		return seq
	}
	// ESC % (character encoding), ESC SP (C1 transmission, conformance) and
	// anything unknown.
	return nil
}

// resetState forgets the program state a full or soft reset clears.
func (f *filter) resetState() {
	f.sgr = nil
	f.g0 = nil
	f.shift = 0
	f.insert = false
	f.origin = false
	f.sync = false
}

// csi rewrites one complete CSI sequence (ESC [ params final).
func (f *filter) csi(seq []byte) []byte {
	final := seq[len(seq)-1]
	body := seq[2 : len(seq)-1]
	var prefix byte
	if len(body) > 0 && body[0] >= 0x3c && body[0] <= 0x3f {
		prefix, body = body[0], body[1:]
	}
	i := bytes.IndexFunc(body, func(r rune) bool { return r >= 0x20 && r <= 0x2f })
	params, inter := string(body), ""
	if i >= 0 {
		params, inter = string(body[:i]), string(body[i:])
		if strings.IndexFunc(inter, func(r rune) bool { return r < 0x20 || r > 0x2f }) >= 0 {
			return nil // parameter bytes after an intermediate: malformed
		}
	}
	if strings.ContainsAny(params, "<=>?") {
		return nil // a private marker in the middle: malformed
	}
	if inter != "" {
		if prefix != 0 {
			return nil
		}
		switch inter + string(final) {
		case " q", " @", " A", "\"q":
			// DECSCUSR, SL, SR, DECSCA.
			return seq
		case "!p":
			// DECSTR soft reset: margins, pen, modes and charsets are reset.
			f.resetState()
			return append(append([]byte(nil), seq...), f.margins()...)
		}
		// `$` (rectangle copy/fill/erase/attributes, DECRQM, DECSCPP,
		// status display), `*` (DECRQCRA, DECSNLS, DECSACE), `'`
		// (locator, column ops), `"` (DECSCL, DECRQDE), `#` (SGR stack
		// reports, checksums), `+` (DECSR) and the rest.
		return nil
	}
	switch prefix {
	case 0:
		return f.csiPlain(seq, params, final)
	case '?':
		switch final {
		case 'h', 'l':
			return f.privateModes(params, final)
		case 'J':
			if params != "1" {
				f.touched = true
			}
			return seq
		case 'K', 'W':
			return seq
		}
		// DECXCPR and DSR (n), kitty keyboard query (u), XTSMGRAPHICS (S),
		// XTQMODKEYS (m), XTSAVE/XTRESTORE (s/r) and the rest.
		return nil
	case '>':
		switch final {
		case 'm', 'n', 'p', 'u', 'f':
			// XTMODKEYS, XTSMPOINTER, kitty keyboard push, XTFMTKEYS.
			return seq
		}
		// DA2 (c), XTVERSION (q), title modes (t/T) and the rest.
		return nil
	case '<', '=':
		if final == 'u' {
			// Kitty keyboard pop and set.
			return seq
		}
		// DA3 (= c) and the rest.
		return nil
	}
	return nil
}

// csiPlain handles a CSI sequence without a private marker or
// intermediates.
func (f *filter) csiPlain(seq []byte, params string, final byte) []byte {
	switch final {
	case 'r':
		nums, ok := numParams(params)
		if !ok {
			return nil
		}
		top, bottom := param(nums, 0, 1), param(nums, 1, f.rows)
		f.top, f.bottom = clamp(top, 1, f.rows), clamp(bottom, 1, f.rows)
		if f.bottom <= f.top {
			f.top, f.bottom = 1, f.rows
		}
		return f.curMargins()
	case 'H', 'f':
		nums, ok := numParams(params)
		if !ok || len(nums) > 2 {
			return nil
		}
		row, col := clamp(param(nums, 0, 1), 1, f.rows), param(nums, 1, 1)
		return []byte("\x1b[" + strconv.Itoa(row) + ";" + strconv.Itoa(col) + string(final))
	case 'd':
		nums, ok := numParams(params)
		if !ok || len(nums) > 1 {
			return nil
		}
		return []byte("\x1b[" + strconv.Itoa(clamp(param(nums, 0, 1), 1, f.rows)) + "d")
	case 'm':
		if params == "" || params == "0" {
			f.sgr = nil
		} else {
			f.sgr = append(f.sgr, append([]byte(nil), seq...))
			if len(f.sgr) > 16 {
				f.sgr = f.sgr[len(f.sgr)-16:]
			}
		}
		return seq
	case 'h', 'l':
		return f.ansiModes(params, final)
	case 'J':
		if params != "1" {
			// ED 0, 2 and 3 erase the status row too.
			f.touched = true
		}
		return seq
	case 's':
		if strings.Contains(params, ";") {
			// DECSLRM (left and right margins).
			return nil
		}
		return seq
	case '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'I', 'K', 'L', 'M', 'P', 'S', 'T',
		'X', 'Z', '`', 'a', 'b', 'e', 'g', 'u':
		return seq
	}
	// DA1 (c), DSR/CPR (n), window ops and reports (t), DECREQTPARM (x),
	// media copy (i), DECTST (y) and the rest.
	return nil
}

// ansiModes keeps the ANSI modes a program may set: IRM (4, tracked) and
// LNM (20). KAM (2) would lock the person's keyboard and SRM (12) would
// turn on local echo; the rest has no use here.
func (f *filter) ansiModes(params string, final byte) []byte {
	var keep []string
	for _, m := range strings.Split(params, ";") {
		switch m {
		case "4":
			f.insert = final == 'h'
			keep = append(keep, m)
		case "20":
			keep = append(keep, m)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	return []byte("\x1b[" + strings.Join(keep, ";") + string(final))
}

// privateModes rewrites a DEC private mode set or reset.
func (f *filter) privateModes(params string, final byte) []byte {
	set := final == 'h'
	var keep []string
	margins := false
	for _, m := range strings.Split(params, ";") {
		if _, ok := numParams(m); !ok {
			// Sub-parameters or junk: the terminal might read a mode
			// number the filter did not see.
			continue
		}
		switch m {
		case "", "3", "5":
			// DECCOLM clears the screen and resizes it; DECSCNM reverses
			// the whole screen, status line colours included.
			continue
		case "69", "2048", "2031":
			// DECLRMM (left/right margins); in-band resize and palette
			// change notifications, which the terminal would send as
			// person input.
			if set {
				continue
			}
		case "2004":
			// Bracketed paste stays on in the person's terminal.
			f.paste = set
			continue
		case "6":
			f.origin = set
		case "2026":
			f.sync = set
		case "1049", "47", "1047":
			margins = true
			f.touched = true
		}
		keep = append(keep, m)
	}
	var out []byte
	if len(keep) > 0 {
		out = []byte("\x1b[?" + strings.Join(keep, ";") + string(final))
	}
	if margins {
		out = append(out, f.margins()...)
	}
	return out
}

// startString begins an OSC, DCS, APC, PM or SOS string.
func (f *filter) startString(kind byte) {
	f.state = stString
	f.strKind = kind
	f.strEsc = false
	f.strUtf8 = 0
	f.strBuf = append(f.strBuf[:0], 0x1b, kind)
	f.strMode = strDrop
	if kind == ']' {
		f.strMode = strCollect
	}
	f.seq = f.seq[:0]
}

// str handles a byte inside a string.
func (f *filter) str(c byte, out []byte) []byte {
	if f.strEsc {
		f.strEsc = false
		out = f.endString(out)
		if c == '\\' {
			return out
		}
		// ESC starts a new sequence: the string ended without ST.
		f.state = stEsc
		f.seq = append(f.seq[:0], 0x1b)
		return f.step(c, out)
	}
	switch {
	case c == 0x1b:
		f.strEsc = true
		return out
	case c == 0x18 || c == 0x1a:
		// CAN and SUB abort the string.
		if f.strMode == strPass {
			out = append(out, c)
		}
		f.dropString()
		return out
	case c == 0x07 && f.strKind == ']':
		return f.endString(out, c)
	case c == 0x9c && f.strUtf8 == 0:
		// 8-bit ST.
		return f.endString(out)
	}
	switch {
	case c >= 0xf8:
		f.strUtf8 = 0
	case c >= 0xf0:
		f.strUtf8 = 3
	case c >= 0xe0:
		f.strUtf8 = 2
	case c >= 0xc0:
		f.strUtf8 = 1
	case c >= 0x80 && f.strUtf8 > 0:
		f.strUtf8--
	default:
		f.strUtf8 = 0
	}
	switch f.strMode {
	case strPass:
		out = append(out, c)
	case strCollect:
		f.strBuf = append(f.strBuf, c)
		if c == ';' {
			out = f.decideOSC(out, false)
		} else if len(f.strBuf) > 2+maxOSCHeader {
			clear(f.strBuf)
			f.strBuf = f.strBuf[:0]
			f.strMode = strDrop
		}
	case strBuffer:
		f.strBuf = append(f.strBuf, c)
		if len(f.strBuf) > maxOSCBuffer {
			clear(f.strBuf)
			f.strBuf = f.strBuf[:0]
			f.strMode = strDrop
		}
	}
	return out
}

// endString finishes the current string (terminated by BEL, ST, or an ESC
// that starts something else) and returns to the ground state. A passed
// string ends with term, ST by default.
func (f *filter) endString(out []byte, term ...byte) []byte {
	if len(term) == 0 {
		term = []byte{0x1b, '\\'}
	}
	switch f.strMode {
	case strPass:
		out = append(out, term...)
	case strCollect:
		out = f.decideOSC(out, true)
		if f.strMode == strPass {
			out = append(out, term...)
		}
	case strBuffer:
		if !oscQuery(f.strBuf) {
			out = append(out, f.strBuf...)
			out = append(out, term...)
		}
	}
	f.dropString()
	return out
}

// dropString forgets the string and returns to the ground state.
func (f *filter) dropString() {
	clear(f.strBuf)
	f.strBuf = f.strBuf[:0]
	f.strEsc = false
	f.strUtf8 = 0
	f.state = stGround
}

// decideOSC chooses what happens to an OSC once its command number is
// known (at the first ';' or at its end).
func (f *filter) decideOSC(out []byte, ended bool) []byte {
	num := string(f.strBuf[2:])
	num = strings.TrimSuffix(num, ";")
	switch num {
	case "0", "1", "2", "7", "8", "9", "104", "105", "110", "111", "112", "113", "114",
		"115", "116", "117", "118", "119", "133", "633", "777":
		// Titles, working directory, hyperlinks, notifications, colour
		// resets, shell integration marks: streamed.
		out = append(out, f.strBuf...)
		clear(f.strBuf)
		f.strBuf = f.strBuf[:0]
		f.strMode = strPass
	case "10", "11", "12", "13", "14", "15", "16", "17", "18", "19":
		// Default colours: buffered, passed unless one of the values is
		// a query. Without a value (the string ended here) it is dropped.
		f.strMode = strBuffer
		if ended {
			clear(f.strBuf)
			f.strBuf = f.strBuf[:0]
			f.strMode = strDrop
		}
	default:
		// Palette changes (4, 5), clipboard (52), fonts (50), images
		// (1337), kitty colour and notification protocols (21, 99) and
		// anything unknown: dropped.
		clear(f.strBuf)
		f.strBuf = f.strBuf[:0]
		f.strMode = strDrop
	}
	return out
}

// oscQuery reports whether a buffered OSC asks the terminal for a value.
func oscQuery(s []byte) bool {
	for _, field := range bytes.Split(s[2:], []byte{';'}) {
		if bytes.Equal(bytes.TrimSpace(field), []byte("?")) {
			return true
		}
	}
	return false
}

// pen returns the sequence that restores the program's SGR state.
func (f *filter) pen() []byte {
	out := []byte("\x1b[0m")
	for _, s := range f.sgr {
		out = append(out, s...)
	}
	return out
}

// numParams parses a parameter string made only of digits and ';'.
// Sub-parameters, private markers or anything else make it invalid, so a
// sequence the terminal would parse differently is never passed on.
func numParams(s string) ([]int, bool) {
	if s == "" {
		return nil, true
	}
	parts := strings.Split(s, ";")
	nums := make([]int, len(parts))
	for i, p := range parts {
		if p == "" {
			continue
		}
		if strings.IndexFunc(p, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return nil, false
		}
		if len(p) > 9 {
			nums[i] = 1 << 30 // huge but valid: the caller clamps it
			continue
		}
		nums[i], _ = strconv.Atoi(p)
	}
	return nums, true
}

// param returns the i-th parameter, or d when it is missing or zero.
func param(nums []int, i, d int) int {
	if i >= len(nums) || nums[i] == 0 {
		return d
	}
	return nums[i]
}

func clamp(v, lo, hi int) int {
	return max(lo, min(v, hi))
}
