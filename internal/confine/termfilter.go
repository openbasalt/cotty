package confine

// The agent's output reaches the person's terminal emulator through the
// pty relay. Escape sequences there are a channel to the emulator, not to
// the person: OSC 52 writes (and on some emulators reads) the clipboard,
// kitty's remote control (DCS @kitty-cmd) and file transfer (OSC 5113),
// iTerm2's file transfer (OSC 1337), graphics and other APC, PM and SOS
// strings act on the person's desktop. The filter passes text, C0
// controls, CSI and two-byte ESC sequences, and only a small set of OSC
// commands (window title, current directory, hyperlinks, prompt marks);
// every other OSC, DCS, APC, PM and SOS string is dropped whole, and C1
// controls are dropped in both forms: the raw byte (0x80 to 0x9f) and its
// UTF-8 encoding (C2 80 to C2 9F, which terminals in UTF-8 mode decode as
// the control, review N12). State is kept across reads, so a sequence
// split over several reads is handled like one in a single read.

import (
	"bytes"
	"io"
)

// allowedOSC are the OSC commands passed through: 0, 1, 2 (titles), 7
// (current directory), 8 (hyperlinks), 133 (prompt marks).
var allowedOSC = map[string]bool{"0": true, "1": true, "2": true, "7": true, "8": true, "133": true}

// maxOSC bounds an allowed OSC string; longer ones are dropped.
const maxOSC = 8192

type tfState int

const (
	tfGround   tfState = iota
	tfEsc              // after ESC
	tfEscInter         // ESC followed by intermediate bytes (ESC ( B ...)
	tfCSI              // inside CSI, passing through
	tfOSC              // inside an OSC string, buffering
	tfDrop             // inside a string being dropped (OSC, DCS, APC, PM, SOS)
	tfStrEsc           // ESC inside a string: ST or the start of a new sequence
)

// TermFilter removes dangerous terminal control strings from a stream.
type TermFilter struct {
	st      tfState
	inStr   tfState // tfOSC or tfDrop, while in tfStrEsc
	osc     []byte  // the OSC being buffered (without ESC ] and terminator)
	utf8    int     // continuation bytes still expected
	c2      bool    // a C2 lead byte is held: the next byte says whether it encodes a C1 control
	dropped int     // number of sequences dropped, for tests and logs
}

// Dropped returns how many control strings the filter dropped.
func (f *TermFilter) Dropped() int { return f.dropped }

// Filter appends the safe part of p to out and returns it.
func (f *TermFilter) Filter(out, p []byte) []byte {
	for _, c := range p {
		out = f.byte(out, c)
	}
	return out
}

func (f *TermFilter) byte(out []byte, c byte) []byte {
	if f.c2 {
		// U+0080 to U+009F encoded in UTF-8: a C1 control, dropped like the
		// raw byte (and so is an OSC it would end or start).
		f.c2 = false
		if c >= 0x80 && c <= 0x9f {
			switch f.st {
			case tfGround:
				return f.c1(out, c)
			case tfOSC:
				f.st = tfDrop
				f.dropped++
				if c == 0x9c {
					f.st = tfGround // ST: the string ends here for the terminal too
				}
				return out
			}
			return out
		}
		// An ordinary two-byte character: emit the held lead byte.
		switch f.st {
		case tfGround:
			out = append(out, 0xc2)
		case tfOSC:
			f.osc = append(f.osc, 0xc2)
		}
		if c&0xc0 == 0x80 {
			switch f.st {
			case tfGround:
				return append(out, c)
			case tfOSC:
				f.osc = append(f.osc, c)
				return out
			}
		}
	}
	switch f.st {
	case tfGround:
		switch {
		case c == 0xc2:
			f.utf8 = 0
			f.c2 = true
			return out
		case c == 0x1b:
			f.utf8 = 0
			f.st = tfEsc
			return out
		case f.utf8 > 0 && c&0xc0 == 0x80:
			f.utf8--
			return append(out, c)
		case c >= 0x80 && c <= 0x9f:
			// A C1 control (not part of a UTF-8 character): 8-bit forms of
			// CSI, OSC, DCS and the others. Dropped.
			f.utf8 = 0
			return f.c1(out, c)
		case c >= 0xc3 && c <= 0xdf:
			f.utf8 = 1
		case c >= 0xe0 && c <= 0xef:
			f.utf8 = 2
		case c >= 0xf0 && c <= 0xf4:
			f.utf8 = 3
		default:
			f.utf8 = 0
		}
		return append(out, c)
	case tfEsc:
		switch {
		case c == '[':
			f.st = tfCSI
			return append(out, 0x1b, '[')
		case c == ']':
			f.st = tfOSC
			f.osc = f.osc[:0]
			f.utf8 = 0
			return out
		case c == 'P' || c == '_' || c == '^' || c == 'X':
			f.st = tfDrop
			f.dropped++
			return out
		case c == 0x1b:
			return out // ESC ESC: the first one is ignored
		case c == 0x18 || c == 0x1a:
			f.st = tfGround
			return out
		case c >= 0x20 && c <= 0x2f:
			f.st = tfEscInter
			return append(out, 0x1b, c)
		case c >= 0x30 && c <= 0x7e:
			f.st = tfGround
			return append(out, 0x1b, c)
		case c >= 0x80:
			// ESC followed by a byte above ASCII is no sequence: the ESC is
			// dropped and the byte handled as text (a raw C1 is dropped).
			f.st = tfGround
			return f.byte(out, c)
		default:
			// A C0 control after ESC: executed by the emulator, ESC kept
			// pending is dropped.
			f.st = tfGround
			return append(out, c)
		}
	case tfEscInter:
		switch {
		case c >= 0x20 && c <= 0x2f:
			return append(out, c)
		case c >= 0x30 && c <= 0x7e:
			f.st = tfGround
			return append(out, c)
		case c == 0x1b:
			f.st = tfEsc
			return out
		case c >= 0x80:
			f.st = tfGround
			return f.byte(out, c)
		default:
			f.st = tfGround
			return append(out, c)
		}
	case tfCSI:
		switch {
		case c >= 0x40 && c <= 0x7e:
			f.st = tfGround
			return append(out, c)
		case c == 0x1b:
			f.st = tfEsc
			return out
		case c == 0x18 || c == 0x1a:
			f.st = tfGround
			return append(out, c)
		case c >= 0x80:
			// Not valid in a CSI: end it here.
			f.st = tfGround
			return out
		}
		return append(out, c)
	case tfOSC:
		if len(f.osc) >= maxOSC {
			f.st = tfDrop
			f.dropped++
			return f.byte(out, c)
		}
		switch {
		case c == 0x07:
			out = f.endOSC(out, []byte{0x07})
			f.st = tfGround
			return out
		case c == 0x1b:
			f.inStr = tfOSC
			f.st = tfStrEsc
			return out
		case c == 0x9c && f.utf8 == 0:
			out = f.endOSC(out, []byte{0x1b, '\\'})
			f.st = tfGround
			return out
		case c == 0xc2 && f.utf8 == 0:
			f.c2 = true
			return out
		case c >= 0x80 && c <= 0x9f && f.utf8 == 0:
			// A raw C1 control inside the string: drop the string.
			f.st = tfDrop
			f.dropped++
			return out
		case c >= 0x80:
			// UTF-8 text in a title or a link.
			switch {
			case f.utf8 > 0 && c&0xc0 == 0x80:
				f.utf8--
			case c >= 0xc3 && c <= 0xdf:
				f.utf8 = 1
			case c >= 0xe0 && c <= 0xef:
				f.utf8 = 2
			case c >= 0xf0 && c <= 0xf4:
				f.utf8 = 3
			default:
				f.utf8 = 0
			}
		case c == 0x18 || c == 0x1a:
			// CAN and SUB abort the string.
			f.st = tfGround
			f.dropped++
			return out
		case c < 0x20 || c == 0x7f:
			// A control character inside: drop the whole string.
			f.st = tfDrop
			f.dropped++
			return out
		}
		f.osc = append(f.osc, c)
		return out
	case tfDrop:
		switch c {
		case 0x07, 0x9c:
			f.st = tfGround
		case 0x1b:
			f.inStr = tfDrop
			f.st = tfStrEsc
		case 0x18, 0x1a:
			f.st = tfGround
		}
		return out
	case tfStrEsc:
		if c == '\\' {
			if f.inStr == tfOSC {
				out = f.endOSC(out, []byte{0x1b, '\\'})
			}
			f.st = tfGround
			return out
		}
		// ESC followed by anything else ends the string (unterminated)
		// and starts a new sequence. An OSC cut short is dropped.
		if f.inStr == tfOSC {
			f.dropped++
		}
		f.st = tfEsc
		return f.byte(out, c)
	}
	return out
}

// c1 drops a C1 control met in the ground state; the string introducers
// (DCS, SOS, OSC, PM, APC) start a string that is dropped whole.
func (f *TermFilter) c1(out []byte, c byte) []byte {
	f.dropped++
	switch c {
	case 0x9d:
		f.osc = f.osc[:0]
		f.st = tfDrop
	case 0x90, 0x98, 0x9e, 0x9f:
		f.st = tfDrop
	}
	return out
}

// endOSC emits the buffered OSC when its command is allowed.
func (f *TermFilter) endOSC(out, term []byte) []byte {
	cmd, _, _ := bytes.Cut(f.osc, []byte{';'})
	if !allowedOSC[string(cmd)] {
		f.dropped++
		return out
	}
	out = append(out, 0x1b, ']')
	out = append(out, f.osc...)
	return append(out, term...)
}

// copyFiltered copies src to dst through a TermFilter until src ends.
func copyFiltered(dst io.Writer, src io.Reader) error {
	var f TermFilter
	buf := make([]byte, 32*1024)
	out := make([]byte, 0, 32*1024+16)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			out = f.Filter(out[:0], buf[:n])
			if len(out) > 0 {
				if _, werr := dst.Write(out); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
