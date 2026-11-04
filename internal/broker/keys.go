package broker

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// keyBytes maps a key name (docs/protocol.md, op keys) to the bytes a
// terminal sends for it. appCursor selects the application cursor key
// encoding (DECCKM), which vim, less and readline in some modes use.
func keyBytes(name string, appCursor bool) ([]byte, error) {
	cur := func(c byte) []byte {
		if appCursor {
			return []byte{0x1b, 'O', c}
		}
		return []byte{0x1b, '[', c}
	}
	switch name {
	case "Enter":
		return []byte{'\r'}, nil
	case "Tab":
		return []byte{'\t'}, nil
	case "BTab":
		return []byte("\x1b[Z"), nil
	case "Esc":
		return []byte{0x1b}, nil
	case "Backspace":
		return []byte{0x7f}, nil
	case "Space":
		return []byte{' '}, nil
	case "Delete":
		return []byte("\x1b[3~"), nil
	case "Insert":
		return []byte("\x1b[2~"), nil
	case "Home":
		return cur('H'), nil
	case "End":
		return cur('F'), nil
	case "PgUp":
		return []byte("\x1b[5~"), nil
	case "PgDn":
		return []byte("\x1b[6~"), nil
	case "Up":
		return cur('A'), nil
	case "Down":
		return cur('B'), nil
	case "Right":
		return cur('C'), nil
	case "Left":
		return cur('D'), nil
	}
	if f, ok := fKeys[name]; ok {
		return []byte(f), nil
	}
	if rest, ok := strings.CutPrefix(name, "C-"); ok && len(rest) == 1 {
		c := rest[0]
		switch {
		case c >= 'a' && c <= 'z':
			return []byte{c - 'a' + 1}, nil
		case c >= 'A' && c <= 'Z':
			return []byte{c - 'A' + 1}, nil
		case c == '@' || c == ' ':
			return []byte{0}, nil
		case c == '[':
			return []byte{0x1b}, nil
		case c == '\\':
			return []byte{0x1c}, nil
		case c == ']':
			return []byte{0x1d}, nil
		case c == '^':
			return []byte{0x1e}, nil
		case c == '_':
			return []byte{0x1f}, nil
		}
	}
	if rest, ok := strings.CutPrefix(name, "M-"); ok && utf8.RuneCountInString(rest) == 1 {
		return append([]byte{0x1b}, rest...), nil
	}
	return nil, fmt.Errorf("unknown key %q", name)
}

var fKeys = map[string]string{
	"F1": "\x1bOP", "F2": "\x1bOQ", "F3": "\x1bOR", "F4": "\x1bOS",
	"F5": "\x1b[15~", "F6": "\x1b[17~", "F7": "\x1b[18~", "F8": "\x1b[19~",
	"F9": "\x1b[20~", "F10": "\x1b[21~", "F11": "\x1b[23~", "F12": "\x1b[24~",
}

// confirmKeys are the keys an agent may send under the confirm policy:
// nothing that can submit a line without the person seeing it.
var confirmKeys = map[string]bool{
	"Enter": true, "Tab": true, "Backspace": true, "Delete": true, "Space": true,
	"Left": true, "Right": true, "Up": true, "Down": true, "Home": true, "End": true,
	"C-c": true,
}

// confirmTextOK reports whether agent text is allowed under the confirm
// policy: printable characters, tab, backspace, C-c and Enter only. Other
// control characters (C-o, C-j variants, C-x C-e) and escape sequences
// could submit or edit a line in ways the person does not see coming.
func confirmTextOK(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\t' || c == '\r' || c == '\n' || c == 0x7f || c == 0x08 || c == 0x03:
		case c < 0x20:
			return false
		}
	}
	return true
}
