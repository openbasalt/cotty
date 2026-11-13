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
// nothing that can submit a line, run a program or draw earlier commands
// without the person seeing it first. The decision per key follows what
// GNU readline (bash) and zle (zsh) do with the bytes by default, in the
// emacs and the vi keymaps (review COT-1, COT-3):
//
//   - Enter is held for the person's answer (agentType).
//   - Backspace (DEL), Delete (CSI 3 ~), Left, Right, Home, End only edit
//     or move within the line. A sequence a shell does not bind (zsh's
//     emacs keymap leaves Delete unbound) beeps or inserts its last
//     character; in vi mode its ESC switches to the command keymap, where
//     none of the remaining bytes ([, digits, ~, A to H, O) accepts the
//     line or runs anything.
//   - Space inserts a blank. Where it is bound to magic-space (oh-my-zsh
//     does that) it expands history references already on the line; the
//     characters that start one are refused in text (confirmTextOK).
//   - C-c interrupts; it never runs anything.
//
// Refused, although they do not submit a line:
//
//   - Tab and BTab: completion runs programs and files the agent may have
//     written (bash-completion runs `./configure --help` for options and
//     `make -npq`, which evaluates $(shell ...) in a Makefile; zsh's
//     _configure and _make do the same) in the person's unconfined shell.
//   - Up, Down, PgUp, PgDn: they recall the shell's history onto the
//     screen, including commands typed in private mode.
//   - Esc, Insert, F-keys, every C- and M- key: M-., M-_, M-p, M-<, C-p,
//     C-r recall history; C-x C-e, M-C-e (shell-expand-line) and C-o run
//     or submit something; M-?, M-*, M-/ and C-x * complete or expand.
var confirmKeys = map[string]bool{
	"Enter": true, "Backspace": true, "Delete": true, "Space": true,
	"Left": true, "Right": true, "Home": true, "End": true,
	"C-c": true,
}

// confirmTextOK reports whether agent text is allowed under the confirm
// policy: printable characters, backspace, C-c and Enter only. Refused:
//
//   - Tab (completion runs programs, see confirmKeys) and every other
//     control character and escape sequence (C-o, C-x C-e, Meta
//     sequences), which could submit or edit a line in ways the person
//     does not see coming;
//   - history expansion: a '!' that starts a history reference in bash and
//     zsh (any '!' not followed by a blank, '=' or '('; a '!' at the end
//     of the text too, as the next text may complete it) and '^' (quick
//     substitution, ^old^new): with Space bound to magic-space they draw
//     earlier commands, private ones included, on the screen without an
//     Enter, and after an Enter the line that runs is not the line the
//     person approved;
//   - bytes with the eighth bit set unless the shell's locale is UTF-8
//     (utf8): with readline's convert-meta, on by default in 8-bit
//     locales such as C or POSIX, each such byte is a Meta key, and
//     M-C-e (0x85) runs the command substitutions of the line.
func confirmTextOK(s string, utf8 bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\r' || c == '\n' || c == 0x7f || c == 0x08 || c == 0x03:
		case c < 0x20:
			return false
		case c == '^':
			return false
		case c == '!':
			if i+1 == len(s) {
				return false
			}
			switch s[i+1] {
			case ' ', '\t', '\r', '\n', '=', '(':
			default:
				return false
			}
		case c >= 0x80 && !utf8:
			return false
		}
	}
	return true
}

// localeIsUTF8 reports whether an environment selects a UTF-8 character
// set for the shell (LC_ALL, then LC_CTYPE, then LANG, as setlocale reads
// them). Readline then leaves convert-meta off and reads bytes with the
// eighth bit set as characters, not as Meta keys.
func localeIsUTF8(env []string) bool {
	get := func(k string) string {
		v := ""
		for _, e := range env {
			if rest, ok := strings.CutPrefix(e, k+"="); ok {
				v = rest
			}
		}
		return v
	}
	v := get("LC_ALL")
	if v == "" {
		v = get("LC_CTYPE")
	}
	if v == "" {
		v = get("LANG")
	}
	v = strings.ToLower(v)
	return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
}
