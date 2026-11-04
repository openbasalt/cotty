package broker

import "errors"

// MaskEdit is one change masking made to a row: bytes [InStart, InEnd) of
// the input row became bytes [OutStart, OutEnd) of the output row (see
// mask.Edit). The broker moves the reported cursor column with them.
type MaskEdit struct {
	Row              int
	InStart, InEnd   int
	OutStart, OutEnd int
}

// MaskedRows is what MaskScreen and MaskLines return: exactly one row per
// input row (a Masker that cannot keep that must say so by returning a
// different count; the broker then serves nothing).
type MaskedRows struct {
	Rows  []string
	Hits  []MaskHit
	Edits []MaskEdit
}

// MaskHit is one masked span, as the broker logs it (names only, never
// values).
type MaskHit struct {
	Name string
	Kind string
	Row  int
}

// Masker hides secrets in the text an agent reads. Masking runs on
// rendered text, after the vt model. Engine (maskengine.go) wraps
// internal/mask; NoMask is the stand-in for tests and sessions without a
// masking list.
//
// Text handed to a Masker follows one convention: soft-wrapped rows (a row
// that continues on the next) are joined without a separator and hard line
// ends are "\n", so a value that wraps is one run of text.
type Masker interface {
	// MaskScreen masks the screen rows (top to bottom). above is the text
	// before the first row (the end of the scrollback), used only as
	// matching context so a value scrolled half out of view is masked in
	// the part still visible; it is not returned. cols is the terminal
	// width now.
	MaskScreen(above string, rows []string, cols int) MaskedRows
	// MaskLines masks committed scrollback lines read in pieces. wrapped[i]
	// says line i continues on line i+1. above is the committed text right
	// before them and below the text after them in the terminal now (the
	// following committed lines and the screen), both matching context
	// only. A value split across the edges of a read is masked on both
	// sides. One line comes back per line.
	MaskLines(above string, lines []string, wrapped []bool, below string) MaskedRows
	// MaskText masks free text (a command line, a pending agent line).
	MaskText(s string) (string, []MaskHit)
	// AddByName adds a secret from the configured secret sources by name
	// (term_mask). ErrUnsupported when no sources are configured,
	// ErrUnknownSecret when the name is not found, ErrNotMaskable
	// otherwise.
	AddByName(name string) error
}

// Errors returned by Masker.AddByName.
var (
	ErrUnsupported   = errors.New("masking by name is not available")
	ErrUnknownSecret = errors.New("unknown secret")
	// ErrNotMaskable: the source failed, is in backoff, or the value cannot
	// go on the list. Deliberately vague: the agent learns nothing about
	// the value (such as its length).
	ErrNotMaskable = errors.New("the secret could not be added to the masking list now")
)

// NoMask is a Masker that returns text unchanged.
type NoMask struct{}

// MaskScreen returns rows unchanged.
func (NoMask) MaskScreen(_ string, rows []string, _ int) MaskedRows { return MaskedRows{Rows: rows} }

// MaskLines returns lines unchanged.
func (NoMask) MaskLines(_ string, lines []string, _ []bool, _ string) MaskedRows {
	return MaskedRows{Rows: lines}
}

// MaskText returns s unchanged.
func (NoMask) MaskText(s string) (string, []MaskHit) { return s, nil }

// AddByName is unsupported.
func (NoMask) AddByName(string) error { return ErrUnsupported }
