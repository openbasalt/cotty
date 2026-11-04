// Package mask hides secrets in the text an agent reads from a shared
// terminal.
//
// An Engine holds named secret values and token format rules. MaskGrid
// (MaskRows) masks a rendered screen grid, MaskLines masks committed
// scrollback lines and MaskText free text. Masking runs on rendered text,
// after the terminal emulator, so escape sequences and output chunk
// boundaries cannot split a secret past it. Each masked span becomes
// [masked:NAME], whatever its length: on a grid the replacement goes on
// the first row the span touches and the rest of the span is removed, so
// the output does not tell the value's length (Edits say how columns
// moved).
//
// For every secret the engine looks for the raw value and its common
// encodings: base64 (standard and URL alphabets, padded or not, and of the
// value followed by a newline, as `echo "$X" | base64` prints it), percent
// encoding (Go QueryEscape and PathEscape, JavaScript encodeURIComponent,
// strict RFC 3986, upper and lower case hex digits), hex (lower and upper
// case), base64 of the value inside a longer input (`user:VALUE` in a basic
// auth header) at each of the three byte alignments, JSON string escapes
// (\" \\ control characters, Go's \u003c for < > &, PHP's \/), and for a
// multi-line value the value without its line ends (screen rows are joined
// without them). MaskGrid and MaskLines also match across hard line ends,
// so base64 that `base64` wraps at 76 columns, or a multi-line value, is
// found in committed lines.
//
// Wrapping and reads in pieces: MaskRows and MaskRowsBelow match the rows
// of a screen as one joined text, so a value that wraps across rows is
// found; MaskRowsBelow also takes the end of the scrollback as context for
// a value scrolled half out of view. A Stream masks committed scrollback
// read in pieces (an agent's `since` cursor) so a value split between two
// reads is never returned in part.
//
// Not caught, stated plainly:
//
//   - a value inside a larger hex blob, or a base64 blob shorter than 8
//     characters for the value (a 6 or 7 byte value at an odd alignment);
//   - any other transform: compression, encryption, other encodings
//     (base32, quoted-printable, JSON \u escapes of non-ASCII text,
//     escapes of other languages), reversing, case changes of non-hex
//     text, a value split by inserted characters (a multi-line value whose
//     lines a program indents or pads) or printed in pieces at different
//     screen positions;
//   - a value the list does not know and no rule recognises.
//
// What it does not do, by design:
//
//   - A secret that is only partly on screen (cut off by the screen edge,
//     still being printed, scrolled half out of view) is only masked when
//     Options.PartialMin is set, which is off by default because it makes
//     masking an oracle for guessing fragments. Use MaskRowsBelow and
//     Stream so the context around the screen is there.
//   - Masking is not a confinement boundary.
package mask
