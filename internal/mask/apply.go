package mask

import (
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
	"unsafe"
)

// bytesOf views s as a byte slice without copying. The result is only read.
func bytesOf(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// snapToRunes widens every span to whole UTF-8 sequences, so a replacement
// never leaves half of a multi-byte character behind.
func snapToRunes(text string, spans []span) {
	for i := range spans {
		s, e := spans[i].start, spans[i].end
		for s > 0 && s < len(text) && !utf8.RuneStart(text[s]) {
			s--
		}
		for e < len(text) && !utf8.RuneStart(text[e]) {
			e++
		}
		spans[i].start, spans[i].end = s, e
	}
}

func (m *matcher) find(text string) []span {
	spans := m.findLiterals(bytesOf(text), nil)
	return m.findRules(text, spans)
}

func joinParts(parts []span) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(replacement(p.name))
	}
	return b.String()
}

// MaskText masks a committed piece of text (scrollback lines, the output of
// a command). Every masked span is replaced by [masked:NAME], one per
// secret or rule that covers it, with no attempt to keep the length. Pass
// several lines in one call (joined with "\n") when you have them: rules
// such as private-key need the BEGIN line to recognise the body lines. For
// text read in pieces, use a Stream.
func (e *Engine) MaskText(s string) (string, []Hit) {
	m := e.rlockFresh()
	defer e.mu.RUnlock()
	spans := m.find(s)
	if len(spans) == 0 {
		return s, nil
	}
	snapToRunes(s, spans)
	return maskRegion(s, 0, len(s), mergeSpans(spans))
}

// maskRegion returns text[from:to] masked with groups (offsets of text).
// A group that starts before from and continues into the region is
// replaced too, so the region never shows the tail of a secret whose head
// lies outside it; the same holds for a group that runs past to. Hit rows
// count '\n' from from.
func maskRegion(text string, from, to int, groups []group) (string, []Hit) {
	var b strings.Builder
	var hits []Hit
	last, line := from, 0
	for _, g := range groups {
		a, z := max(g.start, from), min(g.end, to)
		if z <= a {
			continue
		}
		line += strings.Count(text[last:a], "\n")
		b.WriteString(text[last:a])
		for _, p := range g.parts {
			b.WriteString(replacement(p.name))
			hits = append(hits, Hit{Name: p.name, Kind: p.kind, Row: line})
		}
		line += strings.Count(text[a:z], "\n")
		last = z
	}
	b.WriteString(text[last:to])
	return b.String(), hits
}

// MaskRows masks a rendered screen grid, one string per row, top to bottom.
// It is MaskRowsBelow with no text above the first row.
func (e *Engine) MaskRows(rows []string) ([]string, []Hit) {
	return e.MaskRowsBelow("", rows)
}

// MaskRowsBelow masks a rendered screen grid, one string per row, top to
// bottom, with Options.Width as the terminal width. It is MaskGrid
// without the edits.
func (e *Engine) MaskRowsBelow(above string, rows []string) ([]string, []Hit) {
	r := e.MaskGrid(above, rows, e.opts.Width)
	return r.Rows, r.Hits
}

// Edit records one change masking made to a row: bytes [InStart, InEnd)
// of the input row became bytes [OutStart, OutEnd) of the output row.
// Edits of a row come in order. A caller that reports a cursor column on a
// masked row uses them to move the column with the text (and never inside
// or after a span by its original length).
type Edit struct {
	Row              int
	InStart, InEnd   int
	OutStart, OutEnd int
}

// Masked is the result of MaskGrid and MaskLines: one output row per input
// row, always.
type Masked struct {
	Rows  []string
	Hits  []Hit
	Edits []Edit
}

// MaskGrid masks a rendered screen grid, one string per row, top to
// bottom. above is the text that precedes the first row in the terminal
// (the end of the scrollback, soft-wrapped rows joined without a
// separator, hard line ends as "\n"), used only as matching context so
// that a value scrolled half out of view is masked in the part still on
// screen. It is not returned. width is the terminal width (0: unknown).
//
// Wrapping: rows are always matched as one joined text, which is a
// superset of joining by wrap state: a secret that wraps is found whatever
// the renderer reports, and the price is that a match may also span a hard
// line break when the end of one row and the start of the next happen to
// form a secret, which only masks more. When width is set, rows shorter
// than width are also matched padded with spaces up to width (exactly the
// wrap-state rule: a short row does not continue), which finds a secret
// with a space at the wrap point when the renderer trims trailing blanks.
//
// Replacement: a masked span becomes [masked:NAME] on the first row it
// touches, whatever its length, and the part of the span on the rows it
// continues into is removed. The replacement does not depend on the
// value's length, so the output does not tell it (padding the span to its
// width would); the price is that the text after a span moves left or
// right. Edits say where.
func (e *Engine) MaskGrid(above string, rows []string, width int) Masked {
	seps := make([]string, len(rows))
	return e.maskJoined(above, rows, seps, "", width)
}

// MaskLines masks committed lines (the scrollback behind a since cursor).
// wrapped[i] says that line i continues on line i+1 (a soft wrap: joined
// without a separator); other lines end with "\n". above is the committed
// text before the first line and below the text after the last one (the
// following committed lines and the screen), both joined the same way and
// used only as matching context, so a value cut by the edges of a read is
// masked on both sides. The result has exactly one line per input line;
// the replacement rules are MaskGrid's.
func (e *Engine) MaskLines(above string, lines []string, wrapped []bool, below string) Masked {
	seps := make([]string, len(lines))
	for i := range lines {
		if i >= len(wrapped) || !wrapped[i] {
			seps[i] = "\n"
		}
	}
	return e.maskJoined(above, lines, seps, below, 0)
}

// maskJoined masks rows joined with seps (seps[i] follows rows[i]) between
// the context texts above and below.
func (e *Engine) maskJoined(above string, rows, seps []string, below string, width int) Masked {
	m := e.rlockFresh()
	defer e.mu.RUnlock()

	starts := make([]int, len(rows)+1)
	ends := make([]int, len(rows))
	var jb strings.Builder
	jb.WriteString(above)
	for i, r := range rows {
		starts[i] = jb.Len()
		jb.WriteString(r)
		ends[i] = jb.Len()
		jb.WriteString(seps[i])
	}
	starts[len(rows)] = jb.Len()
	jb.WriteString(below)
	joined := jb.String()

	spans := m.find(joined)
	spans = append(spans, m.findAcrossLines(joined)...)
	if width > 0 && m.hasSpace {
		// Grid only (every separator is ""): starts are offsets of joined.
		spans = append(spans, m.findPadded(rows, starts, width)...)
	}
	out := Masked{Rows: slices.Clone(rows)}
	if len(spans) == 0 {
		return out
	}
	snapToRunes(joined, spans)
	groups := mergeSpans(spans)
	named := make([]bool, len(groups))

	gi := 0
	for i := range rows {
		rs, re := starts[i], ends[i]
		for gi < len(groups) && groups[gi].end <= rs {
			gi++
		}
		if gi == len(groups) || groups[gi].start >= re {
			continue
		}
		var b strings.Builder
		pos := rs
		for k := gi; k < len(groups) && groups[k].start < re; k++ {
			g := groups[k]
			a, z := max(g.start, rs), min(g.end, re)
			if z <= a {
				continue
			}
			b.WriteString(joined[pos:a])
			ed := Edit{Row: i, InStart: a - rs, InEnd: z - rs, OutStart: b.Len()}
			if !named[k] {
				named[k] = true
				b.WriteString(joinParts(g.parts))
				for _, p := range g.parts {
					out.Hits = append(out.Hits, Hit{Name: p.name, Kind: p.kind, Row: i})
				}
			}
			ed.OutEnd = b.Len()
			out.Edits = append(out.Edits, ed)
			pos = z
		}
		b.WriteString(joined[pos:re])
		out.Rows[i] = b.String()
	}
	return out
}

// findAcrossLines finds literal patterns in text with its line ends
// removed and maps the matches back. It catches a value printed across
// hard line ends: base64 that `base64` wraps at 76 columns, a multi-line
// value (its variant without line ends), a value cut by a program that
// folds long lines. Joining unrelated lines can only mask more.
func (m *matcher) findAcrossLines(text string) []span {
	if len(m.patterns) == 0 || strings.IndexByte(text, '\n') < 0 {
		return nil
	}
	idx := make([]int, 0, len(text))
	var sb strings.Builder
	sb.Grow(len(text))
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' || text[i] == '\r' {
			continue
		}
		sb.WriteByte(text[i])
		idx = append(idx, i)
	}
	stripped := sb.String()
	raw := m.findLiterals(bytesOf(stripped), nil)
	out := raw[:0]
	for _, s := range raw {
		start, end := idx[s.start], idx[s.end-1]+1
		if end-start == s.end-s.start {
			continue // no line end inside: the plain pass has it
		}
		s.start, s.end = start, end
		out = append(out, s)
	}
	return out
}

// findPadded matches literal patterns on the rows padded with spaces up to
// width and maps the hits back to offsets of the joined rows.
func (m *matcher) findPadded(rows []string, starts []int, width int) []span {
	pstarts := make([]int, len(rows)+1)
	var pb strings.Builder
	for i, r := range rows {
		pstarts[i] = pb.Len()
		pb.WriteString(r)
		if n := width - utf8.RuneCountInString(r); n > 0 {
			pb.WriteString(strings.Repeat(" ", n))
		}
	}
	pstarts[len(rows)] = pb.Len()
	padded := pb.String()
	raw := m.findLiterals(bytesOf(padded), nil)

	// locate returns the row of padded offset x and the offset inside it.
	locate := func(x int) (int, int) {
		i := sort.Search(len(rows), func(i int) bool { return pstarts[i+1] > x })
		return i, x - pstarts[i]
	}
	var out []span
	for _, s := range raw {
		i, off := locate(s.start)
		start := starts[i] + off
		if off >= len(rows[i]) {
			start = starts[i+1]
		}
		j, offEnd := locate(s.end - 1)
		end := starts[j] + offEnd + 1
		if offEnd >= len(rows[j]) {
			end = starts[j] + len(rows[j])
		}
		if end > start {
			s.start, s.end = start, end
			out = append(out, s)
		}
	}
	return out
}
