package mask

import (
	"bytes"
	"encoding/binary"
	"sort"
)

// Literal matching: every pattern (variant or fragment of a secret) is at
// least keyLen bytes long, so the first keyLen bytes of a pattern are an
// exact key. The text is scanned once; at each position the next keyLen
// bytes are packed into a uint64, checked against a 64 Kbit filter and, on
// a filter hit, looked up in a map of candidate patterns, which are then
// compared in full. This finds every occurrence of every pattern, including
// overlapping ones, in time linear in the text for realistic pattern sets,
// with far less memory than an Aho-Corasick automaton over 256 symbols.

const filterBits = 1 << 16

type pattern struct {
	b    []byte // points into the owning secret's arena
	name string
	kind Kind
}

type matcher struct {
	keyLen   int
	keyMask  uint64
	filter   []uint64
	index    map[uint64][]int32
	patterns []pattern
	hasSpace bool // some pattern contains a space (enables the padded pass)
	rules    []compiledRule
}

func filterSlot(key uint64) uint64 {
	return (key * 0x9E3779B97F4A7C15) >> (64 - 16)
}

func buildMatcher(secrets []*secret, rules []compiledRule, opts Options) *matcher {
	m := &matcher{
		keyLen: min(opts.MinLen, 8),
		filter: make([]uint64, filterBits/64),
		index:  map[uint64][]int32{},
		rules:  rules,
	}
	m.keyMask = ^uint64(0) >> (64 - 8*m.keyLen)
	add := func(p pattern) {
		key := m.keyOf(p.b, 0)
		m.patterns = append(m.patterns, p)
		m.index[key] = append(m.index[key], int32(len(m.patterns)-1))
		slot := filterSlot(key)
		m.filter[slot/64] |= 1 << (slot % 64)
		if bytes.IndexByte(p.b, ' ') >= 0 {
			m.hasSpace = true
		}
	}
	for _, s := range secrets {
		for _, vs := range s.sets {
			for _, v := range vs.vars {
				if len(v.b) < m.keyLen {
					continue // too short to key (a multi-line value without its line ends)
				}
				add(pattern{b: v.b, name: s.name, kind: v.kind})
			}
			if k := opts.PartialMin; k > 0 {
				raw := vs.vars[0].b
				// Fragments shorter than the value; the full value is vars[0].
				for i := 0; i+k <= len(raw) && k < len(raw); i++ {
					add(pattern{b: raw[i : i+k], name: s.name, kind: KindPartial})
				}
			}
		}
	}
	return m
}

// keyOf packs keyLen bytes of b starting at i (caller ensures they exist).
func (m *matcher) keyOf(b []byte, i int) uint64 {
	if i+8 <= len(b) {
		return binary.LittleEndian.Uint64(b[i:]) & m.keyMask
	}
	var k uint64
	for j := m.keyLen - 1; j >= 0; j-- {
		k = k<<8 | uint64(b[i+j])
	}
	return k
}

// span is a masked byte range of a text.
type span struct {
	start, end int
	name       string
	kind       Kind
	prio       int // lower wins when two spans cover the same range
}

// findLiterals appends the occurrences of every pattern in text.
func (m *matcher) findLiterals(text []byte, out []span) []span {
	if len(m.patterns) == 0 {
		return out
	}
	for i := 0; i+m.keyLen <= len(text); i++ {
		key := m.keyOf(text, i)
		slot := filterSlot(key)
		if m.filter[slot/64]&(1<<(slot%64)) == 0 {
			continue
		}
		for _, pi := range m.index[key] {
			p := &m.patterns[pi]
			if bytes.HasPrefix(text[i:], p.b) {
				prio := 0
				if p.kind == KindPartial {
					prio = 1
				}
				out = append(out, span{start: i, end: i + len(p.b), name: p.name, kind: p.kind, prio: prio})
			}
		}
	}
	return out
}

// findRules appends the matches of every rule in text.
func (m *matcher) findRules(text string, out []span) []span {
	for ri := range m.rules {
		r := &m.rules[ri]
		for _, se := range r.find(text) {
			if se[0] >= 0 && se[1] <= len(text) && se[1] > se[0] {
				out = append(out, span{start: se[0], end: se[1], name: r.Name, kind: KindRule, prio: 2 + ri})
			}
		}
	}
	return out
}

// group is a maximal run of overlapping spans, replaced as one unit.
type group struct {
	start, end int
	parts      []span // what the replacement names, in order
}

// mergeSpans turns raw spans into disjoint groups. Inside a group, spans of
// the same name are merged first (fragments, padded and unpadded base64),
// then spans contained in another span are dropped (equal ranges keep the
// lower prio), and the rest name the replacement in order of start.
func mergeSpans(spans []span) []group {
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		if spans[i].end != spans[j].end {
			return spans[i].end > spans[j].end
		}
		return spans[i].prio < spans[j].prio
	})
	var groups []group
	cur := group{start: spans[0].start, end: spans[0].end}
	members := []span{spans[0]}
	flush := func() {
		cur.parts = reduceParts(members)
		groups = append(groups, cur)
	}
	for _, s := range spans[1:] {
		if s.start < cur.end {
			cur.end = max(cur.end, s.end)
			members = append(members, s)
			continue
		}
		flush()
		cur = group{start: s.start, end: s.end}
		members = []span{s}
	}
	flush()
	return groups
}

func reduceParts(members []span) []span {
	// Union same-name spans that overlap.
	var merged []span
	for _, s := range members {
		done := false
		for i := range merged {
			if merged[i].name == s.name && s.start < merged[i].end && merged[i].start < s.end {
				merged[i].start = min(merged[i].start, s.start)
				merged[i].end = max(merged[i].end, s.end)
				if s.prio < merged[i].prio {
					merged[i].prio, merged[i].kind = s.prio, s.kind
				}
				done = true
				break
			}
		}
		if !done {
			merged = append(merged, s)
		}
	}
	// Drop spans contained in another one.
	var kept []span
	for i, s := range merged {
		inside := false
		for j, o := range merged {
			if i == j || o.start > s.start || o.end < s.end {
				continue
			}
			same := o.start == s.start && o.end == s.end
			if !same || o.prio < s.prio || o.prio == s.prio && j < i {
				inside = true
				break
			}
		}
		if !inside {
			kept = append(kept, s)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].start < kept[j].start })
	return kept
}
