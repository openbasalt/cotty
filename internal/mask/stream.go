package mask

import (
	"fmt"
	"sync"
	"unicode/utf8"
)

// StreamContext is how many bytes of already returned text a Stream keeps
// as matching context (enough for the header of a 4096-bit PEM key and its
// body).
const StreamContext = 16 << 10

// Stream masks committed text that is read in pieces, such as the
// scrollback behind an agent's `since` cursor, where one read can end in
// the middle of a secret and the next read starts with the rest of it.
//
// Each call to Next gets the newly committed text plus a lookahead: the
// text that follows it in the terminal right now (the current screen rows,
// joined top to bottom, soft-wrapped rows without a separator). Masking
// runs on context + committed + lookahead, and only the committed part is
// returned, so:
//
//   - a value whose head is in this read and whose tail is still on the
//     screen (not committed yet) is masked here, thanks to the lookahead;
//   - the tail of that value, when it is committed and read next time, is
//     masked again, thanks to the context kept from earlier reads (the
//     replacement shows up at the start of the new piece);
//   - multi-line rules (private-key) see the BEGIN line in the context.
//
// How the broker uses it: one Stream per agent cursor. When the agent reads
// `since`, take the lines committed after its cursor, joined so that
// soft-wrapped rows have no separator and hard line ends are "\n", call
// Next(thatText, currentScreenJoined) and return the result. Never return
// committed text that did not go through the same Stream. Reset it when the
// cursor jumps (the agent asks for an older position): the context then no
// longer precedes the new text.
//
// Nothing is held back based on content: holding back text that looks like
// the start of a secret would tell the reader which prefixes are secret.
//
// A Stream keeps up to StreamContext bytes of unmasked text in memory (the
// broker's scrollback holds the same text anyway). It is safe for
// concurrent use, though one reader per Stream is the normal case.
type Stream struct {
	e   *Engine
	mu  sync.Mutex
	ctx string
}

// NewStream returns a Stream that masks with e's current secrets and rules.
func (e *Engine) NewStream() *Stream {
	return &Stream{e: e}
}

// Next masks committed, which follows the text of the previous calls,
// using lookahead (the text that follows committed, not returned) as
// context. Hit rows count '\n' in committed.
func (s *Stream) Next(committed, lookahead string) (string, []Hit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	full := s.ctx + committed + lookahead
	from, to := len(s.ctx), len(s.ctx)+len(committed)

	m := s.e.rlockFresh()
	spans := m.find(full)
	var out string
	var hits []Hit
	if len(spans) == 0 {
		out = committed
	} else {
		snapToRunes(full, spans)
		out, hits = maskRegion(full, from, to, mergeSpans(spans))
	}
	s.e.mu.RUnlock()

	ctx := full[:to]
	if len(ctx) > StreamContext {
		cut := len(ctx) - StreamContext
		for cut < len(ctx) && !utf8.RuneStart(ctx[cut]) {
			cut++
		}
		// Copy, so the context does not pin the whole history.
		ctx = string([]byte(ctx[cut:]))
	}
	s.ctx = ctx
	return out, hits
}

// Reset forgets the context, for when the next text does not follow the
// previous one.
func (s *Stream) Reset() {
	s.mu.Lock()
	s.ctx = ""
	s.mu.Unlock()
}

// String reports no content.
func (s *Stream) String() string { return "mask.Stream" }

// GoString is String, so %#v does not dump the context.
func (s *Stream) GoString() string { return s.String() }

// Format makes every fmt verb print String.
func (s *Stream) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(s.String())) }
