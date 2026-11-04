package mask

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Kind says what produced a masked span.
type Kind string

const (
	KindLiteral Kind = "literal" // the secret value as is
	KindBase64  Kind = "base64"  // base64 of the value (std or URL, padded or not, with or without a trailing newline)
	KindURL     Kind = "url"     // percent-encoded value
	KindHex     Kind = "hex"     // hex of the value, lower or upper case
	KindPartial Kind = "partial" // a fragment of the value (Options.PartialMin)
	KindRule    Kind = "rule"    // a token format rule; Name is the rule name
)

// Hit reports one replacement. It never carries the value.
type Hit struct {
	Name string // secret or rule name
	Kind Kind
	// Row is the index of the row (MaskRows) or line (MaskText, counting
	// '\n') where the masked span starts.
	Row int
}

// DefaultMinLen is the shortest secret value AddSecret accepts by default.
// Shorter values would mask ordinary words all over the screen.
const DefaultMinLen = 6

// Options configures an Engine. The zero value is usable.
type Options struct {
	// MinLen is the shortest value AddSecret accepts (default 6, lower
	// values are raised to 4).
	MinLen int
	// Width is the terminal width in columns used by MaskRows. Rows are
	// always matched as one joined text, so a secret that wraps from the
	// end of one row into the next is found whatever Width says. When Width
	// is set, rows shorter than Width (renderers often trim trailing blanks)
	// are also matched padded with spaces up to Width, which finds secrets
	// that contain a space exactly at the wrap point. Width counts runes:
	// a row with double-width characters may be padded a little too much,
	// which only costs that extra pass its precision, never the main one.
	Width int
	// NoBuiltinRules turns off BuiltinRules. Rules added with AddRule still run.
	NoBuiltinRules bool
	// Entropy turns on EntropyRule (off by default).
	Entropy bool
	// PartialMin, when > 0, also masks any run of at least PartialMin bytes
	// that is a fragment of a secret's raw value (for example the start of
	// a key cut off by `less -S`, or a value still being printed). It is
	// off by default because it turns masking into an oracle: whoever can
	// print text and read the masked result can grow a guessed fragment one
	// byte at a time. Use it only with long random secrets and a large
	// PartialMin (12 or more). Values below MinLen are raised to MinLen.
	PartialMin int
}

// Engine holds named secrets and rules and masks text an agent will read.
// It is safe for concurrent use. Values live in locked memory outside the
// Go heap where possible and are zeroed when removed; Engine never prints
// them (String, GoString and every fmt verb print only counts).
type Engine struct {
	opts Options

	mu      sync.RWMutex
	secrets []*secret // sorted by name
	rules   []compiledRule
	dirty   bool
	m       *matcher
}

type secret struct {
	name string
	sets []valueSet // one per value, oldest first (AddSecretVersion)
}

// valueSet is one value of a secret and its variants.
type valueSet struct {
	arena *arena
	vars  []variant // vars[0] is the raw value
}

// maxVersions is how many values one secret name keeps (a rotated value
// stays masked next to the new one: it may still be on screen).
const maxVersions = 4

func (s *secret) allVars() []variant {
	if len(s.sets) == 1 {
		return s.sets[0].vars
	}
	var out []variant
	for _, vs := range s.sets {
		out = append(out, vs.vars...)
	}
	return out
}

func (s *secret) free() {
	for _, vs := range s.sets {
		vs.arena.free()
	}
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// Errors returned by AddSecret and AddRule. They never contain values.
var (
	ErrBadName       = errors.New("mask: name must match [A-Za-z0-9_.-]{1,64}")
	ErrTooShort      = errors.New("mask: secret value is shorter than the minimum length")
	ErrInReplacement = errors.New("mask: secret value would show up in a replacement text (part of a name or of the replacement template)")
	ErrBadRule       = errors.New("mask: rule needs a Pattern or a Find function")
)

// New returns an Engine with the built-in rules (unless turned off).
func New(opts Options) *Engine {
	if opts.MinLen <= 0 {
		opts.MinLen = DefaultMinLen
	}
	opts.MinLen = max(opts.MinLen, 4)
	if opts.PartialMin > 0 {
		opts.PartialMin = max(opts.PartialMin, opts.MinLen)
	}
	e := &Engine{opts: opts, dirty: true}
	if !opts.NoBuiltinRules {
		for _, r := range BuiltinRules() {
			e.rules = append(e.rules, compileRule(r))
		}
	}
	if opts.Entropy {
		e.rules = append(e.rules, compileRule(EntropyRule()))
	}
	return e
}

// replacement is the text that takes the place of a masked span.
func replacement(name string) string {
	return "[masked:" + name + "]"
}

// AddSecret adds (or replaces) the secret called name. The value is copied,
// so the caller may zero its own copy right after. Values shorter than
// Options.MinLen are rejected.
func (e *Engine) AddSecret(name string, value []byte) error {
	return e.addSecret(name, value, false)
}

// AddSecretVersion adds value to the secret called name, keeping the
// values it already has (up to 4, the oldest dropped first), so a rotated
// value and the one before it are both masked. A value the secret already
// has is a no-op.
func (e *Engine) AddSecretVersion(name string, value []byte) error {
	return e.addSecret(name, value, true)
}

func (e *Engine) addSecret(name string, value []byte, keep bool) error {
	if !nameRE.MatchString(name) {
		return ErrBadName
	}
	if len(value) < e.opts.MinLen {
		return ErrTooShort
	}
	a, vars := buildVariants(value)
	e.mu.Lock()
	defer e.mu.Unlock()
	// A value that occurs in some replacement text would be printed by the
	// masking itself. Check the new secret against every name, and every
	// existing secret against the new name.
	names := []string{name}
	for _, s := range e.secrets {
		names = append(names, s.name)
	}
	for _, r := range e.rules {
		names = append(names, r.Name)
	}
	for _, n := range names {
		if leaksInto(vars, replacement(n)) {
			a.free()
			return ErrInReplacement
		}
	}
	for _, s := range e.secrets {
		if s.name != name && leaksInto(s.allVars(), replacement(name)) {
			a.free()
			return ErrInReplacement
		}
	}
	ns := &secret{name: name, sets: []valueSet{{arena: a, vars: vars}}}
	i, found := slices.BinarySearchFunc(e.secrets, name, func(s *secret, n string) int {
		return strings.Compare(s.name, n)
	})
	switch {
	case found && keep:
		old := e.secrets[i]
		for _, vs := range old.sets {
			if bytes.Equal(vs.vars[0].b, vars[0].b) {
				a.free()
				return nil
			}
		}
		sets := append(slices.Clone(old.sets), ns.sets[0])
		e.m = nil // drop references into arenas before freeing any
		for len(sets) > maxVersions {
			sets[0].arena.free()
			sets = sets[1:]
		}
		e.secrets[i] = &secret{name: name, sets: sets}
	case found:
		e.m = nil
		e.secrets[i].free()
		e.secrets[i] = ns
	default:
		e.secrets = slices.Insert(e.secrets, i, ns)
	}
	e.dirty = true
	return nil
}

func leaksInto(vars []variant, text string) bool {
	for _, v := range vars {
		if bytes.Contains([]byte(text), v.b) {
			return true
		}
	}
	return false
}

// LongestPattern returns the length in bytes of the longest text a secret
// on the list is matched by (its longest encoded variant), 0 without
// secrets. It never reveals a value, only a length the configuration
// already fixes.
func (e *Engine) LongestPattern() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := 0
	for _, s := range e.secrets {
		for _, v := range s.allVars() {
			n = max(n, len(v.b))
		}
	}
	return n
}

// RemoveSecret removes the secret called name and zeroes its memory. It
// waits for masking calls in flight. Removing an unknown name is a no-op.
func (e *Engine) RemoveSecret(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, s := range e.secrets {
		if s.name == name {
			e.secrets = slices.Delete(e.secrets, i, i+1)
			e.dirty = true
			e.m = nil // drop references into the arena before freeing it
			s.free()
			return
		}
	}
}

// Close removes every secret and zeroes their memory.
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.m = nil
	for _, s := range e.secrets {
		s.free()
	}
	e.secrets = nil
	e.dirty = true
}

// AddRule adds a token format rule. Its name must not contain any secret.
func (e *Engine) AddRule(r Rule) error {
	if !nameRE.MatchString(r.Name) {
		return ErrBadName
	}
	if r.Find == nil && r.Pattern == nil {
		return ErrBadRule
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.secrets {
		if leaksInto(s.allVars(), replacement(r.Name)) {
			return ErrInReplacement
		}
	}
	e.rules = append(e.rules, compileRule(r))
	e.dirty = true
	return nil
}

// Names returns the secret names, sorted.
func (e *Engine) Names() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, len(e.secrets))
	for i, s := range e.secrets {
		out[i] = s.name
	}
	return out
}

// String reports counts only, never values.
func (e *Engine) String() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return fmt.Sprintf("mask.Engine{secrets: %d, rules: %d}", len(e.secrets), len(e.rules))
}

// GoString is String, so %#v does not dump the fields.
func (e *Engine) GoString() string { return e.String() }

// Format makes every fmt verb print String.
func (e *Engine) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(e.String())) }

// rlockFresh takes the read lock with an up to date matcher. The caller
// must RUnlock. Holding the read lock while matching keeps RemoveSecret from
// freeing an arena the matcher still points into.
func (e *Engine) rlockFresh() *matcher {
	for {
		e.mu.RLock()
		if !e.dirty && e.m != nil {
			return e.m
		}
		e.mu.RUnlock()
		e.mu.Lock()
		if e.dirty || e.m == nil {
			e.m = buildMatcher(e.secrets, e.rules, e.opts)
			e.dirty = false
		}
		e.mu.Unlock()
	}
}
