package broker

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/openbasalt/cotty/internal/mask"
	"github.com/openbasalt/cotty/internal/secretsrc"
)

// Engine is the broker's Masker: internal/mask (WP-B) with the secret
// values named in the person's secrets.conf (internal/secretsrc).
//
// Where the values live: mask.Engine copies each value into memory locked
// with mlock outside the Go heap (where the kernel allows it) and zeroes
// it on RemoveSecret and Close; the broker closes the engine when the
// session ends. The copies the resolver returns are zeroed right after
// AddSecret. The broker process is not dumpable, so neither the locked
// list nor the terminal model (whose grid and scrollback hold the same
// values unmasked, in ordinary memory) can be read through ptrace,
// /proc/PID/mem or a core file by processes of the same user.
type Engine struct {
	eng *mask.Engine
	// load returns the resolver for the current secrets.conf (read again
	// on every term_mask, so secrets added with `cotty secrets add` after
	// the session started can be masked by name). nil: no configuration.
	load func() (*secretsrc.Resolver, error)
	logf func(string, ...any)

	mu     sync.Mutex
	loaded map[string]time.Time // name -> when its value was last read
	failed map[string]failure   // name -> backoff after a failed read
	now    func() time.Time     // tests
}

// failure is the backoff state of a secret whose source failed: term_mask
// does not run the source again (a keyring unlock prompt, a slow vault
// command) before until.
type failure struct {
	until time.Time
	n     int
}

// Backoff after a failed read: 10 s doubling up to 10 min. A value read
// successfully is read again (to catch a rotation) at most every
// reloadAfter.
const (
	backoffFirst = 10 * time.Second
	backoffMax   = 10 * time.Minute
	reloadAfter  = 5 * time.Minute
)

// EngineConfig configures NewEngine.
type EngineConfig struct {
	// ConfigPath is secrets.conf (default secretsrc.DefaultConfigPath()).
	ConfigPath string
	// Width is the terminal width at start (mask.Options.Width);
	// MaskScreen gets the current width on every call, so resizes are
	// followed.
	Width int
	// Logf receives load errors (names and references, never values).
	Logf func(string, ...any)
	// Resolver, when set, replaces reading ConfigPath (tests).
	Resolver *secretsrc.Resolver
}

// NewEngine builds the masking engine and loads every secret the
// configuration names. A missing configuration is not an error: the
// built-in token rules still run.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = secretsrc.DefaultConfigPath()
	}
	e := &Engine{eng: mask.New(mask.Options{Width: cfg.Width}), logf: cfg.Logf,
		loaded: map[string]time.Time{}, failed: map[string]failure{}, now: time.Now}
	switch {
	case cfg.Resolver != nil:
		r := cfg.Resolver
		e.load = func() (*secretsrc.Resolver, error) { return r, nil }
	default:
		path := cfg.ConfigPath
		e.load = func() (*secretsrc.Resolver, error) {
			c, err := secretsrc.LoadConfig(path)
			if err != nil {
				return nil, err
			}
			return secretsrc.NewResolver(c, secretsrc.Options{}), nil
		}
	}
	r, err := e.load()
	switch {
	case errors.Is(err, os.ErrNotExist):
		e.logf("masking: no %s; only the built-in token rules run", cfg.ConfigPath)
		return e
	case err != nil:
		e.logf("masking: %v", err)
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	secrets, err := r.ResolveAll(ctx)
	if err != nil {
		e.logf("masking: %v", err)
	}
	for i := range secrets {
		_ = e.add(secrets[i].Name, secrets[i].Value, false)
		secrets[i].Zero()
	}
	return e
}

// add puts a value on the list. keep adds it next to the values the name
// already has (a rotated value: the old one may still be on screen).
func (e *Engine) add(name string, v []byte, keep bool) error {
	var err error
	if keep {
		err = e.eng.AddSecretVersion(name, v)
	} else {
		err = e.eng.AddSecret(name, v)
	}
	if err != nil {
		e.logf("masking: secret %s not added: %v", name, err)
		return err
	}
	e.mu.Lock()
	e.loaded[name] = e.now()
	delete(e.failed, name)
	e.mu.Unlock()
	return nil
}

// fail starts or extends the backoff of name.
func (e *Engine) fail(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f := e.failed[name]
	d := backoffFirst << min(f.n, 10)
	f.n++
	f.until = e.now().Add(min(d, backoffMax))
	e.failed[name] = f
}

// Names returns the secret names on the masking list.
func (e *Engine) Names() []string { return e.eng.Names() }

// ContextBytes is how much text around a read the masker needs to see a
// value cut by the read's edge: the longest pattern it matches, plus a
// line end every few bytes (a value printed on short lines).
func (e *Engine) ContextBytes() int {
	n := e.eng.LongestPattern()
	return n + n/4 + 1
}

// MaskScreen implements Masker. cols follows the terminal's resizes (the
// width the engine was built with is only the start value).
func (e *Engine) MaskScreen(above string, rows []string, cols int) MaskedRows {
	return convMasked(e.eng.MaskGrid(above, rows, cols))
}

// MaskLines implements Masker. Every read is masked with its own context
// whatever cursor the agent asks for.
func (e *Engine) MaskLines(above string, lines []string, wrapped []bool, below string) MaskedRows {
	return convMasked(e.eng.MaskLines(above, lines, wrapped, below))
}

func convMasked(m mask.Masked) MaskedRows {
	out := MaskedRows{Rows: m.Rows, Hits: convHits(m.Hits)}
	for _, ed := range m.Edits {
		out.Edits = append(out.Edits, MaskEdit(ed))
	}
	return out
}

// MaskText implements Masker.
func (e *Engine) MaskText(s string) (string, []MaskHit) {
	out, hits := e.eng.MaskText(s)
	return out, convHits(hits)
}

// AddByName implements Masker: the name must be in secrets.conf; the
// value is resolved, added and zeroed. It never comes back. A name already
// on the list is read again at most every reloadAfter, and a new value is
// added next to the old one (rotation). A source that fails is not run
// again before its backoff ends (repeated keyring prompts). Errors other
// than ErrUnsupported and ErrUnknownSecret are ErrNotMaskable, which says
// nothing about the value (not even that it was too short).
func (e *Engine) AddByName(name string) error {
	now := e.now()
	e.mu.Lock()
	at, done := e.loaded[name]
	f, failing := e.failed[name]
	e.mu.Unlock()
	if done && now.Sub(at) < reloadAfter {
		return nil
	}
	if failing && now.Before(f.until) {
		if done {
			return nil // the value read earlier is still masked
		}
		return ErrNotMaskable
	}
	r, err := e.load()
	if errors.Is(err, os.ErrNotExist) {
		if done {
			return nil
		}
		return ErrUnsupported
	}
	if err != nil {
		e.logf("masking: secrets configuration: %v", err)
		if done {
			return nil
		}
		return ErrNotMaskable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v, err := r.Resolve(ctx, name)
	if errors.Is(err, secretsrc.ErrNotFound) && !done {
		return ErrUnknownSecret
	}
	if err != nil {
		e.logf("masking: %v", err)
		e.fail(name)
		if done {
			return nil
		}
		return ErrNotMaskable
	}
	defer clear(v)
	if err := e.add(name, v, done); err != nil {
		e.fail(name)
		if done {
			return nil
		}
		return ErrNotMaskable
	}
	return nil
}

// Close zeroes and releases the secret list.
func (e *Engine) Close() { e.eng.Close() }

func convHits(hs []mask.Hit) []MaskHit {
	if len(hs) == 0 {
		return nil
	}
	out := make([]MaskHit, len(hs))
	for i, h := range hs {
		out[i] = MaskHit{Name: h.Name, Kind: string(h.Kind), Row: h.Row}
	}
	return out
}
