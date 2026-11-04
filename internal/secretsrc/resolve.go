package secretsrc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Secret is a resolved value. Format and String never print the value.
type Secret struct {
	Name  string
	Value []byte
}

// Zero overwrites the value.
func (s *Secret) Zero() { clear(s.Value) }

// String reports the name only.
func (s Secret) String() string { return "secretsrc.Secret{" + s.Name + "}" }

// GoString is String.
func (s Secret) GoString() string { return s.String() }

// Format makes every fmt verb print String.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(s.String())) }

// Errors. They never carry values.
var (
	ErrNotFound = errors.New("no value found")
	ErrEmpty    = errors.New("source returned an empty value")
	ErrTooLarge = errors.New("value too large")
)

// Runner runs argv without a shell and returns its standard output. It must
// not put the output or the standard error in the error it returns.
type Runner func(ctx context.Context, argv []string) ([]byte, error)

// Options tunes a Resolver. The zero value is usable.
type Options struct {
	// Run runs external programs (secret-tool, pass, commands). Default:
	// ExecRunner.
	Run Runner
	// Timeout bounds each external program (default 15 s; a keyring unlock
	// prompt needs time).
	Timeout time.Duration
}

// MaxValue bounds a value read from any source.
const MaxValue = 64 << 10

// ExecRunner runs argv with os/exec, no shell, stdin from /dev/null, stderr
// discarded, stdout capped at MaxValue. When the context ends (timeout or
// cancel) the program is killed, and so is everything it started: unless
// it runs in the foreground of the caller's terminal (an interactive
// `cotty secrets check`, where Ctrl-C reaches it), it gets its own process
// group and the whole group is killed. WaitDelay bounds the wait for
// output pipes a grandchild may keep open.
func ExecRunner(ctx context.Context, argv []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = nil
	cmd.Stderr = io.Discard
	var out capped
	cmd.Stdout = &out
	cmd.WaitDelay = 2 * time.Second
	group := !inTerminalForeground()
	if group {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	cmd.Cancel = func() error {
		if group && cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return cmd.Process.Kill()
	}
	err := cmd.Run()
	if out.over {
		clear(out.buf.Bytes())
		return nil, ErrTooLarge
	}
	if err != nil {
		clear(out.buf.Bytes())
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s: %w", argv[0], ctx.Err())
		}
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("%s is not installed: %w", argv[0], exec.ErrNotFound)
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%s failed: %s", argv[0], ee.ProcessState.String())
		}
		return nil, fmt.Errorf("%s: %w", argv[0], err)
	}
	return out.buf.Bytes(), nil
}

// inTerminalForeground reports whether this process has a controlling
// terminal and is in its foreground process group: a program it starts
// in its own group could not read the terminal (SIGTTIN) there.
var inTerminalForeground = func() bool {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	fg, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGPGRP)
	return err == nil && fg == unix.Getpgrp()
}

// capped is a writer that keeps at most MaxValue bytes.
type capped struct {
	buf  bytes.Buffer
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > MaxValue {
		c.over = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

// Resolver turns references into values.
type Resolver struct {
	cfg     *Config
	run     Runner
	timeout time.Duration
}

// NewResolver returns a Resolver for cfg.
func NewResolver(cfg *Config, opts Options) *Resolver {
	r := &Resolver{cfg: cfg, run: opts.Run, timeout: opts.Timeout}
	if r.run == nil {
		r.run = ExecRunner
	}
	if r.timeout <= 0 {
		r.timeout = 15 * time.Second
	}
	return r
}

// Resolve returns the value of the configured secret name.
func (r *Resolver) Resolve(ctx context.Context, name string) ([]byte, error) {
	for _, e := range r.cfg.Secrets {
		if e.Name == name {
			v, err := r.Lookup(ctx, e.Ref)
			if err != nil {
				return nil, fmt.Errorf("secret %s (%s): %w", name, e.Ref, err)
			}
			return v, nil
		}
	}
	return nil, fmt.Errorf("secret %s: not in the configuration: %w", name, ErrNotFound)
}

// ResolveAll resolves every configured secret. Failures do not stop the
// others; they come back joined in err, one line per secret.
func (r *Resolver) ResolveAll(ctx context.Context) ([]Secret, error) {
	var out []Secret
	var errs []error
	for _, e := range r.cfg.Secrets {
		v, err := r.Lookup(ctx, e.Ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("secret %s (%s): %w", e.Name, e.Ref, err))
			continue
		}
		out = append(out, Secret{Name: e.Name, Value: v})
	}
	return out, errors.Join(errs...)
}

// Lookup reads the value a reference points at.
func (r *Resolver) Lookup(ctx context.Context, ref Ref) ([]byte, error) {
	var v []byte
	var err error
	switch ref.Scheme {
	case SchemeFile:
		v, err = ReadEnvKey(r.cfg.EnvFile, ref.Arg)
	case SchemeSecretService:
		argv := []string{"secret-tool", "lookup"}
		for _, a := range ref.Attrs {
			argv = append(argv, a[0], a[1])
		}
		v, err = r.exec(ctx, argv)
		v = trimNewline(v)
	case SchemePass:
		v, err = r.exec(ctx, []string{"pass", "show", ref.Arg})
		v = firstLine(v)
	case SchemeCmd:
		argv, ok := r.cfg.Commands[ref.Arg]
		if !ok {
			return nil, fmt.Errorf("no command %q: %w", ref.Arg, ErrNotFound)
		}
		v, err = r.exec(ctx, argv)
		v = trimNewline(v)
	default:
		return nil, fmt.Errorf("unknown source %q", ref.Scheme)
	}
	if err != nil {
		return nil, err
	}
	if len(v) == 0 {
		return nil, ErrEmpty
	}
	return v, nil
}

func (r *Resolver) exec(ctx context.Context, argv []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.run(ctx, argv)
}

// trimNewline drops one trailing "\n" or "\r\n" (what command line tools
// print after the value).
func trimNewline(v []byte) []byte {
	v = bytes.TrimSuffix(v, []byte("\n"))
	return bytes.TrimSuffix(v, []byte("\r"))
}

// firstLine is the pass convention: the password is the first line, the
// rest of the entry holds metadata.
func firstLine(v []byte) []byte {
	if i := bytes.IndexByte(v, '\n'); i >= 0 {
		clear(v[i:])
		v = v[:i]
	}
	return bytes.TrimSuffix(v, []byte("\r"))
}
