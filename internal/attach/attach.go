// Package attach is the person's client (`cotty attach`): raw
// passthrough of the session's output to the person's terminal, the
// person's keystrokes to the session, and a status line drawn by cotty in
// the terminal's last row, with hotkeys behind a prefix (Ctrl-]).
package attach

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/vt"
	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/harden"
	"github.com/openbasalt/cotty/internal/proto"
)

// Prefix is the hotkey prefix byte (Ctrl-]).
const Prefix = 0x1d

// Options configures an attach.
type Options struct {
	Session      string
	Socket       string
	CreatorToken string
	// BrokerPID is the broker's pid when the caller started it (cotty new).
	BrokerPID int
	// Verifier is the guard's broker check (nil: consistency checks only).
	Verifier BrokerVerifier
	// Insecure accepts a -dev-insecure broker (admission without secret).
	Insecure bool
	In       *os.File // the person's terminal input (stdin)
	Out      *os.File // the person's terminal output (stdout)
	Client   string
}

// Result tells how an attach ended.
type Result struct {
	Detached bool
	Code     string // reattach code, after a detach
	Ended    bool
	ExitCode int
}

// Run attaches until detach or session end.
func Run(opts Options) (Result, error) {
	if opts.In == nil {
		opts.In = os.Stdin
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.Client == "" {
		opts.Client = "cotty-attach"
	}
	rows, cols, err := termSize(opts.Out)
	if err != nil {
		return Result{}, fmt.Errorf("the person's terminal: %w", err)
	}
	if rows < 3 || cols < 10 {
		return Result{}, errors.New("terminal too small")
	}
	cl, hello, err := connect(opts, rows-1, cols)
	if err != nil {
		return Result{}, err
	}
	defer cl.Close()
	// From here on this process holds unmasked output and the person's
	// keystrokes: no core dumps, no ptrace by other processes of the user
	// (Connect already did this before the reattach code was typed).
	if err := harden.Process(); err != nil {
		return Result{}, fmt.Errorf("hardening: %w", err)
	}
	restore, err := makeRaw(opts.In)
	if err != nil {
		return Result{}, err
	}
	a := &client{opts: opts, cl: cl, rows: rows, cols: cols, filter: newFilter(rows - 1),
		session: hello.Session, msgs: make(chan string, 8)}
	a.emu = newLocalEmu(cols, rows-1)
	a.status.Shared, a.status.Assurance = hello.Shared, hello.Assurance
	// The terminal is restored on every way out, a panic included (the
	// panic goes on after the restore).
	defer func() {
		r := recover()
		a.cleanup()
		restore()
		if r != nil {
			panic(r)
		}
	}()
	return a.loop()
}

func connect(opts Options, rows, cols int) (*proto.Client, proto.HelloResult, error) {
	return Connect(ConnectOptions{Socket: opts.Socket, Session: opts.Session,
		Hello:        proto.Hello{Role: proto.RolePerson, Client: opts.Client, Rows: rows, Cols: cols},
		CreatorToken: opts.CreatorToken, BrokerPID: opts.BrokerPID, Verifier: opts.Verifier,
		PromptCode: PromptCode, Insecure: opts.Insecure, Harden: harden.Process,
		Waiting: func() {
			fmt.Fprintf(os.Stderr, "cotty: code accepted; waiting for the attached person to approve (^] a in their client)\r\n")
		}})
}

// PromptCode reads the reattach code from the controlling terminal with
// echo off (it is never taken from argv or the environment, where other
// processes of the user could read it).
func PromptCode(wrong bool) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no terminal to ask for the reattach code: %w", err)
	}
	defer tty.Close()
	if wrong {
		fmt.Fprintln(tty, "cotty: wrong code")
	}
	fmt.Fprint(tty, "Reattach code (shown at detach, or with ^] c in an attached client): ")
	old, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if err == nil {
		t := *old
		t.Lflag &^= unix.ECHO
		_ = unix.IoctlSetTermios(int(tty.Fd()), unix.TCSETS, &t)
		defer func() { _ = unix.IoctlSetTermios(int(tty.Fd()), unix.TCSETS, old) }()
	}
	line, err := bufio.NewReader(tty).ReadString('\n')
	fmt.Fprintln(tty)
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

type client struct {
	opts    Options
	cl      *proto.Client
	rows    int
	cols    int
	filter  *filter
	emu     *localEmu
	session string
	status  proto.Status
	ui      uiState
	msgs    chan string
	out     []byte
	in      inputState
	// busySince is when a status draw first had to wait for the terminal
	// to leave a sequence.
	busySince time.Time
}

// inputState follows the person's input across reads.
type inputState struct {
	prefix bool      // the hotkey prefix was typed
	paste  bool      // inside a bracketed paste (between ESC[200~ and ESC[201~)
	tail   [6]byte   // the last input bytes, to find paste markers split across reads
	last   time.Time // when the last input arrived
}

// Bracketed paste markers, sent by the person's terminal around pasted text.
var (
	pasteStart = []byte("\x1b[200~")
	pasteEnd   = []byte("\x1b[201~")
)

// pasteTimeout ends a paste whose end marker never came: a paste arrives
// as one burst, and a lost marker must not disable the hotkeys for good.
const pasteTimeout = 500 * time.Millisecond

// forceRedraw is how long the status line may wait for the terminal to
// leave a sequence (or a synchronized frame) before cotty cancels it.
const forceRedraw = 100 * time.Millisecond

func (a *client) write(p []byte) {
	_, _ = a.opts.Out.Write(p)
}

func (a *client) loop() (Result, error) {
	a.write([]byte("\x1b[0m\x1b[H\x1b[2J\x1b[?2004h"))
	a.write(a.filter.margins())
	input := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := a.opts.In.Read(buf)
			if n > 0 {
				input <- append([]byte(nil), buf[:n]...)
				clear(buf[:n])
			}
			if err != nil {
				close(input)
				return
			}
		}
	}()
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(term)

	redraw := time.NewTimer(time.Hour)
	defer redraw.Stop()
	// schedule asks for a redraw within d. It never postpones a redraw
	// already due earlier, so a steady stream of output cannot starve the
	// status line.
	var due time.Time
	schedule := func(d time.Duration) {
		at := time.Now().Add(d)
		if !due.IsZero() && !at.Before(due) {
			return
		}
		due = at
		redraw.Reset(d)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	_ = a.cl.Call(context.Background(), "state", nil, &a.status)
	schedule(10 * time.Millisecond)
	for {
		select {
		case p, ok := <-a.cl.Data():
			if !ok {
				return Result{}, fmt.Errorf("connection lost: %v", a.cl.Err())
			}
			a.output(p)
			schedule(20 * time.Millisecond)
		case ev, ok := <-a.cl.Events():
			if !ok {
				continue
			}
			switch ev.Event {
			case proto.EventStatus:
				var st proto.Status
				if json.Unmarshal(ev.Data, &st) == nil {
					a.status = st
				}
			case proto.EventAttachRequest:
				a.note("attach request: ^] a allows, ^] x denies", 10*time.Second)
			case proto.EventEnded:
				var e struct {
					ExitCode int `json:"exit_code"`
				}
				_ = json.Unmarshal(ev.Data, &e)
				// Drain the remaining output first.
			drain:
				for {
					select {
					case p, ok := <-a.cl.Data():
						if !ok {
							break drain
						}
						a.emu.write(p)
						a.write(a.filter.Write(p))
					case <-time.After(50 * time.Millisecond):
						break drain
					}
				}
				return Result{Ended: true, ExitCode: e.ExitCode}, nil
			}
			schedule(10 * time.Millisecond)
		case p, ok := <-input:
			if !ok {
				return Result{}, errors.New("terminal input closed")
			}
			if res, done := a.input(p, time.Now()); done {
				return res, nil
			}
			schedule(10 * time.Millisecond)
		case m := <-a.msgs:
			a.note(m, 6*time.Second)
			schedule(5 * time.Millisecond)
		case <-winch:
			if r, c, err := termSize(a.opts.Out); err == nil && r >= 3 && c >= 10 {
				a.rows, a.cols = r, c
				a.emu.resize(c, r-1)
				a.write(a.filter.resize(r - 1))
				go func() {
					_ = a.cl.Call(context.Background(), "resize", map[string]int{"rows": r - 1, "cols": c}, nil)
				}()
			}
			schedule(30 * time.Millisecond)
		case <-tick.C:
			schedule(5 * time.Millisecond)
		case <-term:
			return Result{}, errors.New("terminated")
		case <-redraw.C:
			due = time.Time{}
			if a.redraw(time.Now()) {
				schedule(20 * time.Millisecond)
			}
		}
	}
}

// redraw draws the status line when the terminal is between sequences.
// It reports true when the draw has to wait (try again shortly). After
// forceRedraw of waiting, the program's sequence (or synchronized frame)
// is cancelled and the line drawn anyway, so output that never leaves a
// sequence cannot freeze the lock indicator.
func (a *client) redraw(now time.Time) bool {
	if !a.filter.idle() {
		if a.busySince.IsZero() {
			a.busySince = now
		}
		if now.Sub(a.busySince) < forceRedraw {
			return true
		}
		abort := a.filter.abort()
		a.emu.write([]byte{0x18})
		a.write(abort)
	}
	a.busySince = time.Time{}
	a.drawStatus()
	return false
}

// output passes a chunk of session output to the person's terminal. When
// the chunk may have erased or painted the status row, the status line is
// redrawn in the same write, so a forged row is not left on screen.
func (a *client) output(p []byte) {
	a.emu.write(p)
	out := a.filter.Write(p)
	if a.filter.takeTouched() && a.filter.idle() {
		out = append(out, a.statusBytes()...)
	}
	a.write(out)
}

// input handles one read of the person's input: hotkeys behind the
// prefix, the rest to the session. The prefix is ignored inside a
// bracketed paste, so pasted text cannot trigger hotkeys. Every buffer
// holding keystrokes is wiped on every path.
func (a *client) input(p []byte, now time.Time) (Result, bool) {
	defer clear(p)
	in := &a.in
	if in.paste && now.Sub(in.last) > pasteTimeout {
		in.paste = false
	}
	in.last = now
	var fwd []byte
	flush := func() {
		if len(fwd) > 0 {
			_ = a.cl.SendData(fwd)
		}
		clear(fwd)
		fwd = fwd[:0]
	}
	defer flush()
	for _, c := range p {
		copy(in.tail[:], in.tail[1:])
		in.tail[len(in.tail)-1] = c
		if in.prefix {
			in.prefix = false
			a.ui.prefix = false
			if c == Prefix {
				fwd = append(fwd, Prefix)
				continue
			}
			flush()
			if res, done := a.hotkey(c); done {
				return res, true
			}
			continue
		}
		if c == Prefix && !in.paste {
			in.prefix = true
			a.ui.prefix = true
			continue
		}
		fwd = append(fwd, c)
		marker := false
		switch {
		case bytes.Equal(in.tail[:], pasteStart):
			in.paste, marker = true, true
		case bytes.Equal(in.tail[:], pasteEnd):
			in.paste, marker = false, true
		}
		if marker && !a.filter.paste && len(fwd) >= len(pasteStart) {
			// cotty keeps bracketed paste on; a program that did not ask
			// for it does not get the markers (when they arrived in one
			// read).
			n := len(fwd) - len(pasteStart)
			clear(fwd[n:])
			fwd = fwd[:n]
		}
	}
	in.wipeTail()
	return Result{}, false
}

// wipeTail keeps only the input bytes that may begin a paste marker split
// across reads, so keystrokes do not linger in memory.
func (in *inputState) wipeTail() {
	keep := 0
	for n := len(in.tail) - 1; n > 0; n-- {
		if bytes.Equal(in.tail[len(in.tail)-n:], pasteStart[:n]) {
			keep = n
			break
		}
	}
	clear(in.tail[:len(in.tail)-keep])
}

func (a *client) note(m string, d time.Duration) {
	a.ui.message, a.ui.msgUntil = m, time.Now().Add(d)
}

// call runs a broker op without blocking the loop; errors become notes.
func (a *client) call(op string, args any, ok string) {
	go func() {
		var res map[string]any
		err := a.cl.Call(context.Background(), op, args, &res)
		switch {
		case err != nil:
			a.msgs <- op + ": " + err.Error()
		case ok != "":
			a.msgs <- ok
		}
	}()
}

// hotkey handles the key typed after the prefix.
func (a *client) hotkey(c byte) (Result, bool) {
	st := a.status
	switch c {
	case 'k':
		a.call("keyboard", map[string]bool{"hold": st.Keyboard != proto.KeyboardHeld}, "")
	case 'p':
		a.call("private", map[string]bool{"on": !st.Private}, "")
	case 'y', 'n':
		a.call("confirm", map[string]bool{"accept": c == 'y'}, "")
	case 'a', 'x':
		// Always the oldest request, the one the status line shows.
		r, ok := oldestRequest(st.PendingAttach)
		if !ok {
			a.note("no attach request", 3*time.Second)
			break
		}
		a.call("approve", map[string]any{"request": r.ID, "accept": c == 'a'}, "")
	case 's':
		on := !st.Shared
		msg := "session hidden from agents"
		if on {
			msg = "session shared with agents"
		}
		a.call("share", map[string]bool{"on": on}, msg)
	case 'c':
		go func() {
			var r struct {
				Code string `json:"code"`
			}
			if err := a.cl.Call(context.Background(), "code", nil, &r); err == nil {
				a.msgs <- "reattach code: " + r.Code
			}
		}()
	case 'd':
		var r struct {
			Code string `json:"code"`
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.cl.Call(ctx, "detach", nil, &r)
		return Result{Detached: true, Code: r.Code}, true
	case '?', 'h':
		a.note("^] then: k keyboard, p private, y/n confirm, a/x attach request, s share, c code, d detach, ^] literal", 8*time.Second)
	default:
		a.note("unknown hotkey (^] ? for help)", 3*time.Second)
	}
	return Result{}, false
}

// drawStatus draws the status line in the last row and puts the cursor
// and the program's state back.
func (a *client) drawStatus() {
	a.write(a.statusBytes())
}

// statusBytes renders the status line draw. Before drawing it resets what
// the program may have left that would move or garble the line: origin
// mode, insert mode, the G0 charset and locking shift, the pen. After
// drawing it re-sends the program's scroll margins, restores those modes,
// the charset, the pen and the cursor, and keeps bracketed paste on.
func (a *client) statusBytes() []byte {
	a.ui.session = a.session
	a.ui.now = time.Now()
	line := renderStatus(statusSegments(a.status, a.ui), a.cols)
	x, y, visible := a.emu.cursor()
	return statusDraw(a.filter, line, a.rows, x, y, visible)
}

// statusDraw builds the draw of line in row rows, then puts the cursor at
// x, y (session coordinates, 0-based).
func statusDraw(f *filter, line string, rows, x, y int, visible bool) []byte {
	var b strings.Builder
	b.WriteString("\x1b[?25l\x1b(B\x0f\x1b[4l")
	if f.origin {
		b.WriteString("\x1b[?6l")
	}
	b.WriteString("\x1b[0m\x1b[" + strconv.Itoa(rows) + ";1H")
	b.WriteString(line)
	b.Write(f.curMargins())
	row := y + 1
	if f.origin {
		b.WriteString("\x1b[?6h")
		row = max(1, row-(clamp(f.top, 1, f.rows)-1))
	}
	if f.g0 != nil {
		b.Write(f.g0)
	}
	switch f.shift {
	case 1:
		b.WriteByte(0x0e)
	case 2:
		b.WriteString("\x1bn")
	case 3:
		b.WriteString("\x1bo")
	}
	if f.insert {
		b.WriteString("\x1b[4h")
	}
	b.WriteString("\x1b[?2004h")
	b.Write(f.pen())
	b.WriteString("\x1b[" + strconv.Itoa(row) + ";" + strconv.Itoa(x+1) + "H")
	if visible {
		b.WriteString("\x1b[?25h")
	}
	return []byte(b.String())
}

// cleanup leaves the person's terminal usable.
func (a *client) cleanup() {
	var b strings.Builder
	b.WriteString("\x1b[r\x1b[0m")
	if a.emu.alt() {
		b.WriteString("\x1b[?1049l")
	}
	b.WriteString("\x1b[?1l\x1b>\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?25h")
	b.WriteString("\x1b[" + strconv.Itoa(a.rows) + ";1H\x1b[2K\r\n")
	a.write([]byte(b.String()))
}

// localEmu mirrors the session screen to know where the cursor is when
// the status line has been drawn.
type localEmu struct {
	e *vt.Emulator
	w int
	h int
}

func newLocalEmu(w, h int) *localEmu {
	l := &localEmu{w: w, h: h}
	l.reset()
	return l
}

func (l *localEmu) reset() {
	if l.e != nil {
		stopEmu(l.e)
	}
	l.e = vt.NewEmulator(l.w, l.h)
	l.e.SetScrollbackSize(1)
	go func(e *vt.Emulator) { _, _ = io.Copy(io.Discard, e) }(l.e)
}

func (l *localEmu) write(p []byte) {
	defer func() {
		if recover() != nil {
			l.reset()
		}
	}()
	_, _ = l.e.Write(p)
	l.e.ClearScrollback()
}

func (l *localEmu) resize(w, h int) {
	defer func() {
		if recover() != nil {
			l.reset()
		}
	}()
	l.w, l.h = w, h
	l.e.Resize(w, h)
}

func (l *localEmu) cursor() (int, int, bool) {
	p := l.e.CursorPosition()
	return min(max(p.X, 0), l.w-1), min(max(p.Y, 0), l.h-1), !l.e.CursorHidden()
}

func (l *localEmu) alt() bool { return l.e.IsAltScreen() }

func termSize(f *os.File) (int, int, error) {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0, err
	}
	return int(ws.Row), int(ws.Col), nil
}

// makeRaw puts the terminal in raw mode and returns the restore function.
func makeRaw(f *os.File) (func(), error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	t := *old
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &t); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }, nil
}

// stopEmu ends the emulator's reply reader. It closes the reply pipe
// directly: vt.Emulator.Close writes a field that Read reads without a
// lock (a data race in x/vt v0.1.0).
func stopEmu(e *vt.Emulator) {
	if c, ok := e.InputPipe().(io.Closer); ok {
		_ = c.Close()
	}
}
