// Package broker is the per-session process (`cotty new`): it owns the
// PTY master and the shell, the vt model, input arbitration, secret input
// detection, private mode and the audit trail, and serves the socket
// protocol of docs/protocol.md.
package broker

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/audit"
	"github.com/openbasalt/cotty/internal/confine"
	"github.com/openbasalt/cotty/internal/guard"
	"github.com/openbasalt/cotty/internal/peer"
	"github.com/openbasalt/cotty/internal/proto"
	"github.com/openbasalt/cotty/internal/session"
)

// Timing constants from PLAN section 5.
const (
	personTypingWindow = 1500 * time.Millisecond
	graceWindow        = 50 * time.Millisecond
	pollInterval       = 100 * time.Millisecond
	approvalTimeout    = 60 * time.Second
	codeLockout        = 30 * time.Second
	maxCodeFails       = 3
	maxAgentText       = 4096
	// typeaheadHold is how long person input typed right after an Enter at
	// the shell prompt is held back, so a program that turns echo off to
	// ask for a password (sudo) can do so before the bytes arrive: the
	// kernel echoes a byte when it is received, with the termios of that
	// moment (PLAN 5.2, review S9).
	typeaheadHold = 150 * time.Millisecond
)

// ptyWriteTimeout bounds a write to the PTY (a program that stops reading
// its input must not hang the broker, review S8 and N8). A variable for
// tests.
var ptyWriteTimeout = 2 * time.Second

// Config configures a broker.
type Config struct {
	Name     string
	Dir      string   // runtime directory (session.Dir)
	Shell    []string // argv; empty means $SHELL as a login shell
	Policy   string   // proto.PolicyAuto or proto.PolicyConfirm
	Shared   bool     // visible to agents from the start (--ai)
	Insecure bool     // --dev-insecure: every same-uid peer is a person
	// RequireConfined refuses agent connections whose assurance is weak
	// (--require-confined).
	RequireConfined bool
	// StateDir is the session's state directory
	// ($XDG_STATE_HOME/cotty/sessions/<name>): the shell's HISTFILE and
	// any shell integration state go there, outside every agent project.
	// Empty: the shell's environment is left as it is.
	StateDir string
	Rows     int
	Cols     int
	Env      []string // environment for the shell (default os.Environ())
	// CreatorToken admits the first person (cotty new) once.
	CreatorToken string
	// CountSecretKeys logs the number of keystrokes typed at a secret
	// prompt (off by default, PLAN 5.2).
	CountSecretKeys bool
	AuditPath       string
	Masker          Masker
	Guard           peer.Guard
	// ProtectPTS, when set, asks the guard (layer 3) to let only the
	// broker and the session's own processes open the session pts; it
	// gets the pty master and an O_PATH descriptor of the slave while the
	// pty is still locked (openPTY). The protection lasts while the
	// returned closer is open (guard.Session.Protect).
	ProtectPTS func(ptmx *os.File, pts int) (io.Closer, error)
	// ClaimSocket, when set, asks the guard to keep a socket the broker
	// bound its own (slot 0: the person socket, 1: the agent socket).
	ClaimSocket func(slot int, path string) error
	// PTSException, when set, asks the guard for the running process that
	// opened the session pts through its exception list (pid in the
	// guard's pid namespace, start time in clock ticks, the listed
	// executable path; pid 0 when there is none). Such a program (a
	// pinentry-curses started by gpg-agent) is outside the foreground job,
	// so the lock is lit for it from this answer (guard.Session).
	PTSException   func() (pid int, start uint64, exe string, err error)
	SecretPrograms []string
	Logger         *log.Logger
	// Ready is called once the socket listens.
	Ready func()
}

// Broker is one running session.
type Broker struct {
	ptsGuard   io.Closer // keeps the guard's protection of the pts (layer 3)
	nameLock   *os.File  // flock on paths.Lock, held while the broker runs
	cfg        Config
	paths      session.Paths
	audit      *audit.Log
	masker     Masker
	classifier *peer.Classifier
	model      *Model
	logf       func(string, ...any)

	ptmx *os.File
	cmd  *exec.Cmd
	// shellUTF8: the shell's environment selects a UTF-8 locale, so its
	// line editor reads bytes above 0x7f as characters, not Meta keys
	// (confirmTextOK). Set before the session serves anybody.
	shellUTF8 bool
	ptsPath   string
	ptsRdev   uint64
	ln        *net.UnixListener
	// agentLn serves the agent endpoint (paths.AgentSocket) while the
	// session is shared; nil otherwise. Guarded by mu.
	agentLn *net.UnixListener
	created time.Time

	// ptyIn serializes everything written to the PTY with the decisions
	// taken for it (arbitration, secret state).
	ptyIn sync.Mutex
	// outMu orders model writes and person broadcast against new person
	// registrations (snapshot, then live stream, nothing lost).
	outMu sync.Mutex

	mu      sync.Mutex
	conns   map[*conn]bool
	gen     chan struct{} // closed and replaced on every change
	changed chan struct{} // wakes the notifier

	held                  bool
	lastPersonInput       time.Time
	private               bool
	shared                bool
	requireConfined       bool
	refusedAgents         int
	pending               *proto.Confirmation
	lastConfirm           string // "accepted" or "denied": the last answer to a held line
	agentRequestsKeyboard bool
	agentText             string
	agentActiveAt         time.Time
	lastOutput            time.Time
	outputSeq             int64
	// agentSeq and agentLastOutput are the output counter and time agents
	// see: frozen while private mode is on and while secret input is
	// active, bumped once when either ends (review B1, B2).
	agentSeq        int64
	agentLastOutput time.Time
	// privateState is the agent state when private mode began; agents see
	// it (plus their own side) until private mode ends.
	privateState *proto.State
	// secretTyping is person_typing as agents saw it when secret input
	// began; it does not change while the person types the secret.
	secretTyping bool
	// replies carries the vt model's answers to terminal queries to
	// replyWriter (review S3).
	replies chan []byte
	// enterAtPrompt is when an Enter was last typed at the shell prompt,
	// by the person or the agent (typeaheadHold).
	enterAtPrompt time.Time

	secretRaw      bool // termios says secret right now
	secretReported bool // what agents are told (ended at Enter or restore)
	secretProg     *proto.Program
	secretKeys     int
	// exc is the process outside the session that opened the pts through
	// the guard's exception list and still runs (nil when none): while it
	// runs and echo is off, the lock is lit for it. excAskedAt is when the
	// guard was last asked.
	exc        *excProc
	excAskedAt time.Time
	// holders looks for processes outside the session that hold the pts
	// when the guard cannot tell (outside.go); nil until the shell runs.
	holders *holderScanner
	// excErrLogged and excNSLogged: the guard's pts-exception failures
	// and a pid namespace mismatch are logged once.
	excErrLogged bool
	excNSLogged  bool
	// promptAfterEnter is set when printable output arrives after the
	// Enter that ended a secret prompt (see pollTTY).
	promptAfterEnter bool
	transitionAt     time.Time
	fgPgid           int
	fgAt             time.Time // when fgPgid last changed
	fgDescribedAt    time.Time
	fg               *proto.Program
	fgMembers        []*proto.Program
	// fgStarts are the start times of fgMembers when they were described
	// (a pid that ends and is reused is a new process); fgGen counts the
	// descriptions, so one made outside b.mu is dropped when another came
	// first; fgCheckedAt is the last cheap re-check (jobUnchanged) of a
	// raw group's members.
	fgStarts    map[int]uint64
	fgGen       uint64
	fgCheckedAt time.Time
	// descMu lets one poll at a time re-check the raw foreground group
	// outside b.mu (refreshRawJob).
	descMu     sync.Mutex
	agentPgids map[int]bool
	// The agent window: after an agent Enter, every new foreground
	// process group is marked as started by the agent until the shell is
	// back at its line editor, draws a prompt (OSC 133 A) or the person
	// types Enter at the prompt (review B6).
	agentWindow       bool
	agentWindowAt     time.Time
	agentWindowLeft   bool // the shell left its line editor or a job ran since the Enter
	agentWindowPrompt int64

	creatorToken string
	code         string
	codeSalt     []byte // PBKDF2 salt of the code's proof key
	codeKey      []byte // proof key of the code (proto.CodeKey)
	codeSpent    bool   // the code admitted a person; no proof passes until rotateCode
	// codeReady is closed while b.code is valid; while a spent code is
	// being replaced it is open, and readers of the code wait on it.
	codeReady     chan struct{}
	codeIter      int
	codeLimits    map[codeLimitKey]*codeLimiter // wrong-code backoff per terminal and session
	nconns        atomic.Int32
	pendingAttach map[int64]*attachReq
	nextReq       int64
	sizeOwner     *conn
	ended         bool
	exitCode      int
	hitLogged     map[string]time.Time
	hitLocations  map[string]map[int64]time.Time
	probeFlagged  map[string]time.Time

	// nagentConns counts connections on the agent endpoint, nconns those
	// on the main socket: one cap each (review N11).
	nagentConns atomic.Int32
	// approvalBackoff: terminals whose attach request was just denied
	// (review N11).
	approvalBackoff map[codeLimitKey]time.Time
	// maskGen counts values added to the masking list by term_mask.
	maskGen atomic.Int64
}

type attachReq struct {
	info proto.AttachRequest
	ch   chan bool
}

// New prepares a broker; Run starts it.
func New(cfg Config) (*Broker, error) {
	if !session.ValidName(cfg.Name) {
		return nil, fmt.Errorf("invalid session name %q", cfg.Name)
	}
	if cfg.Policy == "" {
		cfg.Policy = proto.PolicyAuto
	}
	if cfg.Policy != proto.PolicyAuto && cfg.Policy != proto.PolicyConfirm {
		return nil, fmt.Errorf("unknown policy %q", cfg.Policy)
	}
	if cfg.Rows <= 0 || cfg.Cols <= 0 {
		cfg.Rows, cfg.Cols = 24, 80
	}
	if cfg.Masker == nil {
		cfg.Masker = NoMask{}
	}
	if cfg.Guard == nil {
		cfg.Guard = peer.NoGuard{}
	}
	if cfg.SecretPrograms == nil {
		cfg.SecretPrograms = LoadSecretPrograms()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	b := &Broker{
		cfg:             cfg,
		paths:           session.PathsFor(cfg.Dir, cfg.Name),
		masker:          cfg.Masker,
		logf:            cfg.Logger.Printf,
		conns:           map[*conn]bool{},
		gen:             make(chan struct{}),
		changed:         make(chan struct{}, 1),
		shared:          cfg.Shared,
		requireConfined: cfg.RequireConfined,
		creatorToken:    cfg.CreatorToken,
		pendingAttach:   map[int64]*attachReq{},
		approvalBackoff: map[codeLimitKey]time.Time{},
		agentPgids:      map[int]bool{},
		hitLogged:       map[string]time.Time{},
		hitLocations:    map[string]map[int64]time.Time{},
		probeFlagged:    map[string]time.Time{},
		replies:         make(chan []byte, 64),
		created:         time.Now(),
		secretProg:      nil,
	}
	if cfg.AuditPath != "" {
		b.audit = audit.Open(cfg.AuditPath)
	}
	b.code, b.codeSalt, b.codeKey = newCodeState()
	b.codeReady = make(chan struct{})
	close(b.codeReady)
	b.codeIter = proto.CodeKDFIterations
	b.codeLimits = map[codeLimitKey]*codeLimiter{}
	b.classifier = peer.Self()
	b.classifier.Guard = cfg.Guard
	b.classifier.SeccompFilter = confine.SeccompSupported()
	b.classifier.LandlockABI = confine.LandlockABI()
	b.classifier.Insecure = cfg.Insecure
	dir, name := cfg.Dir, cfg.Name
	b.classifier.OtherTTYs = func() []uint64 { return session.OtherTTYs(dir, name) }
	b.model = NewModel(cfg.Rows, cfg.Cols, b.emulatorReply)
	return b, nil
}

// Run starts the shell and serves until the shell exits. It returns the
// shell's exit code.
func (b *Broker) Run() (int, error) {
	// The name is claimed before the shell starts: a second broker of a
	// live session's name stops here, without running the person's login
	// files a second time (review A4).
	if err := b.claimName(); err != nil {
		return 1, err
	}
	if err := b.startShell(); err != nil {
		return 1, err
	}
	if err := b.pollablePTY(); err != nil {
		_ = b.cmd.Process.Kill()
		return 1, err
	}
	if err := b.listen(); err != nil {
		_ = b.cmd.Process.Kill()
		return 1, err
	}
	b.auditf(audit.Record{Event: audit.SessionStart, Subject: audit.Subject{Role: "broker", PID: os.Getpid()},
		Data: map[string]any{"shell": filepath.Base(b.cmd.Path), "policy": b.cfg.Policy, "shared": b.shared,
			"rows": b.cfg.Rows, "cols": b.cfg.Cols, "insecure": b.cfg.Insecure}})
	if b.cfg.Ready != nil {
		b.cfg.Ready()
	}
	go b.acceptLoop()
	go b.replyWriter()
	go b.notifier()
	go b.pollLoop()
	b.outputLoop()
	err := b.cmd.Wait()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
	}
	b.finish(code)
	return code, nil
}

func (b *Broker) startShell() error {
	argv := b.cfg.Shell
	login := false
	if len(argv) == 0 {
		sh := os.Getenv("SHELL")
		if sh == "" {
			sh = "/bin/bash"
		}
		argv = []string{sh}
		login = true
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	// The pts is protected before anybody can open it (it is still
	// locked) and before the shell starts: from then on only this broker
	// and the session's own processes can open it.
	ptmx, tty, g, err := openPTY(b.cfg.Rows, b.cfg.Cols, b.cfg.ProtectPTS)
	if err != nil {
		return err
	}
	b.ptsGuard = g
	env := b.cfg.Env
	if env == nil {
		env = os.Environ()
	}
	env = withEnv(env, "COTTY_SESSION", b.cfg.Name)
	if b.cfg.StateDir != "" {
		// History and shell integration state stay in the session's own
		// state directory, never in a directory an agent may write (its
		// project), whatever the working directory is.
		env = withEnv(env, "HISTFILE", filepath.Join(b.cfg.StateDir, "history"))
		env = withEnv(env, "COTTY_STATE_DIR", b.cfg.StateDir)
	}
	if !hasEnv(env, "TERM") {
		env = withEnv(env, "TERM", "xterm-256color")
	}
	cmd := &exec.Cmd{Path: path, Args: append([]string(nil), argv...), Env: env,
		Stdin: tty, Stdout: tty, Stderr: tty,
		SysProcAttr: &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}}
	if login {
		cmd.Args[0] = "-" + filepath.Base(path)
	}
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	if wd, err := os.Getwd(); err == nil {
		cmd.Dir = wd
	}
	if err := cmd.Start(); err != nil {
		_ = ptmx.Close()
		_ = tty.Close()
		return err
	}
	b.ptsPath = tty.Name()
	var st syscall.Stat_t
	if syscall.Fstat(int(tty.Fd()), &st) == nil {
		b.ptsRdev = st.Rdev
		b.holders = newHolderScanner(uint64(st.Dev), uint64(st.Ino))
	}
	_ = tty.Close()
	b.mu.Lock()
	b.ptmx, b.cmd = ptmx, cmd
	b.shellUTF8 = localeIsUTF8(env)
	b.mu.Unlock()
	b.classifier.ShellPID = cmd.Process.Pid
	b.classifier.ShellSID = cmd.Process.Pid // the shell leads its session (Setsid)
	b.classifier.SessionTTY = b.ptsRdev
	return nil
}

func withEnv(env []string, k, v string) []string {
	out := env[:0:0]
	for _, e := range env {
		if !strings.HasPrefix(e, k+"=") {
			out = append(out, e)
		}
	}
	return append(out, k+"="+v)
}

func hasEnv(env []string, k string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, k+"=") && len(e) > len(k)+1 {
			return true
		}
	}
	return false
}

// claimName makes this broker the only one of its session name. The
// lock is held for the broker's lifetime (the kernel drops it when the
// process ends), and a socket that still answers is never removed (review
// N1: a second broker with the same name replaced the session's socket).
func (b *Broker) claimName() error {
	if err := b.lockName(); err != nil {
		return err
	}
	if c, err := net.DialTimeout("unix", b.paths.Socket, time.Second); err == nil {
		_ = c.Close()
		return fmt.Errorf("session %q already exists (its socket answers)", b.cfg.Name)
	}
	return nil
}

// listen serves the session socket (after claimName).
func (b *Broker) listen() error {
	if b.nameLock == nil {
		return errors.New("session name not claimed")
	}
	_ = os.Remove(b.paths.Socket)
	old := syscall.Umask(0o177)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: b.paths.Socket, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return err
	}
	ln.SetUnlinkOnClose(true)
	b.ln = ln
	if b.cfg.ClaimSocket != nil {
		if err := b.cfg.ClaimSocket(0, b.paths.Socket); err != nil {
			_ = ln.Close()
			return fmt.Errorf("cotty-guard refused to keep the session socket: %w", err)
		}
	}
	if b.shared {
		b.mu.Lock()
		err := b.openAgentLocked()
		b.mu.Unlock()
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("agent endpoint: %w", err)
		}
	}
	var start uint64
	if st, err := peer.ReadStat(os.Getpid()); err == nil {
		start = st.StartTime
	}
	return session.WriteMeta(b.paths.Meta, session.Meta{Name: b.cfg.Name, BrokerPID: os.Getpid(), BrokerStart: start,
		PTS: b.ptsPath, PTSRdev: b.ptsRdev, Created: b.created.UTC().Format(time.RFC3339)})
}

// lockName takes the session name's lock (paths.Lock) for the broker's
// lifetime; another live broker holding it means the session exists.
func (b *Broker) lockName() error {
	fd, err := syscall.Open(b.paths.Lock, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("session lock: %w", err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = syscall.Close(fd)
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("session %q already exists (another broker holds its lock)", b.cfg.Name)
		}
		return fmt.Errorf("session lock: %w", err)
	}
	b.nameLock = os.NewFile(uintptr(fd), b.paths.Lock)
	return nil
}

func (b *Broker) acceptLoop() {
	for {
		c, err := b.ln.AcceptUnix()
		if err != nil {
			return
		}
		go b.serve(c, false)
	}
}

// openAgentLocked starts serving the agent endpoint,
// $XDG_RUNTIME_DIR/cotty/agent/<name>.sock. Connections there may only
// take the agent and info roles, whatever the peer is: a confined agent
// sees this directory and nothing else of the runtime directory.
func (b *Broker) openAgentLocked() error {
	if b.agentLn != nil {
		return nil
	}
	if _, err := session.AgentDir(b.cfg.Dir); err != nil {
		return err
	}
	path := b.paths.AgentSocket
	// A stale socket of an earlier broker of this name: cotty new checked
	// that no live broker answers on the main socket.
	_ = os.Remove(path)
	old := syscall.Umask(0o177)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return err
	}
	ln.SetUnlinkOnClose(true)
	if b.cfg.ClaimSocket != nil {
		if err := b.cfg.ClaimSocket(1, path); err != nil {
			_ = ln.Close()
			return fmt.Errorf("cotty-guard refused to keep the agent socket: %w", err)
		}
	}
	b.agentLn = ln
	go func() {
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			go b.serve(c, true)
		}
	}()
	return nil
}

// closeAgentLocked stops serving the agent endpoint and removes it, so
// agents no longer see the session.
func (b *Broker) closeAgentLocked() {
	if b.agentLn == nil {
		return
	}
	_ = b.agentLn.Close()
	b.agentLn = nil
}

// outputLoop copies program output to the model and the persons.
func (b *Broker) outputLoop() {
	buf := make([]byte, 32<<10)
	for {
		n, err := b.ptmx.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			b.pollTTY()
			b.outMu.Lock()
			if err := b.model.Write(chunk); err != nil {
				b.logf("%v", err)
			}
			b.broadcastData(chunk)
			b.outMu.Unlock()
			b.mu.Lock()
			b.lastOutput = time.Now()
			b.outputSeq++
			if !b.private && !b.secretRaw {
				b.agentSeq++
				b.agentLastOutput = b.lastOutput
			}
			if b.secretRaw && !b.secretReported && hasPrintable(chunk) {
				b.promptAfterEnter = true
			}
			b.mu.Unlock()
			b.pollTTY()
			b.bump()
		}
		if err != nil {
			return
		}
	}
}

// pollLoop re-reads the PTY state on a timer, so a prompt that ends
// without output (termios restored) is noticed.
func (b *Broker) pollLoop() {
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for range t.C {
		b.mu.Lock()
		ended := b.ended
		b.mu.Unlock()
		if ended {
			return
		}
		b.pollTTY()
	}
}

// pollTTY reads termios and the foreground group and updates the secret
// state. It returns whether secret input is active now.
func (b *Broker) pollTTY() bool { return b.pollTTYFor(false) }

// pollTTYFor is pollTTY; input says the person's keys are about to be
// written, so an exception use is asked about without delay.
func (b *Broker) pollTTYFor(input bool) bool {
	var st ttyState
	b.ptyControl(func(fd int) { st = readTTY(fd) })
	b.refreshException(st, input)
	return b.observeTTY(st)
}

// observeTTY applies one PTY reading: the raw-mode re-check of the
// foreground group runs first, outside b.mu, then the secret rules.
func (b *Broker) observeTTY(st ttyState) bool {
	b.refreshRawJob(st)
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.applyTTYLocked(st)
}

// excAskEvery is the shortest time between two questions to the guard
// about an exception use while echo is off and none is known, after
// output (a pinentry draws its dialog as soon as it opened the pts); an
// idle session asks nothing. Person input always asks first, at most
// every excAskInput, so no key reaches a program that opened the pts
// through an exception before the lock is lit for it.
const (
	excAskEvery = 250 * time.Millisecond
	excAskInput = 10 * time.Millisecond
)

// excProc is a process outside the session that reads the session pts:
// one that opened it through the guard's exception list (job 0), or, when
// the guard cannot tell, one found holding it while the process group
// job had the terminal with echo off (outside.go).
type excProc struct {
	pid   int
	start uint64
	job   int
	prog  *proto.Program
}

// refreshException keeps b.exc current: a known process is dropped once
// it exits (read from /proc, no question to the guard), or, for one found
// by the scan, once its job no longer has the terminal; while none is
// known and the terminal's echo is off (every password reader turns it
// off) the guard is asked. When the guard cannot answer (no guard, its
// daemon is down or too old), and a job runs with echo off that no prompt
// rule explains, the broker scans for a holder itself. The question and
// the scan run outside b.mu (guard requests never run under the broker's
// lock).
func (b *Broker) refreshException(st ttyState, input bool) {
	b.mu.Lock()
	cur := b.exc
	since := time.Since(b.excAskedAt)
	due := st.ok && !st.echo && cur == nil &&
		(input && since >= excAskInput || b.lastOutput.After(b.excAskedAt) && since >= excAskEvery)
	if due {
		b.excAskedAt = time.Now()
	}
	// The shell at its line editor turns echo off at every prompt: only a
	// running job, with no prompt detected, leaves echo off unexplained.
	shell, sid := b.classifier.ShellPID, b.classifier.ShellSID
	job := st.pgid > 0 && st.pgid != shell && !b.secretRaw
	holders := b.holders
	b.mu.Unlock()
	if cur != nil {
		if !procStarted(cur.pid, cur.start) || cur.job != 0 && st.ok && st.pgid != cur.job {
			b.mu.Lock()
			if b.exc == cur {
				b.exc = nil
			}
			b.mu.Unlock()
		}
		return
	}
	if !due {
		return
	}
	if b.cfg.PTSException != nil {
		pid, start, exe, err := b.cfg.PTSException()
		if err == nil {
			if pid <= 0 {
				return
			}
			if !procStarted(pid, start) {
				b.noteForeignPID(pid)
				return
			}
			p := exceptionProgram(pid, exe, os.Getuid())
			agent := sessionAncestorPgids(pid, sid)
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.exc == nil {
				p.AgentStarted = b.anyAgentPgidLocked(agent)
				b.exc = &excProc{pid: pid, start: start, prog: p}
			}
			return
		}
		b.noteExceptionErr(err)
	}
	if !job || holders == nil {
		return
	}
	h, ok := holders.scan(input, inSessionOf(os.Getpid(), sid))
	if !ok {
		return
	}
	p := outsideProgram(h.pid, os.Getuid())
	b.mu.Lock()
	defer b.mu.Unlock()
	// st is the reading the caller is about to apply (the job that has
	// the terminal now), so the holder is tied to it even before
	// applyTTYLocked records the group.
	if b.exc == nil {
		b.exc = &excProc{pid: h.pid, start: h.start, job: st.pgid, prog: p}
		b.logf("process %d (%s, parent %s) outside the session holds the session terminal while %s reads with echo off: lock lit",
			h.pid, p.Name, p.Parent, jobName(b.fg))
	}
}

// anyAgentPgidLocked tells whether one of the process groups is a job
// the agent started.
func (b *Broker) anyAgentPgidLocked(pgids []int) bool {
	for _, pg := range pgids {
		if b.agentPgids[pg] {
			return true
		}
	}
	return false
}

func jobName(p *proto.Program) string {
	if p == nil || p.Name == "" {
		return "the foreground job"
	}
	return p.Name
}

// noteExceptionErr logs, once, why the guard could not answer
// pts-exception (no connection is the ordinary state without a guard and
// is not logged). The broker then watches the pts itself.
func (b *Broker) noteExceptionErr(err error) {
	if errors.Is(err, guard.ErrNotRunning) {
		return
	}
	b.mu.Lock()
	logged := b.excErrLogged
	b.excErrLogged = true
	b.mu.Unlock()
	if logged {
		return
	}
	if strings.Contains(err.Error(), "unknown operation") {
		b.logf("cotty-guard does not know pts-exception (an older daemon): exception prompts are watched by the broker's own scan (logged once)")
		return
	}
	b.logf("cotty-guard pts-exception: %v (logged once)", err)
}

// noteForeignPID logs, once, that the guard named a process this broker
// cannot see as that process: the guard answers pids in its own pid
// namespace, so a broker in another one never lights the lock for an
// exception prompt (it fails silent, the program still reads the keys).
func (b *Broker) noteForeignPID(pid int) {
	if !nestedPIDNamespace() {
		return // the process just exited
	}
	b.mu.Lock()
	logged := b.excNSLogged
	b.excNSLogged = true
	b.mu.Unlock()
	if !logged {
		b.logf("cotty-guard named process %d of its pid namespace for an exception use; this broker runs in another pid namespace and cannot light the lock for it (logged once)", pid)
	}
}

// exceptionProgram describes an exception process for the lock: judged
// like a foreground member, marked as an exception, named after the
// listed executable when its own cannot be read, and with its parent
// (`LOCK pinentry-curses (exception, for gpg-agent)`): the listed program
// hands what it reads to whoever started it.
func exceptionProgram(pid int, exe string, uid int) *proto.Program {
	p := describeProgram(pid, uid)
	if p == nil {
		p = &proto.Program{PID: pid, Trust: proto.TrustOther}
	}
	if p.Exe == "" && exe != "" {
		p.Exe = exe
		p.Name = filepath.Base(exe)
	}
	p.Exception = true
	p.Parent = parentName(pid, uid)
	return p
}

// describeEvery is the shortest time between two descriptions (or cheap
// re-checks) of the same foreground group while it is young or reads in
// raw mode with echo off.
const describeEvery = 50 * time.Millisecond

// fullDescribeEvery is the longest a raw, echo-off foreground group goes
// without a full description (a walk of /proc) while the cheap re-check
// sees no change. The re-check follows the members' children and execs,
// so this only bounds how long a process that joins the group without
// being a member's child (setpgid from elsewhere in the session) goes
// unjudged.
const fullDescribeEvery = 5 * time.Second

// refreshRawJob keeps the member list fresh while the terminal is raw
// with echo off (review T3: a script or Makefile can exec sudo-rs long
// after its group took the terminal, and the raw-mode rules judge the
// members). Readline and zle keep that mode at every idle prompt, so this
// runs for most of a session: the members are re-checked cheaply
// (jobUnchanged, a few /proc files per member) and /proc is walked only
// when they changed, or every fullDescribeEvery; all of it outside b.mu,
// so keys and agent operations do not wait for it (review round 4).
//
// While a raw-mode prompt is detected (secretRaw) the members are never
// described again (a failed read must not unlock); members that have
// ended, or whose pid now belongs to another process, are dropped, so a
// short-lived helper (newuidmap, fusermount3) does not keep the lock on
// after it exits.
func (b *Broker) refreshRawJob(st ttyState) {
	if !st.ok || st.echo || st.icanon {
		return
	}
	if !b.descMu.TryLock() {
		return // another poll is re-checking right now
	}
	defer b.descMu.Unlock()
	b.mu.Lock()
	if st.pgid != b.fgPgid || b.fg == nil || time.Since(b.fgCheckedAt) < describeEvery {
		b.mu.Unlock()
		return
	}
	gen, members, starts, secret := b.fgGen, b.fgMembers, b.fgStarts, b.secretRaw
	full := time.Since(b.fgDescribedAt) >= fullDescribeEvery
	shell := b.classifier.ShellPID
	b.fgCheckedAt = time.Now()
	b.mu.Unlock()

	if secret {
		kept := liveMembers(members, starts)
		if len(kept) == len(members) {
			return
		}
		b.mu.Lock()
		if b.fgGen == gen {
			b.fgMembers = kept
			b.fgGen++
		}
		b.mu.Unlock()
		return
	}
	if !full && jobUnchanged(st.pgid, members, starts) {
		return
	}
	fg, mem := describeGroup(st.pgid, shell, os.Getuid())
	ms := memberStarts(mem)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fgGen != gen || b.fgPgid != st.pgid {
		return // a newer description is in place
	}
	was := b.fg
	b.setJobLocked(st.pgid, fg, mem, ms)
	if !sameJob(was, b.fg) {
		b.bumpLocked()
	}
}

// setJobLocked installs a description of the foreground group.
func (b *Broker) setJobLocked(pgid int, fg *proto.Program, members []*proto.Program, starts map[int]uint64) {
	b.fg, b.fgMembers, b.fgStarts = fg, members, starts
	b.fgDescribedAt = time.Now()
	b.fgCheckedAt = b.fgDescribedAt
	b.fgGen++
	if b.fg != nil {
		b.fg.AgentStarted = b.agentPgids[pgid]
	}
}

// applyTTYLocked updates the foreground and secret state from one PTY
// reading.
func (b *Broker) applyTTYLocked(st ttyState) bool {
	changed := false
	shell := b.classifier.ShellPID
	b.agentWindowLocked(st)
	// The description is refreshed when the group changes, while it is
	// young (a member may be between fork and exec, still named like its
	// parent shell, and pipeline members join) and whenever a secret prompt
	// starts. While the terminal is raw with echo off, refreshRawJob keeps
	// the members fresh before this runs (review T3).
	since := time.Since(b.fgDescribedAt)
	young := time.Since(b.fgAt) < 500*time.Millisecond && since >= describeEvery
	// A program outside the session that opened the pts through the
	// guard's exception list reads the keys while echo is off.
	excOn := b.exc != nil && st.ok && !st.echo && (b.exc.job == 0 || st.pgid == b.exc.job)
	startingSecret := !b.secretRaw && (excOn || isSecret(st, b.fgMembers, b.cfg.SecretPrograms))
	if st.pgid != b.fgPgid || b.fg == nil || young || startingSecret {
		if st.pgid != b.fgPgid {
			b.fgAt = time.Now()
		}
		was, wasPgid := b.fg, b.fgPgid
		b.fgPgid = st.pgid
		fg, members := describeGroup(st.pgid, shell, os.Getuid())
		b.setJobLocked(st.pgid, fg, members, memberStarts(members))
		changed = changed || st.pgid != wasPgid || young || startingSecret || !sameJob(was, b.fg)
	}
	secret := excOn || isSecret(st, b.fgMembers, b.cfg.SecretPrograms)
	if secret && b.secretRaw && excOn && b.secretProg != nil && !b.secretProg.Exception && !b.secretProg.Outside {
		// The prompt was lit for the foreground job; the reader is the
		// exception program: name it.
		p := *b.exc.prog
		b.secretProg = &p
		changed = true
	}
	if secret && b.secretRaw && !b.secretReported && b.promptAfterEnter {
		// Echo stayed off after the Enter and the program printed again:
		// a second prompt ("Verifying - Password:", "Sorry, try again").
		b.secretReported = true
		b.promptAfterEnter = false
		changed = true
		b.auditLocked(audit.Record{Event: audit.SecretStart, Data: map[string]any{
			"program": b.secretProg.Name, "exe": b.secretProg.Exe, "trust": b.secretProg.Trust,
			"agent_started": b.secretProg.AgentStarted, "again": true}})
	}
	if secret != b.secretRaw {
		b.secretRaw = secret
		b.transitionAt = time.Now()
		changed = true
		// What the screen shows during the prompt (a mark per key) is
		// hidden from agents like private mode (the B2 pwfeedback residual).
		b.model.SetSecretInput(secret)
		if secret {
			b.secretReported = true
			b.secretKeys = 0
			b.secretTyping = time.Since(b.lastPersonInput) < personTypingWindow
			switch {
			case excOn:
				p := *b.exc.prog
				b.secretProg = &p
			case b.fg != nil:
				p := *b.fg
				b.secretProg = &p
			default:
				b.secretProg = &proto.Program{Trust: proto.TrustOther}
			}
			b.auditLocked(audit.Record{Event: audit.SecretStart, Data: map[string]any{
				"program": b.secretProg.Name, "exe": b.secretProg.Exe, "trust": b.secretProg.Trust,
				"agent_started": b.secretProg.AgentStarted, "exception": b.secretProg.Exception,
				"outside": b.secretProg.Outside, "parent": b.secretProg.Parent}})
		} else {
			b.endSecretLocked("termios")
			b.secretProg = nil
			// What happened on screen during the prompt reaches agents as one
			// change, not as one event per keystroke.
			if !b.private {
				b.agentSeq++
				b.agentLastOutput = time.Now()
			}
		}
	}
	if changed {
		b.bumpLocked()
	}
	return secret
}

// sameJob reports whether two descriptions of the foreground job show
// the same thing.
func sameJob(a, b *proto.Program) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.PID == b.PID && a.Name == b.Name && a.Exe == b.Exe && a.Trust == b.Trust &&
		a.AgentStarted == b.AgentStarted && a.SetuidRoot == b.SetuidRoot
}

// openAgentWindowLocked starts marking new foreground jobs as started by
// the agent (an agent line was entered).
func (b *Broker) openAgentWindowLocked() {
	b.agentWindow = true
	b.agentWindowAt = time.Now()
	b.agentWindowLeft = false
	b.agentWindowPrompt = b.model.PromptMarks()
	// Forget groups that no longer exist, so a reused pgid of a person's
	// job is not taken for the agent's.
	for pg := range b.agentPgids {
		if pg == b.fgPgid {
			continue
		}
		if _, err := os.Stat("/proc/" + strconv.Itoa(pg)); err != nil {
			delete(b.agentPgids, pg)
		}
	}
}

// agentWindowLocked marks the foreground group as agent-started while the
// agent window is open, and closes the window once the shell is back at
// its prompt.
func (b *Broker) agentWindowLocked(st ttyState) {
	if !b.agentWindow || !st.ok || st.pgid <= 0 {
		return
	}
	shell := b.classifier.ShellPID
	if st.pgid != shell {
		// Every group that takes the terminal before the shell is back,
		// whatever ran before it in the same command line (`sleep 3; ...`).
		b.agentPgids[st.pgid] = true
		b.agentWindowLeft = true
		return
	}
	if st.icanon {
		// The shell runs the line (its line editor is off), between jobs
		// or running a builtin.
		b.agentWindowLeft = true
		return
	}
	if b.agentWindowLeft || b.model.PromptMarks() > b.agentWindowPrompt {
		// Back at the line editor (or a new prompt was drawn).
		b.agentWindow = false
	}
}

// hasPrintable reports whether output contains a visible character
// outside escape sequences (roughly: a byte above space that is not part
// of a CSI or OSC introducer).
func hasPrintable(p []byte) bool {
	esc := false
	for _, c := range p {
		switch {
		case c == 0x1b:
			esc = true
		case esc && c >= 0x40 && c <= 0x7e:
			esc = false
		case !esc && c > ' ' && c != 0x7f:
			return true
		}
	}
	return false
}

// endSecretLocked marks the secret prompt as ended for agents.
func (b *Broker) endSecretLocked(reason string) {
	if !b.secretReported {
		return
	}
	b.secretReported = false
	data := map[string]any{"reason": reason}
	if b.secretProg != nil {
		data["program"] = b.secretProg.Name
	}
	if b.cfg.CountSecretKeys {
		data["keystrokes"] = b.secretKeys
	}
	b.auditLocked(audit.Record{Event: audit.SecretEnd, Data: data})
}

// personInput forwards a batch of person keystrokes. Bytes typed while
// secret input is active go to the PTY and nowhere else, and the buffer
// is wiped afterwards.
func (b *Broker) personInput(p []byte) {
	b.ptyIn.Lock()
	defer b.ptyIn.Unlock()
	for len(p) > 0 {
		p = b.personChunk(p)
	}
}

// personChunk writes the person's bytes up to and including the first
// Enter typed at the shell prompt (or all of them) and returns the rest.
// Called with ptyIn held.
func (b *Broker) personChunk(p []byte) []byte {
	b.holdTypeahead()
	secret := b.pollTTYFor(true)
	b.mu.Lock()
	wait := graceWindow - time.Since(b.transitionAt)
	b.mu.Unlock()
	if wait > 0 {
		// A transition just happened: give the program time to finish
		// switching and classify with the settled state.
		time.Sleep(wait)
		secret = b.pollTTYFor(true)
	}
	b.mu.Lock()
	atPrompt := b.atPromptLocked(secret)
	b.mu.Unlock()
	chunk, rest := p, []byte(nil)
	if atPrompt {
		if i := indexEnter(p); i >= 0 && i < len(p)-1 {
			chunk, rest = p[:i+1], p[i+1:]
		}
	}
	b.writePTY(chunk)
	b.mu.Lock()
	b.lastPersonInput = time.Now()
	enter := indexEnter(chunk) >= 0
	if secret {
		b.secretKeys += len(chunk)
		if enter {
			b.endSecretLocked("enter")
			b.promptAfterEnter = false
		}
	}
	if atPrompt && enter {
		// The person runs a command: what starts now is the person's.
		b.agentWindow = false
		b.enterAtPrompt = time.Now()
	}
	b.mu.Unlock()
	if secret {
		clear(chunk)
	}
	b.bump()
	return rest
}

// holdTypeahead waits, after an Enter typed at the shell prompt (by the
// person, by the agent, or a held agent line the person accepted), until
// typeaheadHold has passed or a secret prompt is detected,
// so keys typed ahead of a password prompt are not echoed (review S9).
// Programs slower than typeaheadHold to turn echo off still see typeahead
// echoed (docs/broker.md).
func (b *Broker) holdTypeahead() {
	b.mu.Lock()
	at := b.enterAtPrompt
	b.enterAtPrompt = time.Time{}
	b.mu.Unlock()
	if at.IsZero() {
		return
	}
	for deadline := at.Add(typeaheadHold); time.Now().Before(deadline); {
		if b.pollTTY() {
			return
		}
		time.Sleep(min(5*time.Millisecond, time.Until(deadline)))
	}
}

// atPromptLocked reports whether the shell is the foreground job and no
// secret prompt is active: an Enter now runs a command line.
func (b *Broker) atPromptLocked(secret bool) bool {
	return !secret && b.fgPgid == b.classifier.ShellPID && b.fgPgid > 0
}

func indexEnter(p []byte) int {
	for i, c := range p {
		if c == '\r' || c == '\n' {
			return i
		}
	}
	return -1
}

// pollablePTY puts the PTY master in non-blocking mode under Go's poller,
// so writePTY's deadline works: (*os.File).Fd, which pty.Open and
// pty.Setsize call, switches a file to blocking mode for good, and a
// blocking write ignores deadlines (review N8). The master is replaced
// by a non-blocking duplicate; from here on its descriptor is only
// reached through ptyControl, never Fd.
func (b *Broker) pollablePTY() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, err := pollableFile(b.ptmx)
	if err != nil {
		return fmt.Errorf("pty: %w", err)
	}
	b.ptmx = f
	return nil
}

// pollableFile returns a non-blocking duplicate of f registered with the
// poller, and closes f.
func pollableFile(f *os.File) (*os.File, error) {
	nfd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		_ = unix.Close(nfd)
		return nil, err
	}
	nf := os.NewFile(uintptr(nfd), f.Name())
	_ = f.Close()
	if err := nf.SetWriteDeadline(time.Time{}); err != nil {
		_ = nf.Close()
		return nil, fmt.Errorf("the PTY master is not pollable: %w", err)
	}
	return nf, nil
}

// ptyControl runs fn with the PTY master's descriptor, without the
// blocking mode switch of (*os.File).Fd. It does nothing without a PTY.
func (b *Broker) ptyControl(fn func(fd int)) {
	if b.ptmx == nil {
		return
	}
	rc, err := b.ptmx.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) { fn(int(fd)) })
}

// setPTYSize sets the PTY's window size (the kernel signals the
// foreground job).
func (b *Broker) setPTYSize(rows, cols int) {
	b.ptyControl(func(fd int) {
		_ = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(rows), Col: uint16(cols)})
	})
}

// writePTY writes to the PTY with a deadline (a real one: the master is
// non-blocking, see pollablePTY). Called with ptyIn held, never with b.mu
// held.
func (b *Broker) writePTY(p []byte) (int, error) {
	_ = b.ptmx.SetWriteDeadline(time.Now().Add(ptyWriteTimeout))
	n, err := b.ptmx.Write(p)
	_ = b.ptmx.SetWriteDeadline(time.Time{})
	return n, err
}

// emulatorReply takes the vt model's answers to terminal queries (DA,
// DSR). It is called from the model's reader goroutine while the model may
// be locked, so it never blocks and never takes a broker lock (review S3):
// replyWriter forwards them. The model answers every query, also while a
// person is attached; the attach client keeps those queries from the
// person's terminal, so its replies cannot enter the session as person
// input (review S2).
func (b *Broker) emulatorReply(p []byte) {
	select {
	case b.replies <- p:
	default:
		// A flood of queries: drop the excess answers.
	}
}

// replyWriter writes the model's answers to the PTY.
func (b *Broker) replyWriter() {
	for p := range b.replies {
		b.mu.Lock()
		ended := b.ended
		b.mu.Unlock()
		if ended {
			return
		}
		b.ptyIn.Lock()
		_, _ = b.writePTY(p)
		b.ptyIn.Unlock()
	}
}

// agentDenied returns the arbitration error for agent input, or nil.
func (b *Broker) agentDeniedLocked(secret bool) *proto.Error {
	switch {
	case b.private:
		return proto.Errorf(proto.ErrPrivateMode, "the person turned on private mode")
	case secret || b.secretRaw:
		return proto.Errorf(proto.ErrSecretInputActive, "a secret prompt is active; wait for secret_ended")
	case b.held:
		return proto.Errorf(proto.ErrKeyboardHeld, "the person holds the keyboard")
	case time.Since(b.lastPersonInput) < personTypingWindow:
		e := proto.Errorf(proto.ErrPersonTyping, "the person is typing")
		e.RetryAfterMS = (personTypingWindow - time.Since(b.lastPersonInput)).Milliseconds() + 1
		return e
	case b.pending != nil:
		return proto.Errorf(proto.ErrConfirmationPending, "an agent line waits for the person's answer")
	}
	return nil
}

// agentType types agent text, holding Enter under the confirm policy.
// The decision is taken under b.mu; the PTY write happens outside it
// (with ptyIn held and a deadline), so a program that stops reading cannot
// hang the broker (review S8).
func (b *Broker) agentType(c *conn, text string, enter bool, keys []string) (proto.Sent, *proto.Error) {
	b.ptyIn.Lock()
	defer b.ptyIn.Unlock()
	secret := b.pollTTY()
	b.mu.Lock()
	kind := "text"
	logText, _ := b.masker.MaskText(text)
	if keys != nil {
		kind, logText = "keys", strings.Join(keys, " ")
	}
	deny := func(e *proto.Error) (proto.Sent, *proto.Error) {
		b.auditLocked(audit.Record{Event: audit.AgentInput, Outcome: "denied", Subject: c.subject(),
			Data: map[string]any{"kind": kind, "reason": e.Code}})
		b.mu.Unlock()
		return proto.Sent{}, e
	}
	if e := b.agentDeniedLocked(secret); e != nil {
		return deny(e)
	}
	confirm := b.cfg.Policy == proto.PolicyConfirm
	// Build the byte sequence and find the first Enter.
	var seq []byte
	enterAt := -1
	if keys != nil {
		app := b.model.AppCursor()
		for _, k := range keys {
			if confirm && !confirmKeys[k] {
				return deny(proto.Errorf(proto.ErrPolicyDenied, "key %s is not allowed under the confirm policy", k))
			}
			kb, err := keyBytes(k, app)
			if err != nil {
				return deny(proto.Errorf(proto.ErrBadRequest, "%v", err))
			}
			if k == "Enter" && enterAt < 0 {
				enterAt = len(seq)
			}
			seq = append(seq, kb...)
		}
	} else {
		if len(text) > maxAgentText {
			return deny(proto.Errorf(proto.ErrBadRequest, "text longer than %d bytes", maxAgentText))
		}
		if confirm && !confirmTextOK(text, b.shellUTF8) {
			return deny(proto.Errorf(proto.ErrPolicyDenied, "under the confirm policy agent text may not hold tabs (completion runs programs), "+
				"control characters, escape sequences, history expansion (! followed by anything but a blank, = or (, and ^) "+
				"or, outside a UTF-8 locale, bytes above 0x7f"))
		}
		seq = []byte(text)
		if enter {
			seq = append(seq, '\r')
		}
		for i, ch := range seq {
			if ch == '\r' || ch == '\n' {
				enterAt = i
				break
			}
		}
	}
	held := false
	if confirm && enterAt >= 0 {
		seq = seq[:enterAt]
		held = true
	}
	// An agent Enter at the shell prompt holds the person's typeahead
	// like a person Enter does (review N15): a password typed ahead of a
	// sudo the agent started is not echoed.
	enterAtPrompt := enterAt >= 0 && !held && b.atPromptLocked(secret)
	if enterAt >= 0 && !held {
		b.openAgentWindowLocked()
	}
	b.mu.Unlock()
	sent := 0
	var werr error
	if len(seq) > 0 {
		sent, werr = b.writePTY(seq)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if enterAtPrompt && werr == nil {
		b.enterAtPrompt = time.Now()
	}
	b.agentText = logText
	b.agentActiveAt = time.Now()
	b.agentRequestsKeyboard = false
	data := map[string]any{"kind": kind, "text": logText}
	if werr != nil {
		data["error"] = "the program did not read its input in time"
		data["sent"] = sent
	}
	b.auditLocked(audit.Record{Event: audit.AgentInput, Subject: c.subject(), Data: data})
	if werr != nil {
		b.bumpLocked()
		return proto.Sent{Sent: sent}, proto.Errorf(proto.ErrInternal, "the program did not read its input in time (%d of %d bytes sent)", sent, len(seq))
	}
	if enterAt >= 0 {
		if held {
			// Let the echo of the typed text reach the screen model before
			// the person is shown the line.
			b.mu.Unlock()
			time.Sleep(30 * time.Millisecond)
			b.mu.Lock()
			line, _ := b.masker.MaskText(b.model.CursorLine())
			typed := logText
			pc := &proto.Confirmation{Line: line, Typed: typed}
			if keys == nil && strings.TrimSpace(typed) != "" &&
				!strings.HasSuffix(strings.TrimSpace(line), strings.TrimSpace(typed)) {
				// The line on screen does not end with what the agent typed: a
				// background job may have drawn over it.
				pc.Mismatch = true
			}
			b.pending = pc
			b.auditLocked(audit.Record{Event: audit.AgentLine, Subject: c.subject(),
				Data: map[string]any{"line": line, "typed": typed, "mismatch": pc.Mismatch, "held": true}})
		} else {
			b.auditLocked(audit.Record{Event: audit.AgentLine, Subject: c.subject(),
				Data: map[string]any{"line": logText, "held": false}})
		}
	}
	b.bumpLocked()
	return proto.Sent{Sent: len(seq), HeldEnter: held}, nil
}

// confirm answers the pending agent line (person only). An accept is
// refused when the line on screen changed since it was shown (review S6):
// the person can only deny it then.
func (b *Broker) confirm(c *conn, accept bool) *proto.Error {
	b.ptyIn.Lock()
	defer b.ptyIn.Unlock()
	b.mu.Lock()
	if b.pending == nil {
		b.mu.Unlock()
		return proto.Errorf(proto.ErrNoPending, "no agent line is waiting")
	}
	line := b.pending.Line
	if accept {
		now, _ := b.masker.MaskText(b.model.CursorLine())
		if now != line {
			b.auditLocked(audit.Record{Event: audit.Confirm, Outcome: "denied", Subject: c.subject(),
				Data: map[string]any{"line": line, "now": now, "reason": proto.ErrConfirmationStale}})
			b.bumpLocked()
			b.mu.Unlock()
			return proto.Errorf(proto.ErrConfirmationStale, "the line changed on screen since it was shown; deny it (^] n)")
		}
	}
	if accept {
		// The Enter reaches the PTY before anyone is told the line was
		// answered (a waiter must not see "no pending line" while the
		// command has not been entered yet). ptyIn, held, keeps another
		// answer out meanwhile; the write happens outside b.mu.
		b.openAgentWindowLocked()
		atPrompt := b.atPromptLocked(b.secretRaw)
		b.mu.Unlock()
		_, werr := b.writePTY([]byte{'\r'})
		b.mu.Lock()
		if atPrompt && werr == nil {
			b.enterAtPrompt = time.Now() // review N15
		}
	}
	b.pending = nil
	outcome := "denied"
	b.lastConfirm = "denied"
	if accept {
		outcome = "allowed"
		b.lastConfirm = "accepted"
	}
	b.auditLocked(audit.Record{Event: audit.Confirm, Outcome: outcome, Subject: c.subject(),
		Data: map[string]any{"line": line}})
	b.bumpLocked()
	b.mu.Unlock()
	return nil
}

// bump wakes waiters and the notifier.
func (b *Broker) bump() {
	b.mu.Lock()
	b.bumpLocked()
	b.mu.Unlock()
}

func (b *Broker) bumpLocked() {
	close(b.gen)
	b.gen = make(chan struct{})
	select {
	case b.changed <- struct{}{}:
	default:
	}
}

// notifier sends status events to persons and state events to
// subscribed agents, debounced. An agent gets a state event only when the
// state it may see changed, and an output event only when the output it
// may see changed: nothing per keystroke at a secret prompt or in private
// mode (review B2).
func (b *Broker) notifier() {
	for range b.changed {
		time.Sleep(30 * time.Millisecond)
		b.mu.Lock()
		if b.ended {
			b.mu.Unlock()
			return
		}
		status := b.statusLocked()
		state := b.stateLocked()
		seq := b.agentSeq
		conns := make([]*conn, 0, len(b.conns))
		for c := range b.conns {
			conns = append(conns, c)
		}
		b.mu.Unlock()
		stateJSON, _ := json.Marshal(state)
		for _, c := range conns {
			switch {
			case c.role == proto.RolePerson:
				c.sendEvent(proto.EventStatus, status)
			case c.role == proto.RoleAgent:
				c.mu.Lock()
				sendState := c.events[proto.EventState] && !bytes.Equal(c.lastState, stateJSON)
				if sendState {
					c.lastState = stateJSON
				}
				sendOut := c.events[proto.EventOutput] && c.lastOutSeq != seq
				if c.events[proto.EventOutput] {
					c.lastOutSeq = seq
				}
				c.mu.Unlock()
				if sendState {
					c.sendEvent(proto.EventState, json.RawMessage(stateJSON))
				}
				if sendOut {
					c.sendEvent(proto.EventOutput, map[string]int64{"cursor_since": state.CursorSince})
				}
			}
		}
	}
}

// stateLocked builds the state object agents see; agent-facing text is
// masked. While private mode is on, agents see the state of the moment it
// began, with only their own side and the session settings live; while
// secret input is active person_typing does not move (review B1, B2).
func (b *Broker) stateLocked() proto.State {
	s := b.liveStateLocked()
	if b.secretRaw {
		s.PersonTyping = b.secretTyping
	}
	if !b.private || b.privateState == nil {
		return s
	}
	f := *b.privateState
	f.Private = true
	f.Keyboard, f.Persons, f.Agents, f.Shared = s.Keyboard, s.Persons, s.Agents, s.Shared
	f.Assurance, f.RequireConfined, f.Policy = s.Assurance, s.RequireConfined, s.Policy
	f.AgentRequestsKeyboard, f.AgentMayType, f.PendingConfirmation = s.AgentRequestsKeyboard, s.AgentMayType, s.PendingConfirmation
	return f
}

// liveStateLocked is the state as it is (the person's view).
func (b *Broker) liveStateLocked() proto.State {
	rows, cols := b.model.Size()
	integ, atPrompt, last, exit, _ := b.model.ShellState()
	last, _ = b.masker.MaskText(last)
	s := proto.State{
		Session:               b.cfg.Name,
		Keyboard:              proto.KeyboardFree,
		PersonTyping:          time.Since(b.lastPersonInput) < personTypingWindow,
		SecretInput:           proto.SecretNone,
		Private:               b.private,
		Policy:                b.cfg.Policy,
		Shell:                 proto.Shell{Integration: integ, AtPrompt: atPrompt, LastCommand: last, ExitCode: exit},
		AltScreen:             b.model.AltScreen(),
		Rows:                  rows,
		Cols:                  cols,
		Persons:               b.countLocked(proto.RolePerson),
		Agents:                b.countLocked(proto.RoleAgent),
		Shared:                b.shared,
		Assurance:             b.assuranceLocked(),
		AgentRequestsKeyboard: b.agentRequestsKeyboard,
		CursorSince:           b.model.CursorSince(),
		RequireConfined:       b.requireConfined,
	}
	if b.held {
		s.Keyboard = proto.KeyboardHeld
	}
	if b.secretReported {
		s.SecretInput = proto.SecretActive
		if b.secretProg != nil {
			p := *b.secretProg
			s.SecretProgram = &p
		}
	}
	if b.fg != nil {
		p := *b.fg
		s.Foreground = &p
	}
	if b.pending != nil {
		p := *b.pending
		s.PendingConfirmation = &p
	}
	s.AgentMayType = b.agentDeniedLocked(false) == nil
	return s
}

// setPrivateLocked turns private mode on or off for agents (the model is
// switched by the caller first).
func (b *Broker) setPrivateLocked(on bool) {
	if on == b.private {
		return
	}
	if on {
		st := b.stateLocked()
		b.private = true
		b.privateState = &st
		return
	}
	b.private = false
	b.privateState = nil
	// The view moves again: one change for everything that happened.
	if !b.secretRaw {
		b.agentSeq++
		b.agentLastOutput = time.Now()
	}
}

func (b *Broker) statusLocked() proto.Status {
	st := proto.Status{State: b.liveStateLocked(), AgentText: b.agentText}
	// The person sees the real lock state, including after Enter until
	// termios is restored.
	if b.secretRaw && b.secretProg != nil {
		st.SecretInput = proto.SecretActive
		p := *b.secretProg
		st.SecretProgram = &p
	}
	if !b.agentActiveAt.IsZero() {
		st.AgentActiveAt = b.agentActiveAt.UTC().Format(time.RFC3339Nano)
	}
	for _, r := range b.pendingAttach {
		st.PendingAttach = append(st.PendingAttach, r.info)
	}
	// Oldest first: the approve hotkey acts on the first one (review S7).
	sort.Slice(st.PendingAttach, func(i, j int) bool { return st.PendingAttach[i].ID < st.PendingAttach[j].ID })
	for c := range b.conns {
		if c.role == proto.RoleAgent && peer.Rank(c.verdict.Assurance) <= peer.Rank(proto.AssuranceWeak) {
			st.WeakAgents++
		}
	}
	st.RefusedAgents = b.refusedAgents
	return st
}

// assuranceLocked is the session's assurance: the weakest of the
// connected agents, or what the guard allows when none is connected.
func (b *Broker) assuranceLocked() string {
	if b.cfg.Insecure {
		return proto.AssuranceInsecure
	}
	best := proto.AssuranceConfined
	if b.cfg.Guard.Loaded() {
		best = proto.AssuranceStrong
	}
	if !b.classifier.ExeTrusted {
		best = proto.AssuranceWeak
	}
	for c := range b.conns {
		if c.role == proto.RoleAgent && peer.Rank(c.verdict.Assurance) < peer.Rank(best) {
			best = c.verdict.Assurance
		}
	}
	return best
}

func (b *Broker) countLocked(role string) int {
	n := 0
	for c := range b.conns {
		if c.role == role {
			n++
		}
	}
	return n
}

// broadcastData sends raw output to every person connection.
func (b *Broker) broadcastData(p []byte) {
	b.mu.Lock()
	var persons []*conn
	for c := range b.conns {
		if c.role == proto.RolePerson && c.streaming {
			persons = append(persons, c)
		}
	}
	b.mu.Unlock()
	for _, c := range persons {
		c.sendData(p)
	}
}

// resize changes the PTY and model size.
func (b *Broker) resize(rows, cols int) {
	if rows < 2 || cols < 2 || rows > 1000 || cols > 1000 {
		return
	}
	b.setPTYSize(rows, cols)
	b.outMu.Lock()
	b.model.Resize(rows, cols)
	b.outMu.Unlock()
	b.bump()
}

// finish ends the session after the shell exited.
func (b *Broker) finish(code int) {
	b.mu.Lock()
	b.ended = true
	b.exitCode = code
	conns := make([]*conn, 0, len(b.conns))
	for c := range b.conns {
		conns = append(conns, c)
	}
	b.auditLocked(audit.Record{Event: audit.SessionEnd, Subject: audit.Subject{Role: "broker", PID: os.Getpid()},
		Data: map[string]any{"exit_code": code, "duration_s": int(time.Since(b.created).Seconds())}})
	// Wake waiters and the notifier; both see ended and stop. The changed
	// channel stays open: connections still closing may signal it.
	b.bumpLocked()
	b.mu.Unlock()
	for _, c := range conns {
		c.sendEvent(proto.EventEnded, map[string]int{"exit_code": code})
		c.closeAfterFlush()
	}
	_ = b.ln.Close()
	b.mu.Lock()
	b.closeAgentLocked()
	b.mu.Unlock()
	_ = os.Remove(b.paths.Meta)
	_ = os.Remove(b.paths.Socket)
	_ = b.ptmx.Close()
	b.model.Close()
	// The masker's secret list lives in locked memory; zero and release it.
	if cl, ok := b.masker.(interface{ Close() }); ok {
		cl.Close()
	}
}

// kill ends the session: SIGHUP to the shell's process group.
func (b *Broker) kill() {
	b.mu.Lock()
	cmd := b.cmd
	b.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGHUP)
		_ = cmd.Process.Signal(syscall.SIGHUP)
	}
}

func (b *Broker) auditf(r audit.Record) {
	b.mu.Lock()
	b.auditLocked(r)
	b.mu.Unlock()
}

func (b *Broker) auditLocked(r audit.Record) {
	if b.audit == nil {
		return
	}
	r.UID = os.Getuid()
	r.Session = b.cfg.Name
	if _, err := b.audit.Append(r); err != nil {
		b.logf("audit: %v", err)
	}
}

// Probing detection: a masked value tells whoever prints text that the
// text is a secret on the list. An agent guessing values (printing
// candidates and reading back) produces hits for the same name at many
// different places in a short time; a value that is simply on screen
// produces hits at one or a few places, however often it is read.
const (
	probeWindow    = time.Minute
	probeLocations = 5
)

// logHits records masking hits by name, at most once a minute per name,
// and flags possible probing (probeLocations distinct lines with a hit
// for the same name within probeWindow). base is the absolute line number
// of hit row 0.
func (b *Broker) logHits(hits []MaskHit, base int64) {
	if len(hits) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	var names []string
	for _, h := range hits {
		locs := b.hitLocations[h.Name]
		if locs == nil {
			locs = map[int64]time.Time{}
			b.hitLocations[h.Name] = locs
		}
		locs[base+int64(h.Row)] = now
		if t, ok := b.hitLogged[h.Name]; ok && now.Sub(t) < time.Minute {
			continue
		}
		b.hitLogged[h.Name] = now
		names = append(names, h.Name)
	}
	if len(names) > 0 {
		b.auditLocked(audit.Record{Event: audit.MaskHit, Data: map[string]any{"names": names}})
	}
	for name, locs := range b.hitLocations {
		for l, t := range locs {
			if now.Sub(t) > probeWindow {
				delete(locs, l)
			}
		}
		if len(locs) >= probeLocations {
			if t, ok := b.probeFlagged[name]; !ok || now.Sub(t) > probeWindow {
				b.probeFlagged[name] = now
				b.auditLocked(audit.Record{Event: audit.MaskProbe, Outcome: "suspected",
					Data: map[string]any{"name": name, "locations": len(locs), "window_s": int(probeWindow.Seconds())}})
				b.logf("masking: possible probing of %s (%d places in %v)", name, len(locs), probeWindow)
			}
		}
	}
}

// codeAlphabet is Crockford base32 without the confusable letters.
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newCode returns a reattach code, 10 symbols (50 bits), as XXXXX-XXXXX.
func newCode() string {
	var raw [10]byte
	_, _ = rand.Read(raw[:])
	out := make([]byte, 0, 11)
	for i, c := range raw {
		if i == 5 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(c)%32])
	}
	return string(out)
}

// newCodeState returns a new reattach code with its salt and proof key.
func newCodeState() (string, []byte, []byte) {
	code := newCode()
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return code, salt, proto.CodeKey(code, salt, proto.CodeKDFIterations)
}

// Kill ends the session (the shell gets SIGHUP; Run returns when it exits).
func (b *Broker) Kill() { b.kill() }
