package broker

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/openbasalt/cotty/internal/audit"
	"github.com/openbasalt/cotty/internal/peer"
	"github.com/openbasalt/cotty/internal/proto"
)

// conn is one client connection.
type conn struct {
	b       *Broker
	c       *net.UnixConn
	info    peer.Info
	verdict peer.Verdict
	role    string
	client  string
	// admission is how a person or control connection was admitted
	// (creator, code, code+approval, insecure).
	admission string
	// agentOnly is set for connections on the agent endpoint: only the
	// agent and info roles, and the peer never counts as a person.
	agentOnly bool

	out       chan outFrame
	done      chan struct{}
	closeOnce sync.Once

	mu        sync.Mutex
	events    map[string]bool
	streaming bool
	rows      int
	cols      int
	// lastState is the last state event sent (JSON), so agents get an
	// event only when what they may see changed.
	lastState []byte
	// lastOutSeq is the agent-visible output counter of the last output
	// event sent.
	lastOutSeq int64

	// challenge is the admission challenge last issued on this
	// connection (one proof attempt per challenge). Guarded by b.mu.
	challenge *proto.Challenge
	// waits counts this connection's running wait requests.
	waits atomic.Int32
}

type outFrame struct {
	typ   byte
	b     []byte
	close bool
}

func (c *conn) subject() audit.Subject {
	return audit.Subject{Role: c.role, PID: c.info.PID, Exe: c.info.Exe, Assurance: c.verdict.Assurance}
}

func (c *conn) wants(ev string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.events[ev]
}

func (c *conn) writer() {
	for f := range c.out {
		if f.close {
			break
		}
		_ = c.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := proto.WriteFrame(c.c, f.typ, f.b); err != nil {
			break
		}
	}
	c.close()
}

func (c *conn) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.c.Close()
	})
}

// closeAfterFlush closes once queued frames are written.
func (c *conn) closeAfterFlush() {
	select {
	case c.out <- outFrame{close: true}:
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.close()
	}
}

func (c *conn) enqueue(f outFrame, block time.Duration) bool {
	if block == 0 {
		select {
		case c.out <- f:
			return true
		case <-c.done:
			return false
		default:
			return false
		}
	}
	t := time.NewTimer(block)
	defer t.Stop()
	select {
	case c.out <- f:
		return true
	case <-c.done:
		return false
	case <-t.C:
		// A person client that stops reading would stall nothing else:
		// drop it.
		c.close()
		return false
	}
}

func (c *conn) sendData(p []byte) {
	c.enqueue(outFrame{typ: proto.FrameData, b: p}, 5*time.Second)
}

func (c *conn) sendJSON(v any, block time.Duration) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	c.enqueue(outFrame{typ: proto.FrameJSON, b: b}, block)
}

func (c *conn) sendEvent(name string, data any) {
	c.sendJSON(proto.Event{Event: name, Data: data}, 0)
}

func (c *conn) reply(id int64, result any, perr *proto.Error) {
	if perr != nil {
		c.sendJSON(proto.Response{ID: id, OK: false, Error: perr}, 5*time.Second)
		return
	}
	if result == nil {
		result = struct{}{}
	}
	c.sendJSON(proto.Response{ID: id, OK: true, Result: result}, 5*time.Second)
}

// Connection limits (resource exhaustion by agents, review S8).
const (
	maxConns         = 128      // open connections per endpoint (main and agent, review N11)
	maxWaitsPerConn  = 8        // concurrent wait requests per connection
	maxHelloFrame    = 64 << 10 // largest frame before hello succeeds
	maxHelloAttempts = 5        // hello requests per connection (challenge, proof, retries)
	maxPendingAttach = 1        // attach requests waiting for the person
	// approvalBackoff: after a request was denied or timed out, the same
	// terminal and kernel session must prove the code for this long
	// instead of asking again (review N11).
	approvalBackoff = 30 * time.Second
)

// serve runs one connection.
func (b *Broker) serve(uc *net.UnixConn, agentOnly bool) {
	// One cap per endpoint: agents filling theirs do not lock the person
	// out of the main socket (review N11).
	n := &b.nconns
	if agentOnly {
		n = &b.nagentConns
	}
	if n.Add(1) > maxConns {
		n.Add(-1)
		_ = uc.Close()
		return
	}
	defer n.Add(-1)
	c := &conn{b: b, c: uc, out: make(chan outFrame, 1024), done: make(chan struct{}), events: map[string]bool{},
		agentOnly: agentOnly}
	go c.writer()
	defer func() {
		// Let the writer flush what is queued (an error reply), then close.
		c.closeAfterFlush()
		b.dropConn(c)
	}()
	info, err := peer.FromConn(uc)
	if err != nil {
		return
	}
	c.info = info
	c.verdict = b.classifier.Classify(info)
	if agentOnly && c.verdict.Person {
		// The agent endpoint never grants person rights; an unconfined
		// peer there is a weakly assured agent.
		c.verdict = peer.Verdict{Failed: []string{"connected through the agent endpoint"},
			Assurance: proto.AssuranceWeak, AssuranceReason: "agent connection from a peer that is not confined"}
		if b.cfg.Insecure {
			c.verdict.Assurance = proto.AssuranceInsecure
		}
	}
	// Hello, possibly in several steps on this connection: a challenge for
	// the creator token or the reattach code, then the proof (the person
	// may take a while to type the code).
	deadline := 15 * time.Second
	for attempt := 1; ; attempt++ {
		_ = uc.SetReadDeadline(time.Now().Add(deadline))
		f, err := proto.ReadFrameMax(uc, maxHelloFrame)
		if err != nil {
			return
		}
		var req proto.Request
		if f.Type != proto.FrameJSON || json.Unmarshal(f.Payload, &req) != nil || req.Op != "hello" {
			c.reply(req.ID, nil, proto.Errorf(proto.ErrHelloRequired, "the first request must be hello"))
			return
		}
		var h proto.Hello
		if err := json.Unmarshal(req.Args, &h); err != nil {
			c.reply(req.ID, nil, proto.Errorf(proto.ErrBadRequest, "hello: %v", err))
			return
		}
		perr := b.hello(c, req.ID, h)
		if perr == nil {
			break
		}
		c.reply(req.ID, nil, perr)
		if perr.Challenge == nil || attempt >= maxHelloAttempts {
			return
		}
		deadline = 3 * time.Minute
	}
	_ = uc.SetReadDeadline(time.Time{})
	for {
		f, err := proto.ReadFrame(uc)
		if err != nil {
			return
		}
		switch f.Type {
		case proto.FrameData:
			if c.role != proto.RolePerson {
				return
			}
			b.personInput(f.Payload)
		case proto.FrameJSON:
			var r proto.Request
			if err := json.Unmarshal(f.Payload, &r); err != nil {
				c.reply(0, nil, proto.Errorf(proto.ErrBadRequest, "%v", err))
				continue
			}
			if r.Op == "wait" {
				if c.waits.Add(1) > maxWaitsPerConn {
					c.waits.Add(-1)
					c.reply(r.ID, nil, proto.Errorf(proto.ErrTooManyRequests, "at most %d waits at a time per connection", maxWaitsPerConn))
					continue
				}
				go func() {
					defer c.waits.Add(-1)
					b.handle(c, r)
				}()
			} else {
				b.handle(c, r)
			}
			if c.role == proto.RoleInfo && r.Op == "info" {
				return
			}
		default:
			return
		}
		select {
		case <-c.done:
			return
		default:
		}
	}
}

// hello admits a connection with a role (docs/protocol.md sections 4, 7).
func (b *Broker) hello(c *conn, id int64, h proto.Hello) *proto.Error {
	if h.V != proto.Version {
		return proto.Errorf(proto.ErrVersionUnsupported, "supported versions: [%d]", proto.Version)
	}
	c.client = h.Client
	b.mu.Lock()
	shared, ended, requireConfined := b.shared, b.ended, b.requireConfined
	b.mu.Unlock()
	if ended {
		return proto.Errorf(proto.ErrSessionEnded, "the session ended")
	}
	if c.agentOnly && h.Role != proto.RoleAgent && h.Role != proto.RoleInfo {
		b.auditf(audit.Record{Event: audit.Attach, Outcome: "denied", Subject: c.subject(),
			Data: map[string]any{"role": h.Role, "reason": proto.ErrRoleDenied, "admission": "agent_endpoint"}})
		return proto.Errorf(proto.ErrRoleDenied, "the agent endpoint only serves the agent and info roles")
	}
	switch h.Role {
	case proto.RoleAgent:
		if !shared {
			return proto.Errorf(proto.ErrNotShared, "the session is not shared with agents (cotty share)")
		}
		c.role = proto.RoleAgent
		if c.verdict.Person && c.verdict.Assurance != proto.AssuranceInsecure {
			// A person-capable peer asking for less still is an agent here.
			c.verdict.Assurance = proto.AssuranceWeak
			c.verdict.AssuranceReason = "agent connection from a peer that is not confined"
		}
		if requireConfined && peer.Rank(c.verdict.Assurance) < peer.Rank(proto.AssuranceConfined) {
			b.mu.Lock()
			b.refusedAgents++
			b.bumpLocked()
			b.mu.Unlock()
			b.auditf(audit.Record{Event: audit.Attach, Outcome: "denied", Subject: c.subject(),
				Data: map[string]any{"role": c.role, "client": h.Client, "reason": proto.ErrConfinementRequired}})
			c.role = ""
			return proto.Errorf(proto.ErrConfinementRequired,
				"this session accepts only confined agents (--require-confined); start the agent with `cotty agent`: %s", c.verdict.AssuranceReason)
		}
		b.register(c)
		b.auditf(audit.Record{Event: audit.Attach, Outcome: "allowed", Subject: c.subject(),
			Data: map[string]any{"role": c.role, "client": h.Client}})
		c.reply(id, b.helloResult(c), nil)
		return nil
	case proto.RoleInfo:
		if !c.verdict.Person && !shared {
			return proto.Errorf(proto.ErrNotShared, "the session is not shared with agents")
		}
		c.role = proto.RoleInfo
		c.reply(id, b.helloResult(c), nil)
		return nil
	case proto.RolePerson, proto.RoleControl:
	default:
		return proto.Errorf(proto.ErrBadRequest, "unknown role %q", h.Role)
	}
	deny := func(e *proto.Error, admission string) *proto.Error {
		b.auditf(audit.Record{Event: audit.Attach, Outcome: "denied", Subject: c.subject(),
			Data: map[string]any{"role": h.Role, "reason": e.Code, "admission": admission}})
		return e
	}
	if !c.verdict.Person {
		return deny(proto.Errorf(proto.ErrRoleDenied, "not classified as a person: %s", strings.Join(c.verdict.Failed, "; ")), "classification")
	}
	adm, perr := b.admit(c, h)
	if perr != nil {
		if perr.Code == proto.ErrCodeRequired {
			// Not a denial yet: the client is asked for its proof.
			return perr
		}
		return deny(perr, adm.how)
	}
	c.role = h.Role
	c.admission = adm.how
	b.auditf(audit.Record{Event: audit.Attach, Outcome: "allowed", Subject: c.subject(),
		Data: map[string]any{"role": c.role, "admission": adm.how, "client": h.Client}})
	res := b.helloResult(c)
	res.Admission, res.ServerProof = adm.how, adm.serverProof
	if c.role == proto.RoleControl {
		b.register(c)
		c.reply(id, res, nil)
		return nil
	}
	// Person: resize, then snapshot and live stream with nothing lost in
	// between (outMu orders this against the output loop).
	b.outMu.Lock()
	if h.Rows > 1 && h.Cols > 1 && h.Rows <= 1000 && h.Cols <= 1000 {
		c.rows, c.cols = h.Rows, h.Cols
		b.setPTYSize(h.Rows, h.Cols)
		b.model.Resize(h.Rows, h.Cols)
	}
	c.streaming = true
	b.register(c)
	b.mu.Lock()
	b.sizeOwner = c
	b.mu.Unlock()
	c.reply(id, res, nil)
	c.sendData(b.model.Snapshot())
	b.outMu.Unlock()
	b.bump()
	return nil
}

// admission is the outcome of admit for an admitted connection.
type admission struct {
	how         string // creator, code, approval, insecure
	serverProof string // the broker's proof for creator and code admission
}

// challengeLocked issues a fresh challenge on c for an admission secret.
func (b *Broker) challengeLocked(c *conn, kind string) *proto.Challenge {
	ch := &proto.Challenge{Kind: kind, Nonce: proto.NewNonce()}
	if kind == proto.AuthCode {
		ch.Salt = hex.EncodeToString(b.codeSalt)
		ch.Iterations = b.codeIter
	}
	c.challenge = ch
	return ch
}

// codeLimiter is the reattach code backoff of one controlling terminal.
type codeLimiter struct {
	fails     int
	lockUntil time.Time
	last      time.Time
}

// admit applies the admission rules for person and control connections
// (docs/protocol.md section 7). The creator token and the reattach code
// are proven, never sent (proto/auth.go).
func (b *Broker) admit(c *conn, h proto.Hello) (admission, *proto.Error) {
	b.mu.Lock()
	if b.cfg.Insecure && h.Auth == "" {
		b.mu.Unlock()
		return admission{how: "insecure"}, nil
	}
	if h.Auth != "" && h.Auth != proto.AuthCreator && h.Auth != proto.AuthCode {
		b.mu.Unlock()
		return admission{how: h.Auth}, proto.Errorf(proto.ErrBadRequest, "unknown auth %q", h.Auth)
	}
	if h.Auth != "" && (len(h.Nonce) != 2*proto.NonceLen) {
		b.mu.Unlock()
		return admission{how: h.Auth}, proto.Errorf(proto.ErrBadRequest, "hello: nonce required")
	}
	if h.Auth == proto.AuthCreator {
		if b.creatorToken == "" {
			b.mu.Unlock()
			return admission{how: "creator"}, proto.Errorf(proto.ErrCodeInvalid, "creator token already used")
		}
		if h.Proof == "" || c.challenge == nil || c.challenge.Kind != proto.AuthCreator {
			e := proto.Errorf(proto.ErrCodeRequired, "prove the creator token")
			e.Challenge = b.challengeLocked(c, proto.AuthCreator)
			b.mu.Unlock()
			return admission{how: "creator"}, e
		}
		key := proto.TokenKey(b.creatorToken)
		tr := proto.Transcript(proto.AuthCreator, h.Role, b.cfg.Name, h.Nonce, c.challenge.Nonce, c.info.PID, os.Getpid())
		c.challenge = nil
		if !proto.ProofEqual(h.Proof, proto.Proof(key, proto.SideClient, tr)) {
			// A wrong proof does not burn the token: only its owner, cotty
			// new, can present the right one.
			b.mu.Unlock()
			return admission{how: "creator"}, proto.Errorf(proto.ErrCodeInvalid, "creator token proof invalid")
		}
		b.creatorToken = ""
		b.mu.Unlock()
		return admission{how: "creator", serverProof: proto.Proof(key, proto.SideServer, tr)}, nil
	}
	if h.Auth == proto.AuthCode {
		now := time.Now()
		lim := b.codeLimitLocked(codeLimitKey{tty: c.info.TTYNr, sid: c.info.SID}, now)
		if now.Before(lim.lockUntil) {
			b.mu.Unlock()
			return admission{how: "code"}, &proto.Error{Code: proto.ErrRateLimited, Message: "too many wrong codes from this terminal",
				RetryAfterMS: time.Until(lim.lockUntil).Milliseconds() + 1}
		}
		if h.Proof == "" || c.challenge == nil || c.challenge.Kind != proto.AuthCode {
			e := proto.Errorf(proto.ErrCodeRequired, "enter the reattach code shown at detach")
			e.Challenge = b.challengeLocked(c, proto.AuthCode)
			b.mu.Unlock()
			return admission{how: "code"}, e
		}
		key := b.codeKey
		tr := proto.Transcript(proto.AuthCode, h.Role, b.cfg.Name, h.Nonce, c.challenge.Nonce, c.info.PID, os.Getpid())
		c.challenge = nil
		if b.codeSpent || !proto.ProofEqual(h.Proof, proto.Proof(key, proto.SideClient, tr)) {
			lim.fails++
			if lim.fails >= maxCodeFails {
				lim.fails = 0
				lim.lockUntil = now.Add(codeLockout)
			}
			e := proto.Errorf(proto.ErrCodeInvalid, "wrong reattach code")
			e.Challenge = b.challengeLocked(c, proto.AuthCode)
			b.mu.Unlock()
			return admission{how: "code"}, e
		}
		lim.fails = 0
		persons := b.countLocked(proto.RolePerson)
		if h.Role == proto.RolePerson {
			// The code is good for one person attach, whatever the attached
			// person answers: it is spent here, under the lock, so a second
			// proof at the same moment fails, and replaced below. A denied
			// or unanswered approval still spends it: the requester knew it
			// (review A2). The next code is shown at the next detach (and
			// with the c hotkey). Control commands (cotty share, cotty kill)
			// leave it as it is.
			b.codeSpent = true
			// Until rotateCode installs the next code, readers of the code
			// (the code and detach ops) wait instead of handing out the
			// spent one (review round 4).
			b.codeReady = make(chan struct{})
		}
		b.mu.Unlock()
		if h.Role == proto.RolePerson {
			b.rotateCode()
		}
		how := "code"
		if h.Role == proto.RolePerson && persons > 0 {
			// The code proves the session to the client and the client to
			// the session; a person already attached still approves a
			// second person (a second gate, not a replacement: review N1).
			if perr := b.approve(c, h); perr != nil {
				return admission{how: "code+approval"}, perr
			}
			how = "code+approval"
		}
		return admission{how: how, serverProof: proto.Proof(key, proto.SideServer, tr)}, nil
	}
	if b.cfg.Insecure {
		b.mu.Unlock()
		return admission{how: "insecure"}, nil
	}
	// No secret offered: the reattach code is required on every admission
	// (an approval alone proves nothing to the client about the broker).
	e := proto.Errorf(proto.ErrCodeRequired, "enter the reattach code (shown at detach, or with ^] c in an attached client)")
	e.Challenge = b.challengeLocked(c, proto.AuthCode)
	b.mu.Unlock()
	return admission{how: "code"}, e
}

// approve asks the attached persons to approve connection c (after it
// proved the reattach code). One request waits at a time; a terminal whose
// request was just denied waits approvalBackoff before asking again (it
// already proved the code, so this only keeps it from flooding the
// person with requests).
func (b *Broker) approve(c *conn, h proto.Hello) *proto.Error {
	b.mu.Lock()
	key := codeLimitKey{tty: c.info.TTYNr, sid: c.info.SID}
	if len(b.pendingAttach) >= maxPendingAttach || time.Now().Before(b.approvalBackoff[key]) {
		b.mu.Unlock()
		return proto.Errorf(proto.ErrApprovalUnavailable,
			"another attach request is waiting for the person, or this terminal was just denied; try again later")
	}
	b.nextReq++
	req := &attachReq{ch: make(chan bool, 1), info: proto.AttachRequest{
		ID: b.nextReq, PID: c.info.PID, Exe: c.info.Exe, TTY: c.info.TTY, Chain: c.info.Chain, Role: h.Role,
		Started:  time.Now().UTC().Format(time.RFC3339),
		Deadline: time.Now().Add(approvalTimeout).UTC().Format(time.RFC3339),
	}}
	b.pendingAttach[req.info.ID] = req
	var persList []*conn
	for pc := range b.conns {
		if pc.role == proto.RolePerson {
			persList = append(persList, pc)
		}
	}
	b.bumpLocked()
	b.mu.Unlock()
	for _, pc := range persList {
		pc.sendEvent(proto.EventAttachRequest, req.info)
	}
	hangup, stopWatch := watchHangup(c.c)
	accepted := false
	select {
	case accepted = <-req.ch:
	case <-time.After(approvalTimeout):
	case <-c.done:
	case <-hangup:
		// The requester went away: free the slot now, not after 60 s.
	}
	stopWatch()
	b.mu.Lock()
	delete(b.pendingAttach, req.info.ID)
	if !accepted {
		b.setApprovalBackoffLocked(key)
	}
	b.bumpLocked()
	b.mu.Unlock()
	if !accepted {
		return proto.Errorf(proto.ErrApprovalDenied, "the attached person did not approve")
	}
	return nil
}

// setApprovalBackoffLocked keeps key from asking for approval again for
// approvalBackoff. The table is bounded.
func (b *Broker) setApprovalBackoffLocked(key codeLimitKey) {
	now := time.Now()
	for k, until := range b.approvalBackoff {
		if now.After(until) {
			delete(b.approvalBackoff, k)
		}
	}
	if len(b.approvalBackoff) >= 4096 {
		for k := range b.approvalBackoff {
			delete(b.approvalBackoff, k)
			break
		}
	}
	b.approvalBackoff[key] = now.Add(approvalBackoff)
}

// watchHangup reports on the returned channel when the peer closes the
// connection (or sends anything, which it must not do while it waits for
// its hello answer). stop ends the watch; the connection's read deadline
// is cleared then, and the caller sets its own.
func watchHangup(uc *net.UnixConn) (<-chan struct{}, func()) {
	gone := make(chan struct{})
	if uc == nil {
		return gone, func() {}
	}
	_ = uc.SetReadDeadline(time.Time{})
	var stopping atomic.Bool
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		var buf [1]byte
		_, err := uc.Read(buf[:])
		if !stopping.Load() || err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
			close(gone)
		}
	}()
	return gone, func() {
		stopping.Store(true)
		_ = uc.SetReadDeadline(time.Now())
		<-exited
		_ = uc.SetReadDeadline(time.Time{})
	}
}

// codeLimitKey identifies where wrong codes come from: the controlling
// terminal and the kernel session. Terminal numbers are reused as soon as
// a pty closes, so the terminal alone would let a guesser's closed pty
// lock out the person's next one; a kernel session id is only reused once
// its leader is gone.
type codeLimitKey struct {
	tty uint64
	sid int
}

// codeLimitLocked returns the reattach code backoff of one terminal and
// session. The backoff is per terminal so that a process that guesses
// cannot lock the person out; the code's 50 bits keep parallel guessing
// from many terminals hopeless (3 guesses per 30 s per terminal).
func (b *Broker) codeLimitLocked(key codeLimitKey, now time.Time) *codeLimiter {
	for k, l := range b.codeLimits {
		if now.After(l.lockUntil) && now.Sub(l.last) > 10*time.Minute {
			delete(b.codeLimits, k)
		}
	}
	l := b.codeLimits[key]
	if l == nil {
		if len(b.codeLimits) >= 4096 {
			// Bound the table; an old entry is cheaper to forget than memory.
			for k := range b.codeLimits {
				delete(b.codeLimits, k)
				break
			}
		}
		l = &codeLimiter{}
		b.codeLimits[key] = l
	}
	l.last = now
	return l
}

// rotateCode replaces the reattach code (the key derivation runs outside
// the lock) and lets waiting readers of the code go on.
func (b *Broker) rotateCode() {
	code, salt, key := newCodeState()
	b.mu.Lock()
	b.code, b.codeSalt, b.codeKey = code, salt, key
	b.codeSpent = false
	select {
	case <-b.codeReady:
	default:
		close(b.codeReady)
	}
	b.mu.Unlock()
}

// codeWait bounds how long a reader of the code waits for a spent code to
// be replaced (the key derivation takes well under a second).
const codeWait = 10 * time.Second

// currentCode returns the reattach code a person may use next: never one
// already spent. While a spent code is being replaced it waits for the new
// one; it fails when that takes longer than codeWait.
func (b *Broker) currentCode() (string, *proto.Error) {
	deadline := time.NewTimer(codeWait)
	defer deadline.Stop()
	for {
		b.mu.Lock()
		if !b.codeSpent {
			code := b.code
			b.mu.Unlock()
			return code, nil
		}
		ready := b.codeReady
		b.mu.Unlock()
		select {
		case <-ready:
		case <-deadline.C:
			return "", proto.Errorf(proto.ErrInternal, "the reattach code is being replaced; try again")
		}
	}
}

func (b *Broker) helloResult(c *conn) proto.HelloResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	return proto.HelloResult{V: proto.Version, Session: b.cfg.Name, Role: c.role,
		Assurance: c.verdict.Assurance, AssuranceReason: c.verdict.AssuranceReason,
		BrokerPID: b.selfPID(), Policy: b.cfg.Policy, Shared: b.shared}
}

func (b *Broker) selfPID() int { return b.classifier.SelfPID }

func (b *Broker) register(c *conn) {
	b.mu.Lock()
	b.conns[c] = true
	b.bumpLocked()
	b.mu.Unlock()
}

func (b *Broker) dropConn(c *conn) {
	b.mu.Lock()
	if !b.conns[c] {
		b.mu.Unlock()
		return
	}
	delete(b.conns, c)
	var next *conn
	if b.sizeOwner == c {
		b.sizeOwner = nil
		for pc := range b.conns {
			if pc.role == proto.RolePerson && pc.rows > 0 {
				next = pc
			}
		}
		b.sizeOwner = next
	}
	if c.role == proto.RolePerson && b.countLocked(proto.RolePerson) == 0 {
		// Nobody can take or give the keyboard any more.
		b.held = false
	}
	ended := b.ended
	b.bumpLocked()
	b.mu.Unlock()
	if c.role == proto.RolePerson || c.role == proto.RoleAgent {
		if !ended {
			b.auditf(audit.Record{Event: audit.Detach, Subject: c.subject(), Data: map[string]any{"role": c.role}})
		}
	}
	if next != nil {
		b.resize(next.rows, next.cols)
	}
}

// allowed lists the ops of each role.
var allowed = map[string]map[string]bool{
	proto.RoleAgent: set("info", "state", "screen", "since", "type", "keys", "wait", "subscribe",
		"request_keyboard", "mask"),
	proto.RolePerson: set("info", "state", "screen", "since", "wait", "subscribe", "mask", "resize",
		"keyboard", "private", "confirm", "approve", "share", "code", "detach", "kill"),
	proto.RoleControl: set("info", "share", "kill", "code"),
	proto.RoleInfo:    set("info"),
}

func set(ops ...string) map[string]bool {
	m := map[string]bool{}
	for _, o := range ops {
		m[o] = true
	}
	return m
}

func decode(r proto.Request, v any) *proto.Error {
	if len(r.Args) == 0 {
		return nil
	}
	if err := json.Unmarshal(r.Args, v); err != nil {
		return proto.Errorf(proto.ErrBadRequest, "%s: %v", r.Op, err)
	}
	return nil
}

// handle dispatches one request.
func (b *Broker) handle(c *conn, r proto.Request) {
	ops, ok := allowed[c.role]
	if !ok {
		c.reply(r.ID, nil, proto.Errorf(proto.ErrForbidden, "no role"))
		return
	}
	if !ops[r.Op] {
		known := false
		for _, m := range allowed {
			if m[r.Op] {
				known = true
			}
		}
		if !known {
			c.reply(r.ID, nil, proto.Errorf(proto.ErrUnknownOp, "unknown op %q", r.Op))
		} else {
			c.reply(r.ID, nil, proto.Errorf(proto.ErrForbidden, "op %q is not allowed for role %s", r.Op, c.role))
		}
		return
	}
	res, perr := b.op(c, r)
	c.reply(r.ID, res, perr)
	if r.Op == "detach" && perr == nil {
		c.closeAfterFlush()
	}
}

func (b *Broker) op(c *conn, r proto.Request) (any, *proto.Error) {
	switch r.Op {
	case "info":
		return b.info(), nil
	case "state":
		b.mu.Lock()
		defer b.mu.Unlock()
		if c.role == proto.RolePerson {
			return b.statusLocked(), nil
		}
		return b.stateLocked(), nil
	case "screen":
		var a struct {
			Context int `json:"context"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		if c.role == proto.RoleAgent {
			b.settle()
		}
		return b.screen(min(max(a.Context, 0), 200))
	case "since":
		var a struct {
			Cursor int64 `json:"cursor"`
			Limit  int   `json:"limit"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		if a.Limit <= 0 {
			a.Limit = 500
		}
		if c.role == proto.RoleAgent {
			b.settle()
		}
		return b.since(a.Cursor, min(a.Limit, 5000))
	case "type":
		var a struct {
			Text  string `json:"text"`
			Enter bool   `json:"enter"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		return b.agentType(c, a.Text, a.Enter, nil)
	case "keys":
		var a struct {
			Keys []string `json:"keys"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		if len(a.Keys) == 0 || len(a.Keys) > 64 {
			return nil, proto.Errorf(proto.ErrBadRequest, "keys: 1 to 64 names")
		}
		return b.agentType(c, "", false, a.Keys)
	case "wait":
		var a proto.WaitArgs
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		return b.wait(c, a)
	case "subscribe":
		var a struct {
			Events []string `json:"events"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		c.mu.Lock()
		for _, ev := range a.Events {
			c.events[ev] = true
		}
		c.mu.Unlock()
		b.bump()
		return nil, nil
	case "request_keyboard":
		b.mu.Lock()
		b.agentRequestsKeyboard = true
		b.auditLocked(audit.Record{Event: audit.KeyboardRequest, Subject: c.subject()})
		b.bumpLocked()
		b.mu.Unlock()
		return nil, nil
	case "mask":
		var a struct {
			Name string `json:"name"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		switch err := b.masker.AddByName(a.Name); err {
		case nil:
			// Regex waits look again with the new list.
			b.maskGen.Add(1)
			b.bump()
			return map[string]bool{"masked": true}, nil
		case ErrUnknownSecret:
			return nil, proto.Errorf(proto.ErrUnknownSecret, "no secret named %q", a.Name)
		case ErrUnsupported:
			return nil, proto.Errorf(proto.ErrUnsupported, "%v", err)
		default:
			// Never the engine's own error: it could describe the value
			// (too short for the list). The broker log has the cause.
			return nil, proto.Errorf(proto.ErrUnsupported, "%v; try again later or ask the person", ErrNotMaskable)
		}
	case "resize":
		var a struct {
			Rows int `json:"rows"`
			Cols int `json:"cols"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		c.mu.Lock()
		c.rows, c.cols = a.Rows, a.Cols
		c.mu.Unlock()
		b.mu.Lock()
		b.sizeOwner = c
		b.mu.Unlock()
		b.resize(a.Rows, a.Cols)
		return nil, nil
	case "keyboard":
		var a struct {
			Hold bool `json:"hold"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		b.mu.Lock()
		b.held = a.Hold
		if !a.Hold {
			b.agentRequestsKeyboard = false
		}
		b.auditLocked(audit.Record{Event: audit.Keyboard, Subject: c.subject(), Data: map[string]any{"hold": a.Hold}})
		b.bumpLocked()
		b.mu.Unlock()
		return nil, nil
	case "private":
		var a struct {
			On bool `json:"on"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		b.outMu.Lock()
		b.model.SetPrivate(a.On)
		b.mu.Lock()
		b.setPrivateLocked(a.On)
		b.outMu.Unlock()
		b.auditLocked(audit.Record{Event: audit.PrivateMode, Subject: c.subject(), Data: map[string]any{"on": a.On}})
		b.bumpLocked()
		b.mu.Unlock()
		return nil, nil
	case "confirm":
		var a struct {
			Accept bool `json:"accept"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		return nil, b.confirm(c, a.Accept)
	case "approve":
		var a struct {
			Request int64 `json:"request"`
			Accept  bool  `json:"accept"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		b.mu.Lock()
		req := b.pendingAttach[a.Request]
		b.mu.Unlock()
		if req == nil {
			return nil, proto.Errorf(proto.ErrNoPending, "no attach request %d", a.Request)
		}
		outcome := "denied"
		if a.Accept {
			outcome = "allowed"
		}
		b.auditf(audit.Record{Event: audit.AttachApproval, Outcome: outcome, Subject: c.subject(),
			Data: map[string]any{"request": a.Request, "pid": req.info.PID, "exe": req.info.Exe}})
		select {
		case req.ch <- a.Accept:
		default:
		}
		return nil, nil
	case "share":
		var a struct {
			On              bool  `json:"on"`
			RequireConfined *bool `json:"require_confined"`
		}
		if e := decode(r, &a); e != nil {
			return nil, e
		}
		if err := b.setShared(c, a.On, a.RequireConfined); err != nil {
			return nil, proto.Errorf(proto.ErrInternal, "agent endpoint: %v", err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		return map[string]bool{"shared": a.On, "require_confined": b.requireConfined}, nil
	case "code":
		if c.role == proto.RoleControl && c.admission != "creator" && c.admission != "insecure" {
			// A control connection admitted with the code (cotty share,
			// cotty kill) must not read the next code: one leak of a code
			// would be access for good (review A1). cotty new -d reads it
			// with the creator token.
			return nil, proto.Errorf(proto.ErrRoleDenied, "only the session's creator reads the code over a control connection")
		}
		code, perr := b.currentCode()
		if perr != nil {
			return nil, perr
		}
		return map[string]string{"code": code}, nil
	case "detach":
		code, perr := b.currentCode()
		if perr != nil {
			return nil, perr
		}
		return map[string]string{"code": code}, nil
	case "kill":
		b.kill()
		return nil, nil
	}
	return nil, proto.Errorf(proto.ErrUnknownOp, "unknown op %q", r.Op)
}

// setShared shows or hides the session from agents: the agent endpoint
// is served only while the session is shared. requireConfined, when not
// nil, sets --require-confined; turning it on closes the weak agents
// already connected.
func (b *Broker) setShared(c *conn, on bool, requireConfined *bool) error {
	b.mu.Lock()
	var err error
	if on && !b.ended {
		err = b.openAgentLocked()
	} else {
		b.closeAgentLocked()
	}
	if err != nil {
		on = false
	}
	b.shared = on
	if requireConfined != nil {
		b.requireConfined = *requireConfined
	}
	var agents []*conn
	for ac := range b.conns {
		if ac.role != proto.RoleAgent {
			continue
		}
		if !on || (b.requireConfined && peer.Rank(ac.verdict.Assurance) < peer.Rank(proto.AssuranceConfined)) {
			agents = append(agents, ac)
		}
	}
	data := map[string]any{"on": on, "require_confined": b.requireConfined}
	if err != nil {
		data["error"] = err.Error()
	}
	b.auditLocked(audit.Record{Event: audit.Share, Subject: c.subject(), Data: data})
	b.bumpLocked()
	b.mu.Unlock()
	for _, ac := range agents {
		ac.close()
	}
	return err
}

func (b *Broker) info() proto.Info {
	b.mu.Lock()
	defer b.mu.Unlock()
	rows, cols := b.model.Size()
	return proto.Info{Session: b.cfg.Name, Created: b.created.UTC().Format(time.RFC3339),
		BrokerPID: b.selfPID(), Shared: b.shared, Policy: b.cfg.Policy,
		Persons: b.countLocked(proto.RolePerson), Agents: b.countLocked(proto.RoleAgent), Rows: rows, Cols: cols}
}

// maskContextLines is how many committed lines before a read (the screen,
// or the first line of a since read) and after a since read are given to
// the masker as context: a value scrolled half out of view, split by the
// edges of a paged read, or a private key whose BEGIN line is far above.
// One depth for both reads, so the screen and since agree. The lines
// are taken further back (or ahead) until they hold the longest pattern
// the masker matches: a long value printed on many short lines (base64
// wraps at 76 columns) is matched at a page edge too (review N24).
const maskContextLines = 200

// contextBytes is implemented by maskers that know the longest text they
// match (Engine).
type contextBytes interface{ ContextBytes() int }

// maskDepth is the masking context of a read.
func (b *Broker) maskDepth() Depth {
	d := Depth{Lines: maskContextLines}
	if cb, ok := b.masker.(contextBytes); ok {
		d.Bytes = cb.ContextBytes()
	}
	return d
}

// joinWrapped joins lines the masker's way: a soft-wrapped line continues
// on the next without a separator, a hard line end is "\n".
func joinWrapped(lines []string, wrapped []bool) string {
	var b strings.Builder
	for i, l := range lines {
		b.WriteString(l)
		if i >= len(wrapped) || !wrapped[i] {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// settle waits briefly until the program stops printing, so an agent
// read does not catch a value half printed or half scrolled (the part on
// screen alone may not match). It waits at most 400 ms. Best effort: a
// value that arrives in pieces more than 80 ms apart can show its head
// (docs/mcp.md, Masking). It goes by the output time agents see, frozen
// in private mode and during secret input, so its delay does not trace
// activity they may not see.
func (b *Broker) settle() {
	const quiet, most = 80 * time.Millisecond, 400 * time.Millisecond
	deadline := time.Now().Add(most)
	for {
		b.mu.Lock()
		since := time.Since(b.agentLastOutput)
		b.mu.Unlock()
		if since >= quiet || !time.Now().Before(deadline) {
			return
		}
		time.Sleep(min(quiet-since, time.Until(deadline)))
	}
}

// errMasking is what an agent gets when the masker does not return one row
// per row: never the unmasked text.
func errMasking() *proto.Error {
	return proto.Errorf(proto.ErrInternal, "masking failed; the text is withheld")
}

// screen returns the masked agent view.
func (b *Broker) screen(context int) (proto.Screen, *proto.Error) {
	v := b.model.ReadScreen(context, b.maskDepth())
	all := append(append([]string(nil), v.Context...), v.Rows...)
	top := v.CursorSince - int64(len(v.Context))
	res := b.masker.MaskScreen(joinWrapped(v.Above, v.AboveWrap), all, v.Cols)
	if len(res.Rows) != len(all) {
		b.logf("masking: masker returned %d rows for %d; screen withheld", len(res.Rows), len(all))
		return proto.Screen{}, errMasking()
	}
	b.logHits(res.Hits, top)
	col := v.Col
	if cr := len(v.Context) + v.Row; v.Row >= 0 && cr < len(all) {
		col = maskedColumn(all[cr], res.Rows[cr], v.Col, res.Edits, cr)
	}
	b.mu.Lock()
	st := b.stateLocked()
	b.mu.Unlock()
	return proto.Screen{
		Rows: res.Rows[len(v.Context):], Wrapped: v.Wrapped, Context: res.Rows[:len(v.Context)],
		Cursor: proto.Cursor{Row: v.Row, Col: col, Visible: v.Visible},
		RowsN:  len(v.Rows), Cols: st.Cols, AltScreen: v.AltScreen, CursorSince: v.CursorSince, State: st,
	}, nil
}

// maskedColumn moves a cursor column on a masked row with the text: after
// a span it moves by the difference between the replacement and the span
// (the raw column would tell the value's length), inside a span it is
// reported at the start of the replacement. Columns are terminal cells.
func maskedColumn(in, out string, col int, edits []MaskEdit, row int) int {
	c := col
	for _, ed := range edits {
		if ed.Row != row {
			continue
		}
		if ed.InEnd > len(in) || ed.OutEnd > len(out) {
			return 0 // inconsistent edits: tell nothing
		}
		inA, inZ := ansi.StringWidth(in[:ed.InStart]), ansi.StringWidth(in[:ed.InEnd])
		if col < inA {
			break
		}
		if col < inZ {
			return ansi.StringWidth(out[:ed.OutStart])
		}
		c = ansi.StringWidth(out[:ed.OutEnd]) + col - inZ
	}
	return c
}

// since returns masked committed lines. The masker sees up to 200
// committed lines before the read, and the 200 after it followed by the
// screen, all taken under one model lock, so a value split by the edges
// of this read is masked on both sides. One line comes back per line, so
// callers can index into the result.
func (b *Broker) since(cursor int64, limit int) (proto.Since, *proto.Error) {
	d := b.maskDepth()
	r := b.model.ReadSince(cursor, limit, d, d)
	if len(r.Lines) == 0 {
		return proto.Since{Lines: []string{}, Wrapped: []bool{}, Cursor: r.Next, First: r.First, Truncated: r.Truncated}, nil
	}
	res := b.masker.MaskLines(joinWrapped(r.Before, r.BeforeWrap), r.Lines, r.Wrapped, joinWrapped(r.After, r.AfterWrap))
	if len(res.Rows) != len(r.Lines) {
		b.logf("masking: masker returned %d lines for %d; since withheld", len(res.Rows), len(r.Lines))
		return proto.Since{}, errMasking()
	}
	b.logHits(res.Hits, r.First)
	return proto.Since{Lines: res.Rows, Wrapped: r.Wrapped, Cursor: r.Next, First: r.First, Truncated: r.Truncated}, nil
}

// wait blocks until a condition holds or the timeout passes.
func (b *Broker) wait(c *conn, a proto.WaitArgs) (any, *proto.Error) {
	timeout := time.Duration(a.TimeoutMS) * time.Millisecond
	if a.TimeoutMS <= 0 {
		timeout = 10 * time.Second
	}
	timeout = min(timeout, 300*time.Second)
	idle := time.Duration(a.IdleMS) * time.Millisecond
	if a.IdleMS <= 0 {
		idle = 500 * time.Millisecond
	}
	var re *regexp.Regexp
	if a.For == proto.WaitRegex {
		var err error
		if re, err = regexp.Compile(a.Pattern); err != nil {
			return nil, proto.Errorf(proto.ErrBadRequest, "pattern: %v", err)
		}
	}
	switch a.For {
	case proto.WaitIdle, proto.WaitPrompt, proto.WaitRegex, proto.WaitChange, proto.WaitSecretEnded, proto.WaitConfirmation:
	default:
		return nil, proto.Errorf(proto.ErrBadRequest, "unknown wait condition %q", a.For)
	}
	deadline := time.Now().Add(timeout)
	b.mu.Lock()
	startSeq := b.agentSeq
	b.mu.Unlock()
	// A regex wait re-masks only when the output or private mode changed
	// since its last match attempt (the masked text is the same
	// otherwise), and lets the output settle first.
	type regexKey struct {
		seq     int64
		private bool
		masks   int64 // b.maskGen: a value added by term_mask
	}
	var regexChecked *regexKey
	_, _, _, _, startMarks := b.model.ShellState()
	startCursor := b.model.CursorSince()
	result := func(matched bool, reason, match string) (any, *proto.Error) {
		b.mu.Lock()
		st := b.stateLocked()
		b.mu.Unlock()
		return proto.WaitResult{Matched: matched, Reason: reason, Match: match, State: st}, nil
	}
	for {
		b.mu.Lock()
		gen := b.gen
		ended := b.ended
		// What the agent may see: frozen in private mode and during secret
		// input (review B1, B2).
		lastOut := b.agentLastOutput
		seq := b.agentSeq
		secret := b.secretReported
		if b.private && b.privateState != nil {
			secret = b.privateState.SecretInput == proto.SecretActive
		}
		pending := b.pending != nil
		answer := b.lastConfirm
		b.mu.Unlock()
		if ended {
			return nil, proto.Errorf(proto.ErrSessionEnded, "the session ended")
		}
		next := time.Until(deadline)
		switch a.For {
		case proto.WaitChange:
			if seq != startSeq {
				return result(true, proto.WaitChange, "")
			}
		case proto.WaitSecretEnded:
			if !secret {
				return result(true, proto.WaitSecretEnded, "")
			}
		case proto.WaitConfirmation:
			if !pending {
				// match tells how the person answered the last held line:
				// "accepted" or "denied" ("" if none was answered yet).
				return result(true, proto.WaitConfirmation, answer)
			}
		case proto.WaitPrompt, proto.WaitIdle:
			if a.For == proto.WaitPrompt {
				integ, _, _, _, marks := b.model.ShellState()
				if marks != startMarks {
					return result(true, proto.WaitPrompt, "")
				}
				if integ {
					break
				}
			}
			since := time.Since(lastOut)
			if since >= idle {
				return result(true, proto.WaitIdle, "")
			}
			next = min(next, idle-since)
		case proto.WaitRegex:
			b.mu.Lock()
			key := regexKey{b.outputSeq, b.private, b.maskGen.Load()}
			b.mu.Unlock()
			if regexChecked != nil && *regexChecked == key {
				break
			}
			b.settle()
			b.mu.Lock()
			key = regexKey{b.outputSeq, b.private, b.maskGen.Load()}
			b.mu.Unlock()
			if m, ok := b.regexMatch(re, startCursor); ok {
				return result(true, proto.WaitRegex, m)
			}
			regexChecked = &key
		}
		if next <= 0 {
			return result(false, "timeout", "")
		}
		t := time.NewTimer(next)
		select {
		case <-gen:
		case <-t.C:
		case <-c.done:
			t.Stop()
			return nil, proto.Errorf(proto.ErrSessionEnded, "connection closed")
		}
		t.Stop()
	}
}

// regexMatch matches the masked screen and the lines committed since the
// wait started.
func (b *Broker) regexMatch(re *regexp.Regexp, startCursor int64) (string, bool) {
	sc, e1 := b.screen(0)
	sn, e2 := b.since(startCursor, 5000)
	if e1 != nil || e2 != nil {
		return "", false
	}
	for _, text := range []string{
		strings.Join(sc.Rows, "\n"),
		strings.Join(sn.Lines, "\n"),
	} {
		if loc := re.FindStringIndex(text); loc != nil {
			return text[loc[0]:loc[1]], true
		}
	}
	return "", false
}

// String describes a connection for logs.
func (c *conn) String() string {
	return fmt.Sprintf("%s pid %d %s", c.role, c.info.PID, c.info.Exe)
}
