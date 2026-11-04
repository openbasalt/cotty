// Package proto implements the broker socket protocol, version 1. The
// contract is docs/protocol.md; this package holds the framing, the
// message envelopes and the shared types so the broker, the attach client
// and the MCP server agree byte for byte.
package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version this package speaks.
const Version = 1

// MaxFrame is the largest frame length (type byte plus payload).
const MaxFrame = 1 << 20

// Frame types.
const (
	FrameJSON byte = 'j'
	FrameData byte = 'd'
)

// Roles a client may request in hello.
const (
	RoleAgent   = "agent"
	RolePerson  = "person"
	RoleControl = "control"
	RoleInfo    = "info"
)

// Assurance levels (docs/protocol.md section 6).
const (
	AssuranceStrong   = "strong"
	AssuranceConfined = "confined"
	AssuranceWeak     = "weak"
	AssuranceInsecure = "insecure"
)

// Error codes (docs/protocol.md section 11).
const (
	ErrHelloRequired       = "hello_required"
	ErrVersionUnsupported  = "version_unsupported"
	ErrRoleDenied          = "role_denied"
	ErrNotShared           = "not_shared"
	ErrCodeRequired        = "code_required"
	ErrCodeInvalid         = "code_invalid"
	ErrRateLimited         = "rate_limited"
	ErrApprovalDenied      = "approval_denied"
	ErrApprovalUnavailable = "approval_unavailable" // reserved: brokers ask for the code instead (review N11)
	ErrBadRequest          = "bad_request"
	ErrUnknownOp           = "unknown_op"
	ErrForbidden           = "forbidden"
	ErrPrivateMode         = "private_mode"
	ErrSecretInputActive   = "secret_input_active"
	ErrKeyboardHeld        = "keyboard_held"
	ErrPersonTyping        = "person_typing"
	ErrConfirmationPending = "confirmation_pending"
	ErrPolicyDenied        = "policy_denied"
	ErrNoPending           = "no_pending"
	ErrUnknownSecret       = "unknown_secret"
	ErrUnsupported         = "unsupported"
	ErrSessionEnded        = "session_ended"
	ErrInternal            = "internal"
	// ErrConfinementRequired: the session was started or shared with
	// --require-confined and the agent peer is not confined.
	ErrConfinementRequired = "confinement_required"
	// ErrConfirmationStale: the held agent line changed on screen after it
	// was shown to the person; it can only be denied.
	ErrConfirmationStale = "confirmation_stale"
	// ErrTooManyRequests: a per-connection or per-session cap was hit.
	ErrTooManyRequests = "too_many_requests"
)

// ErrFrameTooLarge is returned for frames above MaxFrame.
var ErrFrameTooLarge = errors.New("proto: frame too large")

// Frame is one decoded frame.
type Frame struct {
	Type    byte
	Payload []byte
}

// WriteFrame writes one frame. Callers serialize writes on a connection.
func WriteFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload)+1 > MaxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)+1))
	buf[4] = typ
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	clear(buf)
	return err
}

// ReadFrame reads one frame.
func ReadFrame(r io.Reader) (Frame, error) { return ReadFrameMax(r, MaxFrame) }

// ReadFrameMax reads one frame of at most max bytes. The payload buffer
// grows with the bytes that actually arrive, so a header that announces a
// large frame costs nothing until the peer sends it.
func ReadFrameMax(r io.Reader, max uint32) (Frame, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:4]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n == 0 || n > max || n > MaxFrame {
		return Frame{}, ErrFrameTooLarge
	}
	if _, err := io.ReadFull(r, hdr[4:5]); err != nil {
		return Frame{}, unexpected(err)
	}
	want := int64(n - 1)
	var buf bytes.Buffer
	buf.Grow(int(min(want, 4096)))
	got, err := buf.ReadFrom(io.LimitReader(r, want))
	if err != nil {
		return Frame{}, unexpected(err)
	}
	if got != want {
		return Frame{}, io.ErrUnexpectedEOF
	}
	return Frame{Type: hdr[4], Payload: buf.Bytes()}, nil
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// WriteJSON marshals v and writes it as a JSON frame.
func WriteJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return WriteFrame(w, FrameJSON, b)
}

// Request is a client request.
type Request struct {
	ID   int64           `json:"id"`
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Error is the error object of a failed response.
type Error struct {
	Code         string `json:"code"`
	Message      string `json:"message,omitempty"`
	RetryAfterMS int64  `json:"retry_after_ms,omitempty"`
	// Challenge comes with code_required and code_invalid.
	Challenge *Challenge `json:"challenge,omitempty"`
}

func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// Errorf builds an Error with a formatted message.
func Errorf(code, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// Response answers a request.
type Response struct {
	ID     int64  `json:"id"`
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  *Error `json:"error,omitempty"`
}

// RawResponse is a response as a client decodes it.
type RawResponse struct {
	ID     int64           `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
	// Event and Data are set instead for events.
	Event string          `json:"event,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Event is an unsolicited broker message.
type Event struct {
	Event string `json:"event"`
	Data  any    `json:"data,omitempty"`
}

// Event names.
const (
	EventState         = "state"
	EventOutput        = "output"
	EventStatus        = "status"
	EventAttachRequest = "attach_request"
	EventEnded         = "ended"
)

// Hello is the hello request's args.
type Hello struct {
	V      int    `json:"v"`
	Role   string `json:"role"`
	Client string `json:"client,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Cols   int    `json:"cols,omitempty"`
	// Auth asks for admission by a shared secret (AuthCreator or
	// AuthCode); the secret itself never crosses the socket (auth.go).
	Auth string `json:"auth,omitempty"`
	// Nonce is the client's fresh nonce for the admission proofs (hex).
	Nonce string `json:"nonce,omitempty"`
	// Proof is the client's proof for the broker's last challenge on this
	// connection (hex); empty asks for a challenge.
	Proof string `json:"proof,omitempty"`
}

// HelloResult is the hello response.
type HelloResult struct {
	V               int    `json:"v"`
	Session         string `json:"session"`
	Role            string `json:"role"`
	Assurance       string `json:"assurance"`
	AssuranceReason string `json:"assurance_reason,omitempty"`
	BrokerPID       int    `json:"broker_pid"`
	Policy          string `json:"policy"`
	Shared          bool   `json:"shared"`
	// Admission is how the broker admitted a person or control
	// connection: creator, code, code+approval (the code, then the
	// attached person approved) or insecure.
	Admission string `json:"admission,omitempty"`
	// ServerProof is the broker's proof that it knows the secret the
	// client proved (creator and code admission only).
	ServerProof string `json:"server_proof,omitempty"`
}

// Info is the info result.
type Info struct {
	Session   string `json:"session"`
	Created   string `json:"created"`
	BrokerPID int    `json:"broker_pid"`
	Shared    bool   `json:"shared"`
	Policy    string `json:"policy"`
	Persons   int    `json:"persons"`
	Agents    int    `json:"agents"`
	Rows      int    `json:"rows"`
	Cols      int    `json:"cols"`
}

// Program describes the foreground process of the session.
type Program struct {
	PID          int    `json:"pid"`
	Name         string `json:"name"`
	Exe          string `json:"exe,omitempty"`
	Trust        string `json:"trust"` // "system" or "other"
	AgentStarted bool   `json:"agent_started"`
	// Pipeline names every member of the foreground process group when
	// it has more than one (the lock judges all of them).
	Pipeline []string `json:"pipeline,omitempty"`
	// SetuidRoot: the process runs setuid root for the user (sudo, su,
	// passwd); broker-internal, never sent.
	SetuidRoot bool `json:"-"`
	// Exception: the program is outside the session and opened its
	// terminal through cotty-guard's exception list (a pinentry-curses
	// started by gpg-agent with GPG_TTY).
	Exception bool `json:"exception,omitempty"`
	// Outside: without the guard's answer, the broker found the program
	// outside the session holding its terminal while a job read with echo
	// off (never trusted as a system prompt).
	Outside bool `json:"outside,omitempty"`
	// Parent names the parent of an exception or outside program: the
	// process that receives what it reads (gpg-agent for a pinentry).
	Parent string `json:"parent,omitempty"`
}

// Program trust levels (the lock colour).
const (
	TrustSystem = "system" // green lock
	TrustOther  = "other"  // amber lock
)

// Confirmation is a held agent line.
type Confirmation struct {
	// Line is the masked screen line at the cursor when the agent's Enter
	// was held.
	Line string `json:"line"`
	// Typed is what the agent itself sent (masked), to compare with Line.
	Typed string `json:"typed"`
	// Mismatch is true when Line does not end with Typed (something else
	// drew on the cursor line); the person should deny.
	Mismatch bool `json:"mismatch,omitempty"`
}

// Shell is what OSC 133 shell integration marks tell (hints only).
type Shell struct {
	Integration bool   `json:"integration"`
	AtPrompt    bool   `json:"at_prompt"`
	LastCommand string `json:"last_command"`
	ExitCode    *int   `json:"exit_code"`
}

// State is the session state object (docs/protocol.md section 8).
type State struct {
	Session               string        `json:"session"`
	Keyboard              string        `json:"keyboard"`
	PersonTyping          bool          `json:"person_typing"`
	AgentMayType          bool          `json:"agent_may_type"`
	SecretInput           string        `json:"secret_input"`
	SecretProgram         *Program      `json:"secret_program"`
	Foreground            *Program      `json:"foreground"`
	Private               bool          `json:"private"`
	Policy                string        `json:"policy"`
	PendingConfirmation   *Confirmation `json:"pending_confirmation"`
	Shell                 Shell         `json:"shell"`
	AltScreen             bool          `json:"alt_screen"`
	Rows                  int           `json:"rows"`
	Cols                  int           `json:"cols"`
	Persons               int           `json:"persons"`
	Agents                int           `json:"agents"`
	Shared                bool          `json:"shared"`
	Assurance             string        `json:"assurance"`
	AgentRequestsKeyboard bool          `json:"agent_requests_keyboard"`
	CursorSince           int64         `json:"cursor_since"`
	// RequireConfined is true when agent connections with assurance weak
	// are refused (--require-confined).
	RequireConfined bool `json:"require_confined"`
}

// Keyboard values.
const (
	KeyboardHeld = "held"
	KeyboardFree = "free"
)

// Secret input values.
const (
	SecretActive = "active"
	SecretNone   = "none"
)

// Policies.
const (
	PolicyAuto    = "auto"
	PolicyConfirm = "confirm"
)

// AttachRequest describes a person connection waiting for approval.
type AttachRequest struct {
	ID       int64    `json:"id"`
	PID      int      `json:"pid"`
	Exe      string   `json:"exe"`
	TTY      string   `json:"tty"`
	Chain    []string `json:"chain"`
	Role     string   `json:"role"`
	Started  string   `json:"started"`
	Deadline string   `json:"deadline"`
}

// Status is the person's view: the state plus person-only fields.
type Status struct {
	State
	PendingAttach []AttachRequest `json:"pending_attach"`
	AgentText     string          `json:"agent_text"`
	AgentActiveAt string          `json:"agent_active_at,omitempty"`
	// WeakAgents counts connected agents whose assurance is weak (not
	// started through cotty agent); the status line warns about them.
	WeakAgents int `json:"weak_agents"`
	// RefusedAgents counts agent connections refused by
	// --require-confined since the session started.
	RefusedAgents int `json:"refused_agents"`
}

// Cursor is a screen cursor.
type Cursor struct {
	Row     int  `json:"row"`
	Col     int  `json:"col"`
	Visible bool `json:"visible"`
}

// Screen is the screen result.
type Screen struct {
	Rows        []string `json:"rows"`
	Wrapped     []bool   `json:"wrapped"`
	Cursor      Cursor   `json:"cursor"`
	RowsN       int      `json:"rows_n"`
	Cols        int      `json:"cols"`
	AltScreen   bool     `json:"alt_screen"`
	Context     []string `json:"context"`
	CursorSince int64    `json:"cursor_since"`
	State       State    `json:"state"`
}

// Since is the since result.
type Since struct {
	Lines     []string `json:"lines"`
	Wrapped   []bool   `json:"wrapped"`
	Cursor    int64    `json:"cursor"`
	First     int64    `json:"first"`
	Truncated bool     `json:"truncated"`
}

// Sent is the result of type and keys.
type Sent struct {
	Sent      int  `json:"sent"`
	HeldEnter bool `json:"held_enter"`
}

// WaitArgs are the wait args.
type WaitArgs struct {
	For       string `json:"for"`
	TimeoutMS int64  `json:"timeout_ms,omitempty"`
	IdleMS    int64  `json:"idle_ms,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
}

// WaitResult is the wait result.
type WaitResult struct {
	Matched bool   `json:"matched"`
	Reason  string `json:"reason"`
	Match   string `json:"match,omitempty"`
	State   State  `json:"state"`
}

// Wait conditions.
const (
	WaitIdle         = "idle"
	WaitPrompt       = "prompt"
	WaitRegex        = "regex"
	WaitChange       = "change"
	WaitSecretEnded  = "secret_ended"
	WaitConfirmation = "confirmation"
)
