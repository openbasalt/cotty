package attach

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/openbasalt/cotty/internal/peer"
	"github.com/openbasalt/cotty/internal/proto"
	"github.com/openbasalt/cotty/internal/session"
)

// Before the person's client sends anything that matters (keystrokes,
// a proof of the reattach code) it checks that the process listening on
// the session socket is the session's broker. Any process of the user can
// unlink the socket and listen in its place (review B3), so:
//
//  1. the runtime directory must be the user's, mode 0700, not a link, and
//     the socket the user's, mode 0600;
//  2. the listener (SO_PEERCRED of the connection: the process that called
//     listen) must run as the user and be the process the session's
//     metadata names, with the same start time; when `cotty new` started
//     the broker itself it must be that very child;
//  3. the listener must look like a broker: not dumpable (/proc/PID owned
//     by root, as harden.Process makes it), the same comm as this binary,
//     and `__broker` as its first argument;
//  4. with the guard (layer 3) loaded, a BrokerVerifier asks it, as root,
//     whether the listener is the registered broker of this session (the
//     first broker that registered the session name and still runs) and
//     runs the root-owned cotty binary (the exe of a non-dumpable process
//     is unreadable to the user). When the guard enforces but does not
//     answer, the caller gets an error instead of a verifier and refuses
//     to attach;
//  5. every admission proves a secret, the creator token or the reattach
//     code, never sent (proto/auth.go), and the broker must prove it back:
//     a success without the broker's proof is refused, whatever the
//     listener answers (an "approval" or "insecure" admission included,
//     unless the client itself asked for insecure mode). A fake listener
//     cannot produce that proof and learns nothing it could replay.
//
// Checks 2 and 3 are consistency checks: a process of the user can forge
// the metadata, its comm and its argv and make itself non-dumpable. They
// stop accidents and lazy fakes. Check 5 is the one that holds without the
// guard: a forged listener never gets past it, so it never receives a
// keystroke and nothing it sends reaches the person's terminal. The most
// it gets is a proof of the code bound to its own nonce and pid, which it
// can neither relay nor test guesses against faster than the key
// derivation allows.

// BrokerVerifier checks, with more authority than the user has, that the
// listener of a session socket is a real cotty broker. cotty-guard (layer
// 3, running as root) is meant to provide it; see the PR notes for the
// guard side. A nil verifier means consistency checks only.
type BrokerVerifier interface {
	// VerifyBroker gets the client's connected socket, the session name
	// and the listener's pid as SO_PEERCRED gives it. It returns nil when
	// the listener is the session's registered broker and runs the
	// root-owned cotty binary.
	VerifyBroker(conn *net.UnixConn, session string, pid int) error
}

// ConnectOptions configures Connect.
type ConnectOptions struct {
	Socket  string
	Session string
	Hello   proto.Hello // role, client, rows, cols
	// CreatorToken, when set, is proven to the broker (cotty new).
	CreatorToken string
	// BrokerPID, when set, is the pid the listener must have (cotty new
	// started the broker and knows its pid).
	BrokerPID int
	// Verifier is the guard's broker check (nil: consistency checks only).
	Verifier BrokerVerifier
	// PromptCode asks the person for the reattach code; wrong is true after
	// a wrong code.
	PromptCode func(wrong bool) (string, error)
	// Waiting is called once if admission takes a while (approval).
	Waiting func()
	// Harden, when set, is called once before the person is asked for the
	// reattach code: the process that holds the typed code must not be
	// dumpable from then on. It cannot run before the first hello: the
	// broker classifies the client from its /proc files, which a
	// non-dumpable process hides from the user.
	Harden func() error
	// Insecure accepts a broker started with -dev-insecure, which admits
	// without any secret (the caller asked for it explicitly). Without it
	// such a broker is refused.
	Insecure bool
}

// ErrNotBroker is wrapped by Connect when the listener fails a check.
var ErrNotBroker = errors.New("the process listening on the session socket is not the session's broker")

// Connect dials the session socket, checks the listener and performs the
// hello exchange, proving the creator token or the reattach code when
// needed.
func Connect(o ConnectOptions) (*proto.Client, proto.HelloResult, error) {
	if err := session.CheckSocket(o.Socket); err != nil {
		return nil, proto.HelloResult{}, fmt.Errorf("%w: %v", ErrNotBroker, err)
	}
	conn, err := net.DialTimeout("unix", o.Socket, 5*time.Second)
	if err != nil {
		return nil, proto.HelloResult{}, err
	}
	cl := proto.NewClient(conn)
	fail := func(err error) (*proto.Client, proto.HelloResult, error) {
		_ = cl.Close()
		return nil, proto.HelloResult{}, err
	}
	pid, uid, err := cl.PeerCred()
	if err != nil {
		return fail(err)
	}
	if err := listenerCheck(o, pid, uid); err != nil {
		return fail(fmt.Errorf("%w: %v", ErrNotBroker, err))
	}
	if o.Verifier != nil {
		uc, _ := conn.(*net.UnixConn)
		if err := o.Verifier.VerifyBroker(uc, o.Session, pid); err != nil {
			return fail(fmt.Errorf("%w: cotty-guard: %v", ErrNotBroker, err))
		}
	}
	h := o.Hello
	h.Auth, h.Proof, h.Nonce = "", "", proto.NewNonce()
	switch {
	case o.CreatorToken != "":
		h.Auth = proto.AuthCreator
	case !o.Insecure:
		// Ask for the code challenge: the broker must prove the code back.
		h.Auth = proto.AuthCode
	}
	hello := func() (proto.HelloResult, error) {
		var waiting *time.Timer
		if o.Waiting != nil && h.Auth == proto.AuthCode && h.Proof != "" {
			// After the code: an attached person may have to approve.
			waiting = time.AfterFunc(700*time.Millisecond, o.Waiting)
		}
		res, err := cl.Hello(context.Background(), h)
		if waiting != nil {
			waiting.Stop()
		}
		return res, err
	}
	res, err := hello()
	var key, tr []byte
	defer func() { clear(key) }()
	for attempt := 0; ; attempt++ {
		if err == nil {
			if aerr := checkAdmission(o, res, key, tr); aerr != nil {
				return fail(aerr)
			}
			return cl, res, nil
		}
		var pe *proto.Error
		if attempt >= 4 || !errors.As(err, &pe) || pe.Challenge == nil ||
			(pe.Code != proto.ErrCodeRequired && pe.Code != proto.ErrCodeInvalid) {
			return fail(err)
		}
		ch := pe.Challenge
		if len(ch.Nonce) != 2*proto.NonceLen {
			return fail(fmt.Errorf("%w: malformed challenge", ErrNotBroker))
		}
		switch ch.Kind {
		case proto.AuthCreator:
			if o.CreatorToken == "" || h.Proof != "" {
				return fail(err)
			}
			key = proto.TokenKey(o.CreatorToken)
		case proto.AuthCode:
			if o.PromptCode == nil {
				return fail(err)
			}
			salt, derr := hexBytes(ch.Salt)
			if derr != nil || len(salt) < 8 || ch.Iterations < proto.CodeKDFIterations ||
				ch.Iterations > 50*proto.CodeKDFIterations {
				return fail(fmt.Errorf("%w: unacceptable key derivation parameters", ErrNotBroker))
			}
			if o.Harden != nil {
				if herr := o.Harden(); herr != nil {
					return fail(herr)
				}
			}
			code, perr := o.PromptCode(pe.Code == proto.ErrCodeInvalid)
			if perr != nil {
				return fail(perr)
			}
			clear(key)
			key = proto.CodeKey(code, salt, ch.Iterations)
		default:
			return fail(fmt.Errorf("%w: unknown challenge %q", ErrNotBroker, ch.Kind))
		}
		h.Auth, h.Nonce = ch.Kind, proto.NewNonce()
		tr = proto.Transcript(ch.Kind, h.Role, o.Session, h.Nonce, ch.Nonce, os.Getpid(), pid)
		h.Proof = proto.Proof(key, proto.SideClient, tr)
		res, err = hello()
	}
}

// checkAdmission decides whether a successful hello came from the
// session's broker: it must carry the broker's proof of the secret this
// client proved (key, over transcript tr), and with a creator token it
// must be a creator admission. The only exception is an insecure
// admission the caller asked for (ConnectOptions.Insecure).
func checkAdmission(o ConnectOptions, res proto.HelloResult, key, tr []byte) error {
	if key == nil {
		if o.Insecure && o.CreatorToken == "" && res.Admission == "insecure" {
			return nil
		}
		if res.Admission == "insecure" {
			return fmt.Errorf("%w: it admits without a secret (a -dev-insecure broker); attach with --dev-insecure if you started it so", ErrNotBroker)
		}
		return fmt.Errorf("%w: it admitted this client (admission %q) without proving the creator token or the reattach code", ErrNotBroker, res.Admission)
	}
	if o.CreatorToken != "" && res.Admission != "creator" {
		return fmt.Errorf("%w: admission %q where the creator token was proven", ErrNotBroker, res.Admission)
	}
	if !proto.ProofEqual(res.ServerProof, proto.Proof(key, proto.SideServer, tr)) {
		// We proved a secret: the broker must prove it too, or it is not
		// the broker that issued it.
		return fmt.Errorf("%w: it did not prove knowledge of the %s", ErrNotBroker, authName(authKind(o)))
	}
	return nil
}

func authKind(o ConnectOptions) string {
	if o.CreatorToken != "" {
		return proto.AuthCreator
	}
	return proto.AuthCode
}

func authName(kind string) string {
	if kind == proto.AuthCreator {
		return "creator token"
	}
	return "reattach code"
}

func hexBytes(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	if len(s)%2 != 0 {
		return nil, errors.New("odd length")
	}
	for i := range b {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		b[i] = byte(v)
	}
	return b, nil
}

// procRoot is where procfs is mounted (a variable for tests).
var procRoot = "/proc"

// listenerCheck is checkListener (a variable for tests).
var listenerCheck = checkListener

// checkListener applies checks 2 and 3 (see the comment at the top).
func checkListener(o ConnectOptions, pid, uid int) error {
	if uid != os.Getuid() {
		return fmt.Errorf("listener runs as uid %d", uid)
	}
	if pid <= 0 {
		return errors.New("listener pid not visible (other pid namespace)")
	}
	st, err := peer.ReadStat(pid)
	if err != nil {
		return fmt.Errorf("listener pid %d: %v", pid, err)
	}
	if o.BrokerPID > 0 {
		if pid != o.BrokerPID {
			return fmt.Errorf("listener is pid %d, the broker cotty new started is pid %d", pid, o.BrokerPID)
		}
	} else {
		meta, err := session.ReadMeta(strings.TrimSuffix(o.Socket, ".sock") + ".json")
		if err != nil {
			return fmt.Errorf("session metadata: %v", err)
		}
		if meta.BrokerPID != pid {
			return fmt.Errorf("listener is pid %d, the session's broker is pid %d", pid, meta.BrokerPID)
		}
		if meta.BrokerStart != 0 && meta.BrokerStart != st.StartTime {
			return fmt.Errorf("listener pid %d started at %d, the session's broker at %d", pid, st.StartTime, meta.BrokerStart)
		}
	}
	return looksLikeBroker(pid, st)
}

// looksLikeBroker checks that pid is not dumpable (harden.Process) and
// runs this binary's name with the __broker subcommand.
func looksLikeBroker(pid int, st peer.Stat) error {
	p := filepath.Join(procRoot, strconv.Itoa(pid))
	// The files of a non-dumpable process belong to root (the /proc/PID
	// directory itself keeps the user's uid).
	fi, err := os.Stat(filepath.Join(p, "status"))
	if err != nil {
		return err
	}
	if s, ok := fi.Sys().(*syscall.Stat_t); !ok || s.Uid != 0 {
		return fmt.Errorf("listener pid %d is dumpable (a broker never is)", pid)
	}
	self, err := os.ReadFile(filepath.Join(procRoot, "self", "comm"))
	if err == nil && strings.TrimSpace(string(self)) != st.Comm {
		return fmt.Errorf("listener pid %d runs %q, not %q", pid, st.Comm, strings.TrimSpace(string(self)))
	}
	cmd, err := os.ReadFile(filepath.Join(p, "cmdline"))
	if err != nil {
		return err
	}
	args := strings.Split(string(cmd), "\x00")
	if len(args) < 2 || args[1] != "__broker" {
		return fmt.Errorf("listener pid %d is not a cotty broker", pid)
	}
	return nil
}
