package attach

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openbasalt/cotty/internal/proto"
)

// fakeBroker serves one connection: it asks for the reattach code, then
// answers the proof. honest computes the server proof with the code;
// clientPID overrides the client pid in its transcript (a relay sees
// another pid).
type fakeBroker struct {
	code      string
	honest    bool
	clientPID int
	// admitWithout, when set, admits the first hello at once, without a
	// challenge or a proof, as this admission kind (a forged listener,
	// review N1).
	admitWithout string
	mu           sync.Mutex
	received     []string
}

func (f *fakeBroker) serve(t *testing.T, ln net.Listener) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	salt := []byte("0123456789abcdef")
	var ch *proto.Challenge
	for {
		fr, err := proto.ReadFrame(c)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.received = append(f.received, string(fr.Payload))
		f.mu.Unlock()
		var req proto.Request
		_ = json.Unmarshal(fr.Payload, &req)
		var h proto.Hello
		_ = json.Unmarshal(req.Args, &h)
		if f.admitWithout != "" {
			_ = proto.WriteJSON(c, proto.Response{ID: req.ID, OK: true,
				Result: proto.HelloResult{V: 1, Session: "s", Role: h.Role, Admission: f.admitWithout}})
			continue
		}
		if h.Proof == "" {
			ch = &proto.Challenge{Kind: proto.AuthCode, Nonce: proto.NewNonce(), Salt: hex.EncodeToString(salt),
				Iterations: proto.CodeKDFIterations}
			_ = proto.WriteJSON(c, proto.Response{ID: req.ID, Error: &proto.Error{Code: proto.ErrCodeRequired, Challenge: ch}})
			continue
		}
		res := proto.HelloResult{V: 1, Session: "s", Role: h.Role, Admission: "code"}
		if f.honest {
			key := proto.CodeKey(f.code, salt, ch.Iterations)
			cpid := os.Getpid()
			if f.clientPID != 0 {
				cpid = f.clientPID
			}
			tr := proto.Transcript(ch.Kind, h.Role, "s", h.Nonce, ch.Nonce, cpid, os.Getpid())
			res.ServerProof = proto.Proof(key, proto.SideServer, tr)
		} else {
			res.ServerProof = strings.Repeat("ab", 32)
		}
		_ = proto.WriteJSON(c, proto.Response{ID: req.ID, OK: true, Result: res})
	}
}

func listenFake(t *testing.T, f *fakeBroker) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cotty")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(sock, 0o600)
	t.Cleanup(func() { _ = ln.Close() })
	go f.serve(t, ln)
	return sock
}

func noListenerCheck(t *testing.T) {
	old := listenerCheck
	listenerCheck = func(ConnectOptions, int, int) error { return nil }
	t.Cleanup(func() { listenerCheck = old })
}

func connectFake(sock string) error {
	cl, _, err := Connect(ConnectOptions{Socket: sock, Session: "s",
		Hello:      proto.Hello{Role: proto.RolePerson},
		PromptCode: func(bool) (string, error) { return "K7Q2M-9XWZT", nil }})
	if cl != nil {
		_ = cl.Close()
	}
	return err
}

// TestConnectFakeListener: a listener that does not know the code never
// sees it and is refused (review B3).
func TestConnectFakeListener(t *testing.T) {
	noListenerCheck(t)
	f := &fakeBroker{code: "K7Q2M-9XWZT"}
	err := connectFake(listenFake(t, f))
	if !errors.Is(err, ErrNotBroker) {
		t.Fatalf("fake listener accepted: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.received {
		if strings.Contains(strings.ToUpper(r), "K7Q2M") || strings.Contains(r, "9XWZT") {
			t.Fatalf("the code reached the listener: %s", r)
		}
	}
}

// TestConnectRelay: a broker that saw another client pid (a relay in the
// middle) cannot produce the proof the client expects.
func TestConnectRelay(t *testing.T) {
	noListenerCheck(t)
	err := connectFake(listenFake(t, &fakeBroker{code: "K7Q2M-9XWZT", honest: true, clientPID: os.Getpid() + 1}))
	if !errors.Is(err, ErrNotBroker) {
		t.Fatalf("relayed proof accepted: %v", err)
	}
}

func TestConnectHonest(t *testing.T) {
	noListenerCheck(t)
	if err := connectFake(listenFake(t, &fakeBroker{code: "k7q2m 9xwzt", honest: true})); err != nil {
		t.Fatalf("honest broker refused: %v", err)
	}
}

// TestConnectChecksSocket: the socket must sit in a private directory.
func TestConnectChecksSocket(t *testing.T) {
	noListenerCheck(t)
	sock := listenFake(t, &fakeBroker{code: "K7Q2M-9XWZT", honest: true})
	if err := os.Chmod(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := connectFake(sock); !errors.Is(err, ErrNotBroker) {
		t.Fatalf("open runtime directory accepted: %v", err)
	}
}

// TestCheckListenerSelf: the test process is not a broker (dumpable, not
// __broker), so the consistency checks refuse it.
func TestCheckListenerSelf(t *testing.T) {
	err := checkListener(ConnectOptions{BrokerPID: os.Getpid(), Socket: "/nonexistent/x.sock"}, os.Getpid(), os.Getuid())
	if err == nil {
		t.Fatal("the test process passed for a broker")
	}
	if err := checkListener(ConnectOptions{BrokerPID: 1, Socket: "/x.sock"}, os.Getpid(), os.Getuid()); err == nil ||
		!strings.Contains(err.Error(), "cotty new started") {
		t.Fatalf("pid mismatch: %v", err)
	}
	if err := checkListener(ConnectOptions{BrokerPID: os.Getpid()}, os.Getpid(), os.Getuid()+1); err == nil {
		t.Fatal("other uid accepted")
	}
}

// TestConnectForgedAdmission: a forged listener that admits the client at
// once, as if an attached person had approved or as a -dev-insecure
// broker, proves no secret: refused before the code is even asked for
// (review N1).
func TestConnectForgedAdmission(t *testing.T) {
	noListenerCheck(t)
	for _, kind := range []string{"approval", "insecure", "code", "code+approval", "creator"} {
		asked := false
		cl, _, err := Connect(ConnectOptions{Socket: listenFake(t, &fakeBroker{admitWithout: kind}), Session: "s",
			Hello: proto.Hello{Role: proto.RolePerson},
			PromptCode: func(bool) (string, error) {
				asked = true
				return "K7Q2M-9XWZT", nil
			}})
		if cl != nil {
			_ = cl.Close()
		}
		if !errors.Is(err, ErrNotBroker) {
			t.Errorf("%s admission without proof accepted: %v", kind, err)
		}
		if asked {
			t.Errorf("%s: the person was asked for the code by a listener that admitted without a challenge", kind)
		}
	}
}

// TestConnectInsecureOnlyWhenAsked: an insecure admission passes only when
// the client itself asked for insecure mode.
func TestConnectInsecureOnlyWhenAsked(t *testing.T) {
	noListenerCheck(t)
	cl, _, err := Connect(ConnectOptions{Socket: listenFake(t, &fakeBroker{admitWithout: "insecure"}), Session: "s",
		Hello: proto.Hello{Role: proto.RolePerson}, Insecure: true})
	if err != nil {
		t.Fatalf("insecure broker refused in insecure mode: %v", err)
	}
	_ = cl.Close()
	// An "approval" stays refused even in insecure mode.
	_, _, err = Connect(ConnectOptions{Socket: listenFake(t, &fakeBroker{admitWithout: "approval"}), Session: "s",
		Hello: proto.Hello{Role: proto.RolePerson}, Insecure: true})
	if !errors.Is(err, ErrNotBroker) {
		t.Fatalf("approval without proof accepted in insecure mode: %v", err)
	}
}

// TestConnectCreatorNeedsProof: with a creator token, a success without
// the broker's proof is refused.
func TestConnectCreatorNeedsProof(t *testing.T) {
	noListenerCheck(t)
	_, _, err := Connect(ConnectOptions{Socket: listenFake(t, &fakeBroker{admitWithout: "creator"}), Session: "s",
		Hello: proto.Hello{Role: proto.RolePerson}, CreatorToken: "00112233"})
	if !errors.Is(err, ErrNotBroker) {
		t.Fatalf("creator admission without proof accepted: %v", err)
	}
}

type recordingVerifier struct {
	session string
	pid     int
	err     error
}

func (v *recordingVerifier) VerifyBroker(_ *net.UnixConn, session string, pid int) error {
	v.session, v.pid = session, pid
	return v.err
}

// TestConnectVerifierGetsSession: the guard is asked about this session's
// broker (by name), and its refusal stops the client.
func TestConnectVerifierGetsSession(t *testing.T) {
	noListenerCheck(t)
	v := &recordingVerifier{}
	cl, _, err := Connect(ConnectOptions{Socket: listenFake(t, &fakeBroker{code: "K7Q2M-9XWZT", honest: true}), Session: "s",
		Hello: proto.Hello{Role: proto.RolePerson}, Verifier: v,
		PromptCode: func(bool) (string, error) { return "K7Q2M-9XWZT", nil }})
	if err != nil {
		t.Fatal(err)
	}
	_ = cl.Close()
	if v.session != "s" || v.pid != os.Getpid() {
		t.Fatalf("verifier asked about %q pid %d", v.session, v.pid)
	}
	v = &recordingVerifier{err: errors.New("not the registered broker of this session")}
	_, _, err = Connect(ConnectOptions{Socket: listenFake(t, &fakeBroker{code: "K7Q2M-9XWZT", honest: true}), Session: "s",
		Hello: proto.Hello{Role: proto.RolePerson}, Verifier: v,
		PromptCode: func(bool) (string, error) { t.Error("code asked after the guard refused"); return "", nil }})
	if !errors.Is(err, ErrNotBroker) {
		t.Fatalf("refused by the guard, yet: %v", err)
	}
}
