package broker

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/peer"
	"github.com/openbasalt/cotty/internal/proto"
)

func testBroker(t *testing.T) *Broker {
	t.Helper()
	b, err := New(Config{Name: "t1", Dir: t.TempDir(), CreatorToken: "0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.model.Close)
	return b
}

func testConn(pid int, tty uint64) *conn {
	return &conn{info: peer.Info{PID: pid, TTYNr: tty}, done: make(chan struct{}), events: map[string]bool{}}
}

// prove answers a challenge the way the attach client does.
func prove(t *testing.T, b *Broker, c *conn, kind, secret string, ch *proto.Challenge) (proto.Hello, []byte, []byte) {
	t.Helper()
	var key []byte
	if kind == proto.AuthCreator {
		key = proto.TokenKey(secret)
	} else {
		salt, _ := hex.DecodeString(ch.Salt)
		key = proto.CodeKey(secret, salt, ch.Iterations)
	}
	h := proto.Hello{Role: proto.RolePerson, Auth: kind, Nonce: proto.NewNonce()}
	tr := proto.Transcript(kind, h.Role, b.cfg.Name, h.Nonce, ch.Nonce, c.info.PID, os.Getpid())
	h.Proof = proto.Proof(key, proto.SideClient, tr)
	return h, key, tr
}

// TestAdmitCodeProof: the code is proven, never sent; the broker proves it
// back; a wrong proof counts against that terminal only (review B3, S4).
func TestAdmitCodeProof(t *testing.T) {
	b := testBroker(t)
	c := testConn(os.Getpid(), 0x8801)
	_, perr := b.admit(c, proto.Hello{Role: proto.RolePerson})
	if perr == nil || perr.Code != proto.ErrCodeRequired || perr.Challenge == nil || perr.Challenge.Kind != proto.AuthCode {
		t.Fatalf("no person attached: want code_required with a challenge, got %+v", perr)
	}
	// Wrong codes from one terminal: locked after three.
	for i := 0; i < maxCodeFails; i++ {
		ch := c.challenge
		if ch == nil {
			_, perr = b.admit(c, proto.Hello{Role: proto.RolePerson, Auth: proto.AuthCode, Nonce: proto.NewNonce()})
			ch = perr.Challenge
		}
		h, _, _ := prove(t, b, c, proto.AuthCode, "AAAAA-AAAAA", ch)
		if _, perr = b.admit(c, h); perr == nil || perr.Code != proto.ErrCodeInvalid {
			t.Fatalf("wrong code %d: %+v", i, perr)
		}
	}
	h := proto.Hello{Role: proto.RolePerson, Auth: proto.AuthCode, Nonce: proto.NewNonce()}
	if _, perr = b.admit(c, h); perr == nil || perr.Code != proto.ErrRateLimited {
		t.Fatalf("after %d wrong codes: want rate_limited, got %+v", maxCodeFails, perr)
	}
	// The same terminal number in another kernel session (a pty reused
	// after the guesser's closed) is not locked out.
	reused := testConn(os.Getpid(), 0x8801)
	reused.info.SID = 4242
	if _, perr := b.admit(reused, h); perr == nil || perr.Code != proto.ErrCodeRequired {
		t.Fatalf("reused terminal in another session: want a challenge, got %+v", perr)
	}
	// Another terminal (the person) is not locked out.
	p := testConn(os.Getpid(), 0x8802)
	_, perr = b.admit(p, h)
	if perr == nil || perr.Challenge == nil {
		t.Fatalf("other terminal: want a challenge, got %+v", perr)
	}
	old := b.code
	hp, key, tr := prove(t, b, p, proto.AuthCode, old, perr.Challenge)
	adm, perr := b.admit(p, hp)
	if perr != nil {
		t.Fatalf("right code refused: %+v", perr)
	}
	if adm.serverProof != proto.Proof(key, proto.SideServer, tr) {
		t.Error("server proof does not match")
	}
	if b.code == old {
		t.Error("the code did not rotate after a person attach")
	}
	// A proof replayed (or relayed) with another client pid fails.
	_, perr = b.admit(p, proto.Hello{Role: proto.RolePerson, Auth: proto.AuthCode, Nonce: proto.NewNonce()})
	relay := testConn(os.Getpid()+1, 0x8803)
	relay.challenge = perr.Challenge
	hr, _, _ := prove(t, b, p, proto.AuthCode, b.code, perr.Challenge)
	if _, perr = b.admit(relay, hr); perr == nil || perr.Code != proto.ErrCodeInvalid {
		t.Fatalf("relayed proof accepted: %+v", perr)
	}
}

// TestAdmitControlKeepsCode: cotty share / kill with the code leave it
// valid (review S5).
func TestAdmitControlKeepsCode(t *testing.T) {
	b := testBroker(t)
	c := testConn(os.Getpid(), 0x8811)
	_, perr := b.admit(c, proto.Hello{Role: proto.RoleControl})
	h, _, _ := prove(t, b, c, proto.AuthCode, b.code, perr.Challenge)
	h.Role = proto.RoleControl
	old := b.code
	// prove built the transcript for the person role; rebuild for control.
	salt, _ := hex.DecodeString(perr.Challenge.Salt)
	key := proto.CodeKey(old, salt, perr.Challenge.Iterations)
	h.Proof = proto.Proof(key, proto.SideClient, proto.Transcript(proto.AuthCode, proto.RoleControl, b.cfg.Name, h.Nonce,
		perr.Challenge.Nonce, c.info.PID, os.Getpid()))
	if _, perr := b.admit(c, h); perr != nil {
		t.Fatalf("control with the code: %+v", perr)
	}
	if b.code != old {
		t.Error("a control connection rotated the code")
	}
}

// TestAdmitCreatorToken: a wrong proof does not burn the token (S4); the
// right one admits once.
func TestAdmitCreatorToken(t *testing.T) {
	b := testBroker(t)
	c := testConn(os.Getpid(), 0x8821)
	h := proto.Hello{Role: proto.RolePerson, Auth: proto.AuthCreator, Nonce: proto.NewNonce()}
	_, perr := b.admit(c, h)
	if perr == nil || perr.Challenge == nil || perr.Challenge.Kind != proto.AuthCreator {
		t.Fatalf("want a creator challenge, got %+v", perr)
	}
	bad, _, _ := prove(t, b, c, proto.AuthCreator, "ffffffffffffffffffffffffffffffff", perr.Challenge)
	if _, perr = b.admit(c, bad); perr == nil || perr.Code != proto.ErrCodeInvalid {
		t.Fatalf("wrong token: %+v", perr)
	}
	_, perr = b.admit(c, h)
	good, _, _ := prove(t, b, c, proto.AuthCreator, "0123456789abcdef0123456789abcdef", perr.Challenge)
	if _, perr = b.admit(c, good); perr != nil {
		t.Fatalf("the token was burned by a wrong proof: %+v", perr)
	}
	if _, perr = b.admit(c, h); perr == nil || perr.Code != proto.ErrCodeInvalid {
		t.Fatalf("token reused: %+v", perr)
	}
}

// TestAdmitNeedsCodeWithPersonAttached: with a person attached, a hello
// without a secret gets the code challenge, not an approval request (an
// approval proves nothing to the client: review N1); the code then waits
// for the attached person's approval as a second gate.
func TestAdmitNeedsCodeWithPersonAttached(t *testing.T) {
	b := testBroker(t)
	attached := testConn(os.Getpid(), 0x8831)
	attached.role = proto.RolePerson
	attached.out = make(chan outFrame, 16)
	b.conns[attached] = true
	c := testConn(os.Getpid(), 0x8832)
	_, perr := b.admit(c, proto.Hello{Role: proto.RolePerson})
	if perr == nil || perr.Code != proto.ErrCodeRequired || perr.Challenge == nil || perr.Challenge.Kind != proto.AuthCode {
		t.Fatalf("hello without a secret, person attached: want a code challenge, got %+v", perr)
	}
	if len(b.pendingAttach) != 0 {
		t.Fatal("an approval request was raised without a code")
	}
	for i, accept := range []bool{false, true} {
		// A fresh terminal each time (a denied one waits before asking again).
		c := testConn(os.Getpid(), 0x8840+uint64(i))
		_, perr = b.admit(c, proto.Hello{Role: proto.RolePerson, Auth: proto.AuthCode, Nonce: proto.NewNonce()})
		h, key, tr := prove(t, b, c, proto.AuthCode, b.code, perr.Challenge)
		type result struct {
			adm  admission
			perr *proto.Error
		}
		done := make(chan result, 1)
		go func() {
			adm, perr := b.admit(c, h)
			done <- result{adm, perr}
		}()
		var req *attachReq
		for i := 0; i < 500 && req == nil; i++ {
			b.mu.Lock()
			for _, r := range b.pendingAttach {
				req = r
			}
			b.mu.Unlock()
			if req == nil {
				time.Sleep(2 * time.Millisecond)
			}
		}
		if req == nil {
			t.Fatal("no approval request after a valid code with a person attached")
		}
		req.ch <- accept
		r := <-done
		if !accept {
			if r.perr == nil || r.perr.Code != proto.ErrApprovalDenied {
				t.Fatalf("denied approval: %+v", r.perr)
			}
			continue
		}
		if r.perr != nil || r.adm.how != "code+approval" || r.adm.serverProof != proto.Proof(key, proto.SideServer, tr) {
			t.Fatalf("approved: %+v %+v", r.adm, r.perr)
		}
	}
}

// TestControlCodeReadNeedsCreator (review A1): a control connection
// admitted with the code (cotty share, cotty kill) cannot read the next
// code; the creator's (cotty new -d) can.
func TestControlCodeReadNeedsCreator(t *testing.T) {
	b := testBroker(t)
	for _, tc := range []struct {
		how string
		ok  bool
	}{{"code", false}, {"creator", true}} {
		c := testConn(os.Getpid(), 0x8851)
		c.role, c.admission = proto.RoleControl, tc.how
		res, perr := b.op(c, proto.Request{Op: "code"})
		if tc.ok != (perr == nil) {
			t.Fatalf("control admitted by %s: code op %v %+v", tc.how, res, perr)
		}
	}
}

// TestDeniedApprovalSpendsCode (review A2): the requester proved the
// code, so a denied approval spends it as an approved one does.
func TestDeniedApprovalSpendsCode(t *testing.T) {
	b := testBroker(t)
	attached := testConn(os.Getpid(), 0x8861)
	attached.role = proto.RolePerson
	attached.out = make(chan outFrame, 16)
	b.conns[attached] = true
	c := testConn(os.Getpid(), 0x8862)
	_, perr := b.admit(c, proto.Hello{Role: proto.RolePerson, Auth: proto.AuthCode, Nonce: proto.NewNonce()})
	old := b.code
	h, _, _ := prove(t, b, c, proto.AuthCode, old, perr.Challenge)
	done := make(chan *proto.Error, 1)
	go func() {
		_, perr := b.admit(c, h)
		done <- perr
	}()
	var req *attachReq
	for i := 0; i < 500 && req == nil; i++ {
		b.mu.Lock()
		for _, r := range b.pendingAttach {
			req = r
		}
		b.mu.Unlock()
		if req == nil {
			time.Sleep(2 * time.Millisecond)
		}
	}
	if req == nil {
		t.Fatal("no approval request")
	}
	req.ch <- false
	if perr := <-done; perr == nil || perr.Code != proto.ErrApprovalDenied {
		t.Fatalf("denied approval: %+v", perr)
	}
	b.mu.Lock()
	now := b.code
	b.mu.Unlock()
	if now == old {
		t.Fatal("a denied approval left the code valid")
	}
	// The old code no longer admits a control connection either.
	ctl := testConn(os.Getpid(), 0x8863)
	_, perr = b.admit(ctl, proto.Hello{Role: proto.RoleControl, Auth: proto.AuthCode, Nonce: proto.NewNonce()})
	hc := proto.Hello{Role: proto.RoleControl, Auth: proto.AuthCode, Nonce: proto.NewNonce()}
	salt, _ := hex.DecodeString(perr.Challenge.Salt)
	hc.Proof = proto.Proof(proto.CodeKey(old, salt, perr.Challenge.Iterations), proto.SideClient,
		proto.Transcript(proto.AuthCode, proto.RoleControl, b.cfg.Name, hc.Nonce, perr.Challenge.Nonce, ctl.info.PID, os.Getpid()))
	if _, perr := b.admit(ctl, hc); perr == nil || perr.Code != proto.ErrCodeInvalid {
		t.Fatalf("old code after a denied approval: %+v", perr)
	}
}

// TestCodeAdmitsOnePerson: two proofs of the same code made at the same
// time admit one person, not two.
func TestCodeAdmitsOnePerson(t *testing.T) {
	b := testBroker(t)
	code := b.code
	var hs []proto.Hello
	var cs []*conn
	for i := range 2 {
		c := testConn(os.Getpid(), 0x8870+uint64(i))
		_, perr := b.admit(c, proto.Hello{Role: proto.RolePerson, Auth: proto.AuthCode, Nonce: proto.NewNonce()})
		h, _, _ := prove(t, b, c, proto.AuthCode, code, perr.Challenge)
		hs, cs = append(hs, h), append(cs, c)
	}
	if _, perr := b.admit(cs[0], hs[0]); perr != nil {
		t.Fatalf("first proof: %+v", perr)
	}
	if _, perr := b.admit(cs[1], hs[1]); perr == nil || perr.Code != proto.ErrCodeInvalid {
		t.Fatalf("second proof of the spent code: %+v", perr)
	}
}

// TestSecondBrokerStartsNoShell (review A4): a broker whose session name
// is held by another one refuses before it starts its shell, so the
// person's login files never run a second time.
func TestSecondBrokerStartsNoShell(t *testing.T) {
	b := testBroker(t)
	held, err := os.OpenFile(b.paths.Lock, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ran := filepath.Join(t.TempDir(), "shell-ran")
	b.cfg.Shell = []string{"sh", "-c", "touch " + ran}
	if _, err := b.Run(); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second broker: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the second broker started its shell")
	}
}
