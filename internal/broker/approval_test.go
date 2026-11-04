package broker

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/openbasalt/cotty/internal/proto"
)

// socketPair returns two connected unix stream sockets.
func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conv := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "pair")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	a, b := conv(fds[0]), conv(fds[1])
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// withPerson attaches a person connection that never answers requests.
func withPerson(b *Broker) {
	pc := &conn{b: b, role: proto.RolePerson, out: make(chan outFrame, 64), done: make(chan struct{}), events: map[string]bool{}}
	b.mu.Lock()
	b.conns[pc] = true
	b.mu.Unlock()
}

// TestApprovalSlotNoLockout (review N11, with N1): a hello without the
// code never takes the one approval slot, so a process that does not know
// the code cannot hold it; a requester that proved the code and hangs up
// frees the slot at once; a denied terminal waits before it may ask
// again.
func TestApprovalSlotNoLockout(t *testing.T) {
	b := testBroker(t)
	withPerson(b)
	// Without the code: a challenge, never an approval request.
	p := testConn(os.Getpid(), 0x9902)
	if _, perr := b.admit(p, proto.Hello{Role: proto.RolePerson}); perr == nil || perr.Code != proto.ErrCodeRequired {
		t.Fatalf("hello without the code: want code_required, got %+v", perr)
	}
	b.mu.Lock()
	n := len(b.pendingAttach)
	b.mu.Unlock()
	if n != 0 {
		t.Fatal("an approval request was raised without the code")
	}
	// A requester with the code waits for approval, then hangs up.
	srv, cli := socketPair(t)
	req := testConn(os.Getpid(), 0x9901)
	req.c = srv
	_, perr := b.admit(req, proto.Hello{Role: proto.RolePerson, Auth: proto.AuthCode, Nonce: proto.NewNonce()})
	h, _, _ := prove(t, b, req, proto.AuthCode, b.code, perr.Challenge)
	res := make(chan *proto.Error, 1)
	go func() {
		_, perr := b.admit(req, h)
		res <- perr
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		b.mu.Lock()
		n := len(b.pendingAttach)
		b.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("setup: the request did not take the slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = cli.Close()
	select {
	case perr := <-res:
		if perr == nil || perr.Code != proto.ErrApprovalDenied {
			t.Fatalf("hung up request: %+v", perr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a request whose client hung up kept the slot")
	}
	b.mu.Lock()
	n = len(b.pendingAttach)
	b.mu.Unlock()
	if n != 0 {
		t.Fatalf("slot still taken: %d", n)
	}
	// The same terminal, with the code again: backoff, no new request.
	again := testConn(os.Getpid(), 0x9901)
	_, perr = b.admit(again, proto.Hello{Role: proto.RolePerson, Auth: proto.AuthCode, Nonce: proto.NewNonce()})
	h2, _, _ := prove(t, b, again, proto.AuthCode, b.code, perr.Challenge)
	if _, perr := b.admit(again, h2); perr == nil || perr.Code != proto.ErrApprovalUnavailable {
		t.Fatalf("denied terminal asked again: want approval_unavailable, got %+v", perr)
	}
}

// TestConnCapsPerEndpoint (review N11): agents filling the agent
// endpoint's connection cap do not keep anyone off the main socket.
func TestConnCapsPerEndpoint(t *testing.T) {
	b := testBroker(t)
	b.nagentConns.Store(maxConns)
	srv, cli := socketPair(t)
	go b.serve(srv, false)
	_ = cli.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var buf [1]byte
	if _, err := cli.Read(buf[:]); err == nil || !os.IsTimeout(err) {
		t.Fatalf("main socket refused while the agent endpoint is full: %v", err)
	}
	srv2, cli2 := socketPair(t)
	go b.serve(srv2, true)
	_ = cli2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cli2.Read(buf[:]); err == nil || os.IsTimeout(err) {
		t.Fatalf("agent endpoint over its cap not closed: %v", err)
	}
}
