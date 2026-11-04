// Provenance: adapted from basalt-agent internal/audit (commit 0f9e4d4).

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", "audit.jsonl")
	l := Open(p)
	sub := Subject{Role: "agent", PID: 42, Exe: "/usr/bin/cotty", Assurance: "weak"}
	for i, ev := range []string{SessionStart, AgentInput, SecretStart, SessionEnd} {
		r, err := l.Append(Record{UID: 1000, Session: "s-0123456789ab", Event: ev, Subject: sub,
			Data: map[string]any{"host": "example.com", "port": 443, "n": i}})
		if err != nil {
			t.Fatal(err)
		}
		if r.Seq != int64(i+1) || r.Hash == "" || (i == 0) != (r.Prev == "") {
			t.Fatalf("record %d: %+v", i, r)
		}
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if n, err := Verify(p); err != nil || n != 4 {
		t.Fatalf("verify: %d %v", n, err)
	}
	rs, _ := Read(p, "s-0123456789ab")
	if len(rs) != 4 || rs[2].Event != SecretStart {
		t.Fatalf("read: %+v", rs)
	}

	// Tampering with a field breaks the chain.
	b, _ := os.ReadFile(p)
	bad := strings.Replace(string(b), `"host":"example.com"`, `"host":"example.org"`, 1)
	if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(p); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("tampering not detected: %v", err)
	}
	// Removing a line breaks the sequence.
	lines := strings.SplitAfter(string(b), "\n")
	if err := os.WriteFile(p, []byte(lines[0]+lines[2]+lines[3]), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(p); err == nil {
		t.Error("removed record not detected")
	}
}
