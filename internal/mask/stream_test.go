package mask

import (
	"strings"
	"testing"
)

func TestStreamSplitValue(t *testing.T) {
	value := string(fakeValue(newRand(20), 32))
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "K", []byte(value))
	head, tail := "TOKEN="+value[:13], value[13:]+"\n$ "

	// First read: the head is committed, the tail is still on the screen.
	s := e.NewStream()
	out1, hits1 := s.Next(head, tail)
	if out1 != "TOKEN=[masked:K]" || len(hits1) != 1 {
		t.Errorf("first read: %q %+v", out1, hits1)
	}
	// Second read: the tail is committed now.
	out2, hits2 := s.Next(tail, "")
	if out2 != "[masked:K]\n$ " || len(hits2) != 1 {
		t.Errorf("second read: %q %+v", out2, hits2)
	}

	// After Reset the context is gone, so the tail alone is not recognised.
	s.Reset()
	if out, _ := s.Next(value[13:], ""); out != value[13:] {
		t.Errorf("after reset: %q", out)
	}
}

func TestStreamPrivateKeyAcrossReads(t *testing.T) {
	r := newRand(21)
	head := "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n"
	body1 := string(fakeValue(r, 70)) + "\n"
	body2 := string(fakeValue(r, 70)) + "\n"
	tail := "-----END " + "OPENSSH PRIVATE KEY-----\n"
	s := New(Options{}).NewStream()
	var all strings.Builder
	for _, piece := range []string{head, body1, body2, tail} {
		out, _ := s.Next(piece, "")
		all.WriteString(out)
	}
	got := all.String()
	if strings.Contains(got, body1[:20]) || strings.Contains(got, body2[40:60]) || !strings.HasPrefix(got, head) || !strings.HasSuffix(got, tail) {
		t.Errorf("pem across reads: %q", got)
	}
}

func TestMaskRowsBelow(t *testing.T) {
	value := string(fakeValue(newRand(22), 30))
	e := New(Options{NoBuiltinRules: true, Width: 20})
	mustAdd(t, e, "V", []byte(value))
	above := "prompt$ echo " + value[:7] // the head scrolled out of view
	rows := []string{value[7:27], value[27:] + " done"}
	out, hits := e.MaskRowsBelow(above, rows)
	if out[0] != "[masked:V]" || out[1] != " done" || len(hits) != 1 || hits[0].Row != 0 {
		t.Errorf("rows below: %q %+v", out, hits)
	}
	// Without the context, the tail is not recognised (the documented gap).
	if _, hits := e.MaskRows(rows); len(hits) != 0 {
		t.Errorf("unexpected: %+v", hits)
	}
}

// FuzzStream cuts a structured text into reads at fuzzer-chosen points,
// with the rest of the text as lookahead, and checks that the reads put
// together leak no secret byte.
func FuzzStream(f *testing.F) {
	f.Add([]byte{0, 0, 1, 1, 10, 1, 0, 2, 2, 1, 0, 1}, []byte{3, 5, 1})
	f.Add([]byte("split secrets between reads"), []byte{1, 1, 1, 1, 1})
	f.Fuzz(func(t *testing.T, data, cuts []byte) {
		e, text, _ := buildCase(t, data, Options{})
		defer e.Close()
		s := e.NewStream()
		var all strings.Builder
		pos := 0
		for _, c := range cuts {
			if pos >= len(text) {
				break
			}
			end := min(len(text), pos+1+int(c))
			for end < len(text) && text[end]&0xC0 == 0x80 {
				end++ // reads end on rune boundaries, as committed lines do
			}
			out, _ := s.Next(text[pos:end], text[end:])
			all.WriteString(out)
			pos = end
		}
		out, _ := s.Next(text[pos:], "")
		all.WriteString(out)
		checkNoSecretBytes(t, text, all.String(), secretAlphabet)
	})
}
