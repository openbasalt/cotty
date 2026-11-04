package session

import "testing"

// A session name never reads as a flag on a broker's command line
// (review G1).
func TestValidName(t *testing.T) {
	for _, n := range []string{"1", "work", "a.b-c_d", "_x"} {
		if !ValidName(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", "-x", "--", "-dev-insecure", ".", "..", ".hidden", "a/b", "abcdefghijabcdefghijabcdefghijabc"} {
		if ValidName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

// The guard reads a broker's command line as the broker does.
func TestParseBrokerArgs(t *testing.T) {
	f, rest, err := ParseBrokerArgs([]string{"-name", "--", "-dev-insecure", "--", "bash"})
	if err != nil || !f.Insecure || f.Name != "--" || len(rest) != 1 || rest[0] != "bash" {
		t.Fatalf("%+v %q %v", f, rest, err)
	}
}
