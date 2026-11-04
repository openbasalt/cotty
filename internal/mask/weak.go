package mask

import (
	"bytes"
	"math"
)

// Assess judges a value before it goes on the masking list. tooShort says
// the broker drops it (shorter than DefaultMinLen: it would never be
// masked). warnings name properties that make the value easy to guess by
// printing candidates and watching which come back masked (masking tells
// whoever prints text whether that text is on the list). They never quote
// the value.
func Assess(v []byte) (tooShort bool, warnings []string) {
	if len(v) < DefaultMinLen {
		return true, nil
	}
	if len(v) < 12 {
		warnings = append(warnings, "short (under 12 bytes)")
	}
	distinct := map[byte]bool{}
	var lower, upper, digit, other bool
	for _, c := range v {
		distinct[c] = true
		switch {
		case 'a' <= c && c <= 'z':
			lower = true
		case 'A' <= c && c <= 'Z':
			upper = true
		case '0' <= c && c <= '9':
			digit = true
		default:
			other = true
		}
	}
	if len(distinct) < 6 || len(distinct)*3 < len(v) && len(v) < 32 {
		warnings = append(warnings, "few distinct characters")
	}
	alphabet := 0
	for _, f := range []struct {
		on bool
		n  int
	}{{lower, 26}, {upper, 26}, {digit, 10}, {other, 32}} {
		if f.on {
			alphabet += f.n
		}
	}
	if bits := float64(len(v)) * math.Log2(float64(max(alphabet, 2))); bits < 60 {
		warnings = append(warnings, "low entropy (a random value of this length and alphabet has under 60 bits)")
	}
	if looksLikeWords(v) {
		warnings = append(warnings, "looks like a word or a common pattern (letters then digits, a keyboard run, a repeated part)")
	}
	return false, warnings
}

// looksLikeWords catches the shapes people choose: letters then a few
// digits or symbols (Summer2024!), keyboard and alphabet runs, a value
// made of one repeated part.
func looksLikeWords(v []byte) bool {
	// Work on a lower case copy and zero it after: no string copies of the
	// value that could not be wiped.
	s := bytes.ToLower(v)
	defer clear(s)
	i := 0
	for i < len(s) && 'a' <= s[i] && s[i] <= 'z' {
		i++
	}
	if i >= 4 && len(s)-i <= 5 {
		return true
	}
	for _, run := range []string{"qwerty", "asdfgh", "zxcvbn", "abcdef", "123456", "654321", "password", "passwd", "secret", "letmein", "admin"} {
		if bytes.Contains(s, []byte(run)) {
			return true
		}
	}
	for p := 1; p <= len(s)/2; p++ {
		if len(s)%p != 0 {
			continue
		}
		same := true
		for j := p; j < len(s) && same; j++ {
			same = s[j] == s[j%p]
		}
		if same {
			return true
		}
	}
	return false
}
