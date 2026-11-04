package broker

import (
	"math/rand/v2"
	"strings"
)

// fuzzStreams returns random streams biased towards escape sequences
// (same generator as tools/vteval -fuzz).
func fuzzStreams() []string {
	rng := rand.New(rand.NewPCG(1, 2))
	alphabet := []string{"\x1b[", "\x1b]", "\x1bP", "\x07", "\x1b\\", ";", "?", "1", "9", "99999", "m", "H", "J", "K", "r", "h", "l", "@", "L", "M", "P", "X", "S", "T", "\r", "\n", "\t", "\b", "a", "你", "́", "\U0001F600", "\x9b", "\xff", "\x1b(0", "q"}
	var out []string
	for i := 0; i < 120; i++ {
		var b strings.Builder
		for j := 0; j < 2000; j++ {
			b.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		out = append(out, b.String())
	}
	return out
}
