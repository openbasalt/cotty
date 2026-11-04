package proto

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Admission secrets (the creator token and the reattach code) never cross
// the socket. The client and the broker prove to each other that they know
// the secret with HMAC-SHA256 over a transcript that binds both nonces,
// the session, the role and the two process ids each side sees through
// SO_PEERCRED (docs/protocol.md section 7):
//
//   - a process that only listens on the session socket learns nothing it
//     can replay, and nothing it can test guesses against faster than the
//     key derivation allows;
//   - a relay (a fake listener that forwards the exchange to the real
//     broker) fails: the broker sees the relay's pid where the client put
//     its own, and the client sees the relay's pid where the broker put
//     its own.
//
// The reattach code has 50 bits; its key is derived with PBKDF2-SHA256 and
// a per-code salt, so an offline guess costs CodeKDFIterations hashes.

// Auth kinds in Hello.Auth.
const (
	AuthCreator = "creator" // the one-time token cotty new hands the broker
	AuthCode    = "code"    // the reattach code shown at detach
)

// CodeKDFIterations is the PBKDF2 iteration count for reattach code keys.
const CodeKDFIterations = 600000

// NonceLen is the length of the random nonces, in bytes.
const NonceLen = 32

// Challenge is the broker's half of the admission proof, sent with
// code_required (and code_invalid): a fresh nonce and, for the reattach
// code, the PBKDF2 salt and iteration count.
type Challenge struct {
	Kind       string `json:"kind"`
	Nonce      string `json:"nonce"`
	Salt       string `json:"salt,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
}

// NewNonce returns a random nonce, hex encoded.
func NewNonce() string {
	var b [NonceLen]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// NormCode normalizes a reattach code as the person may type it: case,
// dashes and spaces do not matter, and the letters that look like digits
// read as those digits.
func NormCode(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	s = strings.ReplaceAll(s, " ", "")
	return strings.NewReplacer("O", "0", "I", "1", "L", "1").Replace(s)
}

// CodeKey derives the proof key of a reattach code.
func CodeKey(code string, salt []byte, iterations int) []byte {
	if iterations <= 0 {
		iterations = CodeKDFIterations
	}
	k, err := pbkdf2.Key(sha256.New, NormCode(code), salt, iterations, 32)
	if err != nil {
		return nil
	}
	return k
}

// TokenKey derives the proof key of a creator token (256 random bits: no
// stretching needed).
func TokenKey(token string) []byte {
	sum := sha256.Sum256([]byte("cotty-creator-token\x00" + strings.TrimSpace(token)))
	return sum[:]
}

// Transcript is what both proofs cover.
func Transcript(kind, role, session, clientNonce, serverNonce string, clientPID, serverPID int) []byte {
	return []byte(strings.Join([]string{"cotty-admission-v1", kind, role, session, clientNonce, serverNonce,
		strconv.Itoa(clientPID), strconv.Itoa(serverPID)}, "\x00"))
}

// Proof sides.
const (
	SideClient = "client"
	SideServer = "server"
)

// Proof computes one side's proof, hex encoded.
func Proof(key []byte, side string, transcript []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(side))
	m.Write([]byte{0})
	m.Write(transcript)
	return hex.EncodeToString(m.Sum(nil))
}

// ProofEqual compares a received proof with the expected one in constant
// time.
func ProofEqual(got, want string) bool {
	g, err1 := hex.DecodeString(got)
	w, err2 := hex.DecodeString(want)
	return err1 == nil && err2 == nil && len(w) > 0 && hmac.Equal(g, w)
}
