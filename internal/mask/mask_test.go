package mask

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeValue returns a deterministic random alphanumeric value. Tests never
// use real secrets.
func fakeValue(r *rand.Rand, n int) []byte {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[r.IntN(len(alpha))]
	}
	return b
}

func newRand(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed^0x5eed)) }

func mustAdd(t testing.TB, e *Engine, name string, v []byte) {
	t.Helper()
	if err := e.AddSecret(name, v); err != nil {
		t.Fatalf("AddSecret(%s): %v", name, err)
	}
}

func TestAddSecretValidation(t *testing.T) {
	e := New(Options{})
	cases := []struct {
		name  string
		value string
		want  error
	}{
		{"", "abcdefgh", ErrBadName},
		{"has space", "abcdefgh", ErrBadName},
		{"x/y", "abcdefgh", ErrBadName},
		{strings.Repeat("a", 65), "abcdefgh", ErrBadName},
		{"SHORT", "abc12", ErrTooShort},
		{"MASKED", "masked", ErrInReplacement},
		{"MY_TOKEN_NAME", "TOKEN_", ErrInReplacement},
		{"RULE", "-token", ErrInReplacement}, // part of the github-token rule name
		{"OK", "abc123", nil},
	}
	for _, c := range cases {
		err := e.AddSecret(c.name, []byte(c.value))
		if !errors.Is(err, c.want) {
			t.Errorf("AddSecret(%q): got %v, want %v", c.name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), c.value) {
			t.Errorf("error leaks the value: %v", err)
		}
	}
	// A new name that would contain an existing value.
	if err := e.AddSecret("xabc123x", []byte("zzzzzzzz")); !errors.Is(err, ErrInReplacement) {
		t.Errorf("name containing an existing value: got %v", err)
	}
	if err := e.AddRule(Rule{Name: "abc123-rule", Find: func(string) [][2]int { return nil }}); !errors.Is(err, ErrInReplacement) {
		t.Errorf("rule name containing a value: got %v", err)
	}
	if err := e.AddRule(Rule{Name: "empty"}); !errors.Is(err, ErrBadRule) {
		t.Errorf("rule without matcher: got %v", err)
	}
	if got := New(Options{MinLen: 10}).AddSecret("A", []byte("123456789")); !errors.Is(got, ErrTooShort) {
		t.Errorf("MinLen 10: got %v", got)
	}
}

func TestVariants(t *testing.T) {
	r := newRand(1)
	value := append(fakeValue(r, 20), []byte(" /+?&=é")...)
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "TOK", value)
	nl := append(append([]byte{}, value...), '\n')
	cases := map[string]struct {
		text string
		kind Kind
	}{
		"raw":         {string(value), KindLiteral},
		"b64":         {base64.StdEncoding.EncodeToString(value), KindBase64},
		"b64raw":      {base64.RawStdEncoding.EncodeToString(value), KindBase64},
		"b64url":      {base64.URLEncoding.EncodeToString(value), KindBase64},
		"b64urlraw":   {base64.RawURLEncoding.EncodeToString(value), KindBase64},
		"b64nl":       {base64.StdEncoding.EncodeToString(nl), KindBase64},
		"query":       {url.QueryEscape(string(value)), KindURL},
		"querylower":  {strings.ToLower(url.QueryEscape(string(value))), KindURL},
		"path":        {url.PathEscape(string(value)), KindURL},
		"hex":         {hex.EncodeToString(value), KindHex},
		"hexupper":    {strings.ToUpper(hex.EncodeToString(value)), KindHex},
		"strict%20":   {strings.ReplaceAll(url.QueryEscape(string(value)), "+", "%20"), KindURL},
		"inside-text": {"key=" + string(value) + ";", KindLiteral},
	}
	for name, c := range cases {
		if name == "querylower" {
			// Only the %XX escapes are lower case; letters of the value stay.
			c.text = lowerEscapes(url.QueryEscape(string(value)))
		}
		out, hits := e.MaskText("<" + c.text + ">")
		if strings.Contains(out, string(value[:6])) || len(hits) != 1 || hits[0].Name != "TOK" || hits[0].Kind != c.kind {
			t.Errorf("%s: out=%q hits=%+v", name, out, hits)
		}
		if !strings.HasPrefix(out, "<") || !strings.HasSuffix(out, ">") {
			t.Errorf("%s: surrounding text changed: %q", name, out)
		}
	}
}

func lowerEscapes(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = strings.ToLower(string(b[i+1]))[0]
			b[i+2] = strings.ToLower(string(b[i+2]))[0]
		}
	}
	return string(b)
}

func TestPercentEncodersMatchStdlib(t *testing.T) {
	r := newRand(2)
	for range 2000 {
		src := make([]byte, r.IntN(20))
		for i := range src {
			src[i] = byte(r.IntN(256))
		}
		for _, c := range []struct {
			mode percentMode
			want string
		}{
			{percentQuery, url.QueryEscape(string(src))},
			{percentPath, url.PathEscape(string(src))},
		} {
			dst := make([]byte, percentLen(src, c.mode))
			percentEncode(dst, src, c.mode, true)
			if string(dst) != c.want {
				t.Fatalf("mode %d: got %q want %q", c.mode, dst, c.want)
			}
		}
	}
}

// fakeTokens builds token-shaped fake values at run time, so no
// token-looking literal sits in the source.
func fakeTokens(r *rand.Rand) map[string]string {
	alnum := func(n int) string { return string(fakeValue(r, n)) }
	upper := func(n int) string { return strings.ToUpper(alnum(n)) }
	return map[string]string{
		"aws-access-key-id":     "AKIA" + upper(16),
		"aws-secret-access-key": "aws_secret_access_key = " + alnum(40),
		"github-token":          "gh" + "p_" + alnum(36),
		"github-token/pat":      "github" + "_pat_" + alnum(22) + "_" + alnum(59),
		"github-token/gho":      "gh" + "o_" + alnum(36),
		"slack-token":           "xo" + "xb-" + alnum(12) + "-" + alnum(24),
		"stripe-key":            "sk" + "_live_" + alnum(24),
		"stripe-key/rk":         "rk" + "_live_" + alnum(24),
		"google-api-key":        "AI" + "za" + alnum(35),
		"anthropic-key":         "sk" + "-ant-api03-" + alnum(80),
		"openai-key":            "sk" + "-proj-" + alnum(48),
		"jwt":                   "ey" + "J" + alnum(20) + ".ey" + "J" + alnum(40) + "." + alnum(43),
	}
}

func TestBuiltinRules(t *testing.T) {
	e := New(Options{})
	for name, tok := range fakeTokens(newRand(3)) {
		rule, _, _ := strings.Cut(name, "/")
		out, hits := e.MaskText("value: " + tok + " end")
		if len(hits) != 1 || hits[0].Name != rule || hits[0].Kind != KindRule {
			t.Errorf("%s: hits=%+v out=%q", name, hits, out)
			continue
		}
		secretPart := tok
		if _, after, ok := strings.Cut(tok, "= "); ok {
			secretPart = after
		}
		if strings.Contains(out, secretPart[len(secretPart)-8:]) {
			t.Errorf("%s: tail of token survived: %q", name, out)
		}
		if !strings.HasPrefix(out, "value: ") || !strings.HasSuffix(out, " end") {
			t.Errorf("%s: context changed: %q", name, out)
		}
	}
	// Boundaries: no masking inside longer words.
	for _, s := range []string{"task-" + strings.Repeat("x", 30), "MASKIA" + strings.Repeat("A", 16), "short sk-abc"} {
		if out, hits := e.MaskText(s); len(hits) != 0 {
			t.Errorf("false positive on %q: %q", s, out)
		}
	}
	// Rules can be turned off.
	tok := fakeTokens(newRand(3))["github-token"]
	if _, hits := New(Options{NoBuiltinRules: true}).MaskText(tok); len(hits) != 0 {
		t.Errorf("NoBuiltinRules still masked: %+v", hits)
	}
}

func TestPrivateKey(t *testing.T) {
	r := newRand(4)
	body := []string{string(fakeValue(r, 64)), string(fakeValue(r, 64)), string(fakeValue(r, 20)) + "=="}
	head := "-----BEGIN " + "RSA PRIVATE KEY-----"
	tail := "-----END " + "RSA PRIVATE KEY-----"
	e := New(Options{})

	text := "$ cat key\n" + head + "\nProc-Type: 4,ENCRYPTED\n" + strings.Join(body, "\n") + "\n" + tail + "\n$ "
	out, hits := e.MaskText(text)
	want := "$ cat key\n" + head + "\n[masked:private-key]\n" + tail + "\n$ "
	if out != want || len(hits) != 1 || hits[0].Row != 2 {
		t.Errorf("text: got %q hits %+v", out, hits)
	}

	// On a screen, rows padded to the width, END scrolled off the bottom.
	width := 70
	pad := func(s string) string { return s + strings.Repeat(" ", width-len(s)) }
	rows := []string{pad(head), pad(body[0]), pad(body[1])}
	got, hits := e.MaskRows(rows)
	if got[0] != rows[0] || strings.Contains(strings.Join(got, ""), body[0][:10]) || strings.Contains(strings.Join(got, ""), body[1][50:]) {
		t.Errorf("rows: %q", got)
	}
	if len(hits) != 1 || hits[0].Row != 1 {
		t.Errorf("rows hits: %+v", hits)
	}
	// The body rows keep only what follows the span (the padding), so
	// their length does not tell the body's.
	if !strings.HasPrefix(got[1], "[masked:private-key]") || strings.TrimSpace(got[2]) != "" {
		t.Errorf("body rows: %q", got[1:])
	}
	// Public keys and certificates are left alone.
	pub := "-----BEGIN PUBLIC KEY-----\n" + body[0] + "\n-----END PUBLIC KEY-----"
	if _, hits := e.MaskText(pub); len(hits) != 0 {
		t.Errorf("public key masked")
	}
}

func TestMaskRowsWrap(t *testing.T) {
	r := newRand(5)
	value := fakeValue(r, 30)
	e := New(Options{Width: 20, NoBuiltinRules: true})
	mustAdd(t, e, "API", value)
	line := "export K=" + string(value) + " # done"
	var rows []string
	for i := 0; i < len(line); i += 20 {
		rows = append(rows, line[i:min(len(line), i+20)])
	}
	out, hits := e.MaskRows(rows)
	joined := strings.Join(out, "")
	for i := 0; i+6 <= len(value); i++ {
		if strings.Contains(joined, string(value[i:i+6])) {
			t.Fatalf("fragment survived: %q", out)
		}
	}
	if len(hits) != 1 || hits[0].Row != 0 {
		t.Errorf("hits %+v", hits)
	}
	// Row 0 gets the replacement whatever part of the value it held. Row 1
	// is the continuation (19 bytes of the value, then the space before
	// the comment): the value's part is removed, not blanked, so the row
	// does not tell its length.
	if out[0] != "export K=[masked:API]" {
		t.Errorf("row 0: %q", out[0])
	}
	if out[1] != " " {
		t.Errorf("row 1 should keep only the text after the span: %q", out[1])
	}
	if out[2] != "# done" {
		t.Errorf("row 2: %q", out[2])
	}
}

func TestMaskRowsAlignment(t *testing.T) {
	r := newRand(6)
	long := fakeValue(r, 40)
	short := fakeValue(r, 6)
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "LONG", long)
	mustAdd(t, e, "S", short)
	rows := []string{"a " + string(long) + " b", "c " + string(short) + " d"}
	out, _ := e.MaskRows(rows)
	// The replacement has the same width whatever the value's length.
	if out[0] != "a [masked:LONG] b" {
		t.Errorf("long secret row: %q", out[0])
	}
	// "[masked:S]" is longer than the 6-byte value: written whole, row grows.
	if out[1] != "c [masked:S] d" {
		t.Errorf("short secret row: %q", out[1])
	}
}

func TestPaddedWidthPass(t *testing.T) {
	// The value has a space exactly where the row wraps, and the renderer
	// trimmed that trailing space from the first row.
	value := []byte("pass word 2024")
	e := New(Options{Width: 10, NoBuiltinRules: true})
	mustAdd(t, e, "PW", value)
	rows := []string{"say: pass", "word 2024!"}
	out, hits := e.MaskRows(rows)
	if len(hits) != 1 || strings.Contains(strings.Join(out, "|"), "word 2024") || strings.Contains(out[0], "pass") {
		t.Errorf("padded pass missed: %q %+v", out, hits)
	}
	// Without Width the joined text lacks the space and the value is missed.
	e2 := New(Options{NoBuiltinRules: true})
	mustAdd(t, e2, "PW", value)
	if _, hits := e2.MaskRows(rows); len(hits) != 0 {
		t.Errorf("unexpected hit without width: %+v", hits)
	}
}

func TestAdjacentAndOverlapping(t *testing.T) {
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "A", []byte("abcdefgh"))
	mustAdd(t, e, "B", []byte("efghijkl"))
	mustAdd(t, e, "C", []byte("zyxwvuts"))
	cases := []struct{ in, want string }{
		{"abcdefghijkl", "[masked:A][masked:B]"},
		{"abcdefghzyxwvuts", "[masked:A][masked:C]"},
		{"(abcdefgh)", "([masked:A])"},
		{"→abcdefgh←", "→[masked:A]←"},
		{"日本abcdefgh語", "日本[masked:A]語"},
		{"abcdefgabcdefgh", "abcdefg[masked:A]"},
	}
	for _, c := range cases {
		if got, _ := e.MaskText(c.in); got != c.want {
			t.Errorf("MaskText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// One secret containing another: only the outer one is named.
	e2 := New(Options{NoBuiltinRules: true})
	mustAdd(t, e2, "OUTER", []byte("xx123456yy"))
	mustAdd(t, e2, "INNER", []byte("123456"))
	if got, hits := e2.MaskText("-xx123456yy-"); got != "-[masked:OUTER]-" || len(hits) != 1 {
		t.Errorf("nested: %q %+v", got, hits)
	}
}

func TestRemoveAndReplace(t *testing.T) {
	e := New(Options{NoBuiltinRules: true})
	mustAdd(t, e, "X", []byte("first-value"))
	mustAdd(t, e, "Y", []byte("other-value"))
	mustAdd(t, e, "X", []byte("second-value"))
	if got, _ := e.MaskText("first-value second-value"); got != "first-value [masked:X]" {
		t.Errorf("replace: %q", got)
	}
	e.RemoveSecret("X")
	e.RemoveSecret("nope")
	if got, _ := e.MaskText("second-value other-value"); got != "second-value [masked:Y]" {
		t.Errorf("remove: %q", got)
	}
	if n := e.Names(); len(n) != 1 || n[0] != "Y" {
		t.Errorf("names: %v", n)
	}
	e.Close()
	if got, _ := e.MaskText("other-value"); got != "other-value" {
		t.Errorf("close: %q", got)
	}
}

func TestFormatHidesValues(t *testing.T) {
	e := New(Options{})
	value := "s3cr3t-" + string(fakeValue(newRand(7), 12))
	mustAdd(t, e, "V", []byte(value))
	_, _ = e.MaskText("warm " + value) // build the matcher too
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		s := fmt.Sprintf(f, e)
		if strings.Contains(s, value) || strings.Contains(s, hex.EncodeToString([]byte(value))) || strings.Contains(s, "s3cr3t") {
			t.Errorf("%s leaks: %s", f, s)
		}
	}
	if s := fmt.Sprintf("%+v", struct{ E *Engine }{e}); strings.Contains(s, "s3cr3t") {
		t.Errorf("nested leaks: %s", s)
	}
}

func TestPartialMin(t *testing.T) {
	value := fakeValue(newRand(8), 40)
	e := New(Options{NoBuiltinRules: true, PartialMin: 12})
	mustAdd(t, e, "P", value)
	// The first 25 bytes, as if the rest were cut off by the screen edge.
	out, hits := e.MaskText("key: " + string(value[:25]))
	if out != "key: [masked:P]" || len(hits) != 1 || hits[0].Kind != KindPartial {
		t.Errorf("prefix: %q %+v", out, hits)
	}
	// Fragments shorter than PartialMin stay.
	if out, _ := e.MaskText(string(value[3:14])); out != string(value[3:14]) {
		t.Errorf("short fragment masked: %q", out)
	}
	// Full value is still a literal hit.
	if _, hits := e.MaskText(string(value)); len(hits) != 1 || hits[0].Kind != KindLiteral {
		t.Errorf("full: %+v", hits)
	}
	// Off by default.
	e2 := New(Options{NoBuiltinRules: true})
	mustAdd(t, e2, "P", value)
	if _, hits := e2.MaskText(string(value[:25])); len(hits) != 0 {
		t.Errorf("partial on by default")
	}
}

func TestEntropyRule(t *testing.T) {
	tok := string(fakeValue(newRand(9), 32))
	if _, hits := New(Options{}).MaskText("id " + tok); len(hits) != 0 {
		t.Errorf("entropy should be off by default")
	}
	e := New(Options{Entropy: true})
	if out, hits := e.MaskText("id " + tok + " ok"); out != "id [masked:high-entropy] ok" || len(hits) != 1 {
		t.Errorf("entropy: %q", out)
	}
	for _, s := range []string{"/usr/local/share/applications/foo", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ThisIsAVeryLongCamelCaseIdentifier"} {
		if _, hits := e.MaskText(s); len(hits) != 0 {
			t.Errorf("entropy false positive: %q", s)
		}
	}
}

func TestCustomRule(t *testing.T) {
	e := New(Options{NoBuiltinRules: true})
	if err := e.AddRule(Rule{Name: "corp", Keywords: []string{"CORP-"}, Pattern: regexp.MustCompile(`CORP-(?P<secret>[0-9]{8})`), Boundary: true}); err != nil {
		t.Fatal(err)
	}
	if out, _ := e.MaskText("id CORP-12345678."); out != "id CORP-[masked:corp]." {
		t.Errorf("custom rule: %q", out)
	}
}

func TestConcurrent(t *testing.T) {
	e := New(Options{})
	r := newRand(10)
	values := make([][]byte, 50)
	for i := range values {
		values[i] = fakeValue(r, 24)
	}
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				v := values[(i+w)%len(values)]
				out, _ := e.MaskRows([]string{"x " + string(v), "y"})
				_ = out
			}
		}()
	}
	for i := range 200 {
		name := fmt.Sprintf("S%d", i%len(values))
		if i%3 == 2 {
			e.RemoveSecret(name)
		} else {
			_ = e.AddSecret(name, values[i%len(values)])
		}
	}
	wg.Wait()
}

// TestDroppedEngineReleasesMemory checks that engines dropped without Close
// do not leak their locked mappings (they are not Go heap memory).
func TestDroppedEngineReleasesMemory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mappings are linux only")
	}
	before := liveMappings.Load()
	for i := range 500 {
		e := New(Options{NoBuiltinRules: true})
		mustAdd(t, e, "A", fakeValue(newRand(uint64(i)), 32))
	}
	for range 10 {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if after := liveMappings.Load(); after > before+50 {
		t.Errorf("live mappings grew from %d to %d", before, after)
	}
	e := New(Options{})
	mustAdd(t, e, "B", fakeValue(newRand(1), 32))
	e.Close()
	if after := liveMappings.Load(); after > before+50 {
		t.Errorf("Close did not release: %d", after)
	}
}

// TestPrivateKeyInJSON (review N23): a key inside a JSON string (a
// service account file printed with cat) has \n for its line ends; the
// whole body is masked, on one line and wrapped over screen rows.
func TestPrivateKeyInJSON(t *testing.T) {
	r := newRand(41)
	body := []string{string(fakeValue(r, 64)), string(fakeValue(r, 64)), string(fakeValue(r, 30))}
	key := "-----BEGIN " + "PRIVATE KEY-----\\n" + strings.Join(body, "\\n") + "\\n-----END " + "PRIVATE KEY-----\\n"
	text := `{"type": "service_account", "private_key": "` + key + `", "client_email": "x@y.iam"}`
	e := New(Options{})
	out, hits := e.MaskText(text)
	for _, b := range body {
		if strings.Contains(out, b[:12]) || strings.Contains(out, b[len(b)-12:]) {
			t.Fatalf("body line visible: %q", out)
		}
	}
	if len(hits) == 0 || !strings.Contains(out, `"client_email": "x@y.iam"`) {
		t.Fatalf("got %q hits %+v", out, hits)
	}
	// The same JSON line wrapped on an 80 column screen.
	var rows []string
	for i := 0; i < len(text); i += 80 {
		rows = append(rows, text[i:min(i+80, len(text))])
	}
	got, _ := New(Options{Width: 80}).MaskRows(rows)
	if all := strings.Join(got, ""); strings.Contains(all, body[1][:12]) || strings.Contains(all, body[2][:12]) {
		t.Fatalf("wrapped rows: %q", got)
	}
}

// TestShellAndDoubleBase64Variants (review S29): a value shown by bash's
// declare -p (double quote escapes), by printf %q, or base64 encoded
// twice is masked.
func TestShellAndDoubleBase64Variants(t *testing.T) {
	value := `pa$$w"rd` + "`x`" + `\9zQ!k&`
	e := New(Options{})
	if err := e.AddSecret("PW", []byte(value)); err != nil {
		t.Fatal(err)
	}
	dq := strings.NewReplacer(`\`, `\\`, `$`, `\$`, "`", "\\`", `"`, `\"`).Replace(value)
	pq := strings.NewReplacer(`\`, `\\`, `$`, `\$`, "`", "\\`", `"`, `\"`, `!`, `\!`, `&`, `\&`).Replace(value)
	twice := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(value))))
	for name, shown := range map[string]string{
		"declare -p": `declare -- PW="` + dq + `"`,
		"printf %q":  "PW=" + pq,
		"base64 x2":  "data: " + twice,
	} {
		out, _ := e.MaskText(shown)
		if !strings.Contains(out, "[masked:PW]") {
			t.Errorf("%s: %q -> %q", name, shown, out)
		}
	}
}

// TestPrintfQMatchesBash (review M1): the printf %q variant is what bash
// itself prints, for values with the characters whose quoting depends on
// the bash rules (',' escaped, '#' and '~' only where they start a word,
// '~' after '=' or ':'), alone and after NAME=.
func TestPrintfQMatchesBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	for _, value := range []string{
		"k3y,with#hash~tilde",
		"a=~b:~c,d#e!f&g",
		"#starts-with-hash,9Zq",
		"~starts-with-tilde,9Zq",
		`pa$$w"rd` + "`x`" + `\9zQ!k&^[]{}|;<>?*() sp`,
	} {
		e := New(Options{})
		if err := e.AddSecret("PW", []byte(value)); err != nil {
			t.Fatal(err)
		}
		for _, script := range []string{`printf '%q\n' "$1"`, `printf 'PW=%q\n' "$1"`, `printf 'x %q y\n' "$1"`} {
			out, err := exec.Command(bash, "-c", script, "bash", value).Output()
			if err != nil {
				t.Fatal(err)
			}
			shown := strings.TrimSuffix(string(out), "\n")
			masked, _ := e.MaskText(shown)
			if !strings.Contains(masked, "[masked:PW]") {
				t.Errorf("bash %s of %q: %q -> %q", script, value, shown, masked)
			}
		}
	}
}
