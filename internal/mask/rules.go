package mask

import (
	"math"
	"regexp"
	"strings"
)

// Rule masks text that matches a well-known token format, without knowing
// the value in advance.
//
// A rule finds its matches in one of two ways:
//
//   - Find, when set, returns the byte ranges [start, end) to mask;
//   - otherwise Pattern is used. When Keywords is not empty, Pattern only runs
//     where one of the keywords occurs, anchored there, so every match must
//     start with one of them (this keeps rules cheap on a full screen). When
//     the pattern has a named group "secret", only that group is masked.
//
// Name ends up in the replacement text, [masked:NAME], so it must not be
// secret. It must match [A-Za-z0-9_.-]{1,64}.
type Rule struct {
	Name     string
	Keywords []string
	Pattern  *regexp.Regexp
	// Boundary requires that the byte before a keyword is not a letter,
	// digit or underscore, to avoid matching inside longer words.
	Boundary bool
	// MaxLen bounds how far an anchored Pattern may reach from a keyword
	// (default 1024 bytes).
	MaxLen int
	Find   func(text string) [][2]int
}

// compiledRule is a Rule ready to run.
type compiledRule struct {
	Rule
	anchored *regexp.Regexp
	group    int // submatch index of the "secret" group, 0 for the whole match
}

func compileRule(r Rule) compiledRule {
	c := compiledRule{Rule: r}
	if r.MaxLen <= 0 {
		c.MaxLen = 1024
	}
	if r.Find == nil && r.Pattern != nil {
		if len(r.Keywords) > 0 {
			c.anchored = regexp.MustCompile(`^(?:` + r.Pattern.String() + `)`)
		} else {
			c.anchored = r.Pattern
		}
		if i := c.anchored.SubexpIndex("secret"); i > 0 {
			c.group = i
		}
	}
	return c
}

func isWordByte(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_'
}

// find returns the ranges this rule masks in text.
func (c *compiledRule) find(text string) [][2]int {
	if c.Find != nil {
		return c.Find(text)
	}
	if c.anchored == nil {
		return nil
	}
	var out [][2]int
	pick := func(loc []int, base int) {
		s, e := loc[2*c.group], loc[2*c.group+1]
		if s >= 0 && e > s {
			out = append(out, [2]int{base + s, base + e})
		}
	}
	if len(c.Keywords) == 0 {
		for _, loc := range c.anchored.FindAllStringSubmatchIndex(text, -1) {
			pick(loc, 0)
		}
		return out
	}
	for _, kw := range c.Keywords {
		for from := 0; ; {
			i := strings.Index(text[from:], kw)
			if i < 0 {
				break
			}
			p := from + i
			from = p + 1
			if c.Boundary && p > 0 && isWordByte(text[p-1]) {
				continue
			}
			window := text[p:min(len(text), p+c.MaxLen)]
			if loc := c.anchored.FindStringSubmatchIndex(window); loc != nil {
				pick(loc, p)
			}
		}
	}
	return out
}

// BuiltinRules returns the token format rules that are on by default. Order
// matters only for naming: when two rules mask exactly the same range, the
// earlier one names the replacement (anthropic-key wins over openai-key).
func BuiltinRules() []Rule {
	return []Rule{
		{
			Name: "private-key",
			Find: findPrivateKeyBodies,
		},
		{
			Name:     "aws-access-key-id",
			Keywords: []string{"AKIA", "ASIA", "ABIA", "ACCA"},
			Pattern:  regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`),
			Boundary: true,
		},
		{
			Name:     "aws-secret-access-key",
			Keywords: []string{"aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", "SecretAccessKey"},
			Pattern:  regexp.MustCompile(`(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)["']?\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9/+]{40})`),
		},
		{
			Name:     "github-token",
			Keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
			Pattern:  regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}`),
			Boundary: true,
		},
		{
			Name:     "slack-token",
			Keywords: []string{"xox", "xapp-"},
			Pattern:  regexp.MustCompile(`(?:xox[abposre]|xapp)-[A-Za-z0-9-]{10,250}`),
			Boundary: true,
		},
		{
			Name:     "stripe-key",
			Keywords: []string{"sk_live_", "rk_live_"},
			Pattern:  regexp.MustCompile(`[sr]k_live_[A-Za-z0-9]{10,247}`),
			Boundary: true,
		},
		{
			Name:     "google-api-key",
			Keywords: []string{"AIza"},
			Pattern:  regexp.MustCompile(`AIza[A-Za-z0-9_-]{35}`),
			Boundary: true,
		},
		{
			Name:     "anthropic-key",
			Keywords: []string{"sk-ant-"},
			Pattern:  regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`),
			Boundary: true,
		},
		{
			Name:     "openai-key",
			Keywords: []string{"sk-"},
			Pattern:  regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`),
			Boundary: true,
		},
		{
			Name:     "jwt",
			Keywords: []string{"eyJ"},
			Pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`),
			Boundary: true,
		},
	}
}

// EntropyRule returns the high-entropy heuristic: runs of 24 or more
// base64-ish bytes that mix upper case, lower case and digits and carry at
// least 3.5 bits of entropy per byte. It is off by default (Options.Entropy)
// because it also masks hashes, ids and other harmless noise.
func EntropyRule() Rule {
	return Rule{Name: "high-entropy", Find: findHighEntropy}
}

func isTokenByte(c byte) bool {
	return isWordByte(c) || c == '+' || c == '/' || c == '=' || c == '-'
}

func findHighEntropy(text string) [][2]int {
	const minRun = 24
	var out [][2]int
	for i := 0; i < len(text); {
		if !isTokenByte(text[i]) {
			i++
			continue
		}
		j := i
		for j < len(text) && isTokenByte(text[j]) {
			j++
		}
		if j-i >= minRun && looksRandom(text[i:j]) {
			out = append(out, [2]int{i, j})
		}
		i = j
	}
	return out
}

func looksRandom(s string) bool {
	var counts [256]int
	var upper, lower, digit bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		counts[c]++
		switch {
		case 'A' <= c && c <= 'Z':
			upper = true
		case 'a' <= c && c <= 'z':
			lower = true
		case '0' <= c && c <= '9':
			digit = true
		}
	}
	if !upper || !lower || !digit {
		return false
	}
	h := 0.0
	n := float64(len(s))
	for _, k := range counts {
		if k > 0 {
			p := float64(k) / n
			h -= p * math.Log2(p)
		}
	}
	return h >= 3.5
}

// findPrivateKeyBodies masks the body of PEM private key blocks
// ("-----BEGIN ... PRIVATE KEY-----"), keeping the BEGIN and END lines
// visible so the reader still sees what was there. The body runs until
// "-----END" or the first byte that cannot be part of a PEM body, so a block
// cut off at the bottom of the screen is masked to the end too. Encrypted
// key headers (Proc-Type, DEK-Info) are masked with the body.
func findPrivateKeyBodies(text string) [][2]int {
	const begin = "-----BEGIN "
	const tail = "PRIVATE KEY-----"
	var out [][2]int
	for from := 0; ; {
		i := strings.Index(text[from:], begin)
		if i < 0 {
			return out
		}
		p := from + i + len(begin)
		from = p
		// Label: upper case words, then "PRIVATE KEY-----".
		q := p
		for q < len(text) && q-p < 64 && (text[q] == ' ' || 'A' <= text[q] && text[q] <= 'Z' || '0' <= text[q] && text[q] <= '9') && !strings.HasPrefix(text[q:], tail) {
			q++
		}
		if !strings.HasPrefix(text[q:], tail) {
			continue
		}
		start := q + len(tail)
		end := start
		for end < len(text) && !strings.HasPrefix(text[end:], "-----") && isPEMBodyByte(text[end]) {
			end++
		}
		for start < end && isSpace(text[start]) {
			start++
		}
		for end > start && isSpace(text[end-1]) {
			end--
		}
		if end > start {
			out = append(out, [2]int{start, end})
		}
		from = max(from, end)
	}
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// isPEMBodyByte: base64, header and line end bytes. A backslash counts
// too: a key inside a JSON string (a service account file printed with
// cat) has its line ends as \n, which would otherwise stop the body at
// its first line (review N23).
func isPEMBodyByte(c byte) bool {
	return isWordByte(c) || isSpace(c) || c == '+' || c == '/' || c == '=' || c == ':' || c == ',' || c == '-' || c == '\\'
}
