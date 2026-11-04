package mask

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"runtime"
	"strings"
)

// arena is one block of memory that holds a secret value and every encoded
// variant of it, so all of it can be locked and zeroed together.
type arena struct {
	buf     []byte
	mapping []byte // the whole mapping, when buf lives outside the Go heap
	locked  bool
	cleanup runtime.Cleanup // releases the mapping if the arena is dropped unfreed
}

// variant is one byte string that, when found in text, reveals the secret.
type variant struct {
	kind Kind
	b    []byte // slice of the owning secret's arena
}

// percentMode selects which bytes a percent-encoder leaves alone.
type percentMode int

const (
	// percentStrict escapes everything except RFC 3986 unreserved bytes,
	// space as %20 (Python urllib.parse.quote with safe='', curl --data-urlencode).
	percentStrict percentMode = iota
	// percentQuery is Go's url.QueryEscape: strict, but space becomes '+'.
	percentQuery
	// percentPath is Go's url.PathEscape: strict, but $&+:=@ stay as they are.
	percentPath
	// percentJS is JavaScript encodeURIComponent: strict, but !'()* stay.
	percentJS
)

var base64Encodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
	base64.URLEncoding,
	base64.RawURLEncoding,
}

// newlineEncodings encode value+"\n", what `echo "$X" | base64` prints.
var newlineEncodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
}

func isUnreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
		c == '-' || c == '_' || c == '.' || c == '~'
}

func percentKeeps(mode percentMode, c byte) bool {
	if isUnreserved(c) {
		return true
	}
	switch mode {
	case percentPath:
		switch c {
		case '$', '&', '+', ':', '=', '@':
			return true
		}
	case percentJS:
		switch c {
		case '!', '\'', '(', ')', '*':
			return true
		}
	}
	return false
}

func percentLen(src []byte, mode percentMode) int {
	n := 0
	for _, c := range src {
		if percentKeeps(mode, c) || mode == percentQuery && c == ' ' {
			n++
		} else {
			n += 3
		}
	}
	return n
}

// percentEncode writes src percent-encoded into dst (sized by percentLen)
// with upper or lower case hex digits.
func percentEncode(dst, src []byte, mode percentMode, upper bool) {
	digits := "0123456789abcdef"
	if upper {
		digits = "0123456789ABCDEF"
	}
	i := 0
	for _, c := range src {
		switch {
		case percentKeeps(mode, c):
			dst[i] = c
			i++
		case mode == percentQuery && c == ' ':
			dst[i] = '+'
			i++
		default:
			dst[i], dst[i+1], dst[i+2] = '%', digits[c>>4], digits[c&15]
			i += 3
		}
	}
}

// buildVariants copies value into a fresh arena and appends every variant.
// The raw value is always the first variant. Duplicates are dropped.
func buildVariants(value []byte) (*arena, []variant) {
	n := len(value)
	type plan struct {
		kind Kind
		size int
		fill func(dst, raw, rawNL []byte)
	}
	var plans []plan
	for _, enc := range base64Encodings {
		plans = append(plans, plan{KindBase64, enc.EncodedLen(n), func(dst, raw, _ []byte) { enc.Encode(dst, raw) }})
	}
	for _, enc := range newlineEncodings {
		plans = append(plans, plan{KindBase64, enc.EncodedLen(n + 1), func(dst, _, rawNL []byte) { enc.Encode(dst, rawNL) }})
	}
	for _, mode := range []percentMode{percentStrict, percentQuery, percentPath, percentJS} {
		size := percentLen(value, mode)
		for _, upper := range []bool{true, false} {
			plans = append(plans, plan{KindURL, size, func(dst, raw, _ []byte) { percentEncode(dst, raw, mode, upper) }})
		}
	}
	// base64 of the value inside a longer input (`user:VALUE` in an HTTP
	// basic auth header, a value in a base64 JSON document): the characters
	// that depend on the value's bytes only, at each of the three
	// alignments the value can have in the input.
	for _, alpha := range []string{base64Std, base64URL} {
		for shift := range 3 {
			if size := base64CoreLen(n, shift); size >= minCoreLen {
				plans = append(plans, plan{KindBase64, size, func(dst, raw, _ []byte) { base64Core(dst, raw, shift, alpha) }})
			}
		}
	}
	// JSON string escapes (\" \\ \n, Go's \u003c for < > &, \/ for /).
	for _, mode := range []jsonMode{jsonMin, jsonHTML, jsonSlash} {
		if size := jsonLen(value, mode); size != n {
			plans = append(plans, plan{KindLiteral, size, func(dst, raw, _ []byte) { jsonEscape(dst, raw, mode) }})
		}
	}
	// Shell quoting: inside double quotes (bash declare -p) $ ` " \ get a
	// backslash; printf %q puts one before every other special character
	// too, and before # and ~ where they start a word (values with control
	// characters get $'...' quoting instead, not covered).
	modes := []shellMode{shellDouble, shellPrintfQ}
	if n > 0 && (value[0] == '#' || value[0] == '~') {
		modes = append(modes, shellPrintfQWord)
	}
	for _, mode := range modes {
		if size, ok := shellLen(value, mode); ok && size != n {
			plans = append(plans, plan{KindLiteral, size, func(dst, raw, _ []byte) { shellEscape(dst, raw, mode) }})
		}
	}
	// base64 of the base64 (a value encoded twice, as in a Kubernetes
	// secret manifest whose data is itself base64).
	inner := base64.StdEncoding.EncodedLen(n)
	plans = append(plans, plan{KindBase64, base64.StdEncoding.EncodedLen(inner), func(dst, raw, _ []byte) {
		tmp := make([]byte, inner)
		base64.StdEncoding.Encode(tmp, raw)
		base64.StdEncoding.Encode(dst, tmp)
		clear(tmp)
	}})
	// A multi-line value: on screen its rows are joined without the line
	// ends; a terminal shows "\r\n" as a line end.
	if bytes.ContainsAny(value, "\r\n") {
		size := n - bytes.Count(value, []byte("\r")) - bytes.Count(value, []byte("\n"))
		if size > 0 {
			plans = append(plans, plan{KindLiteral, size, func(dst, raw, _ []byte) { dropBytes(dst, raw, "\r\n") }})
		}
		if c := bytes.Count(value, []byte("\r")); c > 0 {
			plans = append(plans, plan{KindLiteral, n - c, func(dst, raw, _ []byte) { dropBytes(dst, raw, "\r") }})
		}
	}
	plans = append(plans,
		plan{KindHex, hex.EncodedLen(n), func(dst, raw, _ []byte) { hex.Encode(dst, raw) }},
		plan{KindHex, hex.EncodedLen(n), func(dst, raw, _ []byte) {
			hex.Encode(dst, raw)
			for i, c := range dst {
				if 'a' <= c && c <= 'f' {
					dst[i] = c - 'a' + 'A'
				}
			}
		}},
	)

	total := n + n + 1
	for _, p := range plans {
		total += p.size
	}
	a := newArena(total)
	raw := a.buf[:n:n]
	copy(raw, value)
	rawNL := a.buf[n : 2*n+1 : 2*n+1]
	copy(rawNL, value)
	rawNL[n] = '\n'

	vars := []variant{{kind: KindLiteral, b: raw}}
	off := 2*n + 1
	for _, p := range plans {
		dst := a.buf[off : off+p.size : off+p.size]
		off += p.size
		p.fill(dst, raw, rawNL)
		dup := false
		for _, v := range vars {
			if bytes.Equal(v.b, dst) {
				dup = true
				break
			}
		}
		if !dup {
			vars = append(vars, variant{kind: p.kind, b: dst})
		}
	}
	return a, vars
}

const (
	base64Std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	base64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	// minCoreLen is the shortest shifted base64 core kept as a pattern.
	minCoreLen = 8
)

// base64CoreLen is how many base64 characters depend only on the bytes of
// an n-byte value that starts shift bytes (0 to 2) after a 3-byte group
// boundary of the encoded input.
func base64CoreLen(n, shift int) int {
	first := (8*shift + 5) / 6  // first character with no bits before the value
	last := 8 * (shift + n) / 6 // characters that end inside the value
	return max(last-first, 0)
}

// base64Core writes the base64CoreLen(len(raw), shift) characters into
// dst, reading raw bit by bit (no copy of the value with a prefix).
func base64Core(dst, raw []byte, shift int, alpha string) {
	first := (8*shift + 5) / 6
	for i := range dst {
		bit := 6*(first+i) - 8*shift // bit offset inside raw
		v := 0
		for k := range 6 {
			b := bit + k
			v = v<<1 | int(raw[b/8]>>(7-b%8)&1)
		}
		dst[i] = alpha[v]
	}
}

// jsonMode selects a JSON string escaper.
type jsonMode int

const (
	jsonMin   jsonMode = iota // " \ and control characters (Python json.dumps of ASCII, jq)
	jsonHTML                  // also < > & as \u003c \u003e \u0026 (Go encoding/json)
	jsonSlash                 // also / as \/ (PHP json_encode)
)

// jsonEsc returns the escape for c in mode, or "" to keep c.
func jsonEsc(c byte, mode jsonMode) string {
	switch c {
	case '"':
		return `\"`
	case '\\':
		return `\\`
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	}
	if c < 0x20 {
		const digits = "0123456789abcdef"
		return `\u00` + string(digits[c>>4]) + string(digits[c&15])
	}
	switch {
	case mode == jsonHTML && c == '<':
		return `\u003c`
	case mode == jsonHTML && c == '>':
		return `\u003e`
	case mode == jsonHTML && c == '&':
		return `\u0026`
	case mode == jsonSlash && c == '/':
		return `\/`
	}
	return ""
}

func jsonLen(src []byte, mode jsonMode) int {
	n := 0
	for _, c := range src {
		if e := jsonEsc(c, mode); e != "" {
			n += len(e)
		} else {
			n++
		}
	}
	return n
}

func jsonEscape(dst, src []byte, mode jsonMode) {
	i := 0
	for _, c := range src {
		if e := jsonEsc(c, mode); e != "" {
			i += copy(dst[i:], e)
		} else {
			dst[i] = c
			i++
		}
	}
}

// shellMode selects a shell escaper.
type shellMode int

const (
	shellDouble      shellMode = iota // inside double quotes (declare -p): \$ \` \" \\
	shellPrintfQ                      // bash printf %q, the value inside a word (PW=VALUE)
	shellPrintfQWord                  // bash printf %q, the value starting a word
)

// printfQSpecial are the bytes bash's printf %q puts a backslash before
// anywhere in a word (bash 5.2, lib/sh/shquote.c; checked against bash's
// own output in the tests). '#' is escaped only at the start of a word,
// '~' at the start and after '=' or ':' (review M1).
const printfQSpecial = "!\"$&'()*,;<>?[\\]^`{|} "

func shellEsc(src []byte, i int, mode shellMode) bool {
	c := src[i]
	if mode == shellDouble {
		return c == '$' || c == '`' || c == '"' || c == '\\'
	}
	if strings.IndexByte(printfQSpecial, c) >= 0 {
		return true
	}
	start := i == 0 && mode == shellPrintfQWord
	switch c {
	case '#':
		return start
	case '~':
		return start || i > 0 && (src[i-1] == '=' || src[i-1] == ':')
	}
	return false
}

// shellLen is the escaped length; ok is false for values with control
// characters (printf %q quotes those as $'...').
func shellLen(src []byte, mode shellMode) (int, bool) {
	n := 0
	for i, c := range src {
		if c < 0x20 || c == 0x7f {
			return 0, false
		}
		if c < 0x80 && shellEsc(src, i, mode) {
			n++
		}
		n++
	}
	return n, true
}

func shellEscape(dst, src []byte, mode shellMode) {
	j := 0
	for i, c := range src {
		if c < 0x80 && shellEsc(src, i, mode) {
			dst[j] = '\\'
			j++
		}
		dst[j] = c
		j++
	}
}

// dropBytes copies src into dst without the bytes in drop.
func dropBytes(dst, src []byte, drop string) {
	i := 0
	for _, c := range src {
		if strings.IndexByte(drop, c) < 0 {
			dst[i] = c
			i++
		}
	}
}
