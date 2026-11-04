package secretsrc

// Adapted from basalt-agent internal/secrets (basalt-os/basalt-os,
// packages/basalt-agent), same owner, Apache-2.0.

import (
	"bytes"
	"fmt"
	"io"
)

// ReadEnvKey returns the value of key in an env-style file: KEY=VALUE
// lines, blank lines and # comments ignored, an optional "export " prefix,
// one pair of matching single or double quotes around the value stripped
// (no escapes, no expansion), and an inline comment after the value
// dropped (whitespace then #, as a shell reads it; quote a value that
// holds " #"). The file must be a regular file
// owned by the user with no group or other access (0600), and not a
// symbolic link. Errors name the file and the line number, never content.
func ReadEnvKey(path, key string) ([]byte, error) {
	f, err := openPrivate(path, 0o077, "must be a regular file owned by you with mode 0600 (chmod 600 "+path+")")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	defer clear(data)
	if err != nil {
		return nil, err
	}
	var found []byte
	for n, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		line = bytes.TrimPrefix(line, []byte("export "))
		k, v, ok := bytes.Cut(line, []byte("="))
		if !ok {
			clear(found)
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", path, n+1)
		}
		if string(bytes.TrimSpace(k)) != key {
			continue
		}
		v = envValue(bytes.TrimSpace(v))
		if bytes.IndexByte(v, 0) >= 0 {
			clear(found)
			return nil, fmt.Errorf("%s:%d: value contains a NUL byte", path, n+1)
		}
		clear(found)
		found = make([]byte, len(v)) // last definition wins, like a shell
		copy(found, v)
	}
	if found == nil {
		return nil, fmt.Errorf("%s: key %s: %w", path, key, ErrNotFound)
	}
	return found, nil
}

// envValue strips the quotes and an inline comment from a trimmed value.
// Quoted: the value ends at the first matching quote followed only by
// blanks or a comment (so a quote inside the value is kept). Unquoted: the
// value ends before the first blank followed by '#'.
func envValue(v []byte) []byte {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		q := v[0]
		for j := 1; j < len(v); j++ {
			if v[j] != q {
				continue
			}
			rest := bytes.TrimSpace(v[j+1:])
			if len(rest) == 0 || rest[0] == '#' {
				return v[1:j]
			}
		}
		return v
	}
	for i := 1; i < len(v); i++ {
		if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
			return bytes.TrimSpace(v[:i])
		}
	}
	return v
}
