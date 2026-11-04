package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/mask"
	"github.com/openbasalt/cotty/internal/secretsrc"
)

func init() {
	register(command{name: "secrets", usage: "list | add NAME [SOURCE] | remove NAME | check [NAME]",
		summary: "manage the masking list (references only; values are never printed)", run: runSecrets})
}

const secretsUsage = `usage:
  cotty secrets list                      names and where each value comes from
  cotty secrets add NAME                  read the value (echo off) into secrets.env
  cotty secrets add NAME --command 'PROG ARG...'   the command's output (run without a shell)
  cotty secrets add NAME --pass PATH      the first line of ` + "`pass show PATH`" + `
  cotty secrets add NAME --secret-service attr=val[,attr=val]   secret-tool lookup
  cotty secrets add NAME --ref REF        any reference (file:KEY, cmd:NAME, ...)
  cotty secrets remove NAME               drop the reference (and the secrets.env line)
  cotty secrets check [NAME]              read each value and report ok or the error, never the value

The list lives in ~/.config/cotty/secrets.conf (values of file: references
in ~/.config/cotty/secrets.env, mode 0600). New sessions mask every listed
secret; a running session masks one when an agent calls term_mask NAME.`

var secretNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// weakAdvice explains why a weak value matters (docs/security.md, Masking
// is not a boundary).
const weakAdvice = "Masking tells whoever prints text whether that text is on the list, so an agent can guess a weak value by printing candidates; use a long random value"

func runSecrets(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, secretsUsage)
		return 2
	}
	confPath := secretsrc.DefaultConfigPath()
	switch args[0] {
	case "list", "ls":
		return secretsList(confPath)
	case "add":
		return secretsAdd(confPath, args[1:])
	case "remove", "rm":
		if len(args) != 2 {
			return fail("usage: cotty secrets remove NAME")
		}
		return secretsRemove(confPath, args[1])
	case "check":
		return secretsCheck(confPath, args[1:])
	case "-h", "--help", "help":
		fmt.Println(secretsUsage)
		return 0
	}
	fmt.Fprintln(os.Stderr, secretsUsage)
	return 2
}

func loadSecretsConf(path string) (*secretsrc.Config, error) {
	cfg, err := secretsrc.LoadConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		return secretsrc.ParseConfig(path, "")
	}
	return cfg, err
}

func secretsList(confPath string) int {
	cfg, err := loadSecretsConf(confPath)
	if err != nil {
		return fail("%v", err)
	}
	if len(cfg.Secrets) == 0 {
		fmt.Printf("no secrets in %s (cotty secrets add NAME)\n", confPath)
		return 0
	}
	for _, e := range cfg.Secrets {
		ref := e.Ref.String()
		if e.Ref.Scheme == secretsrc.SchemeCmd {
			ref += " " + strings.Join(quoteArgv(cfg.Commands[e.Ref.Arg]), " ")
		}
		fmt.Printf("%-24s %s\n", e.Name, ref)
	}
	return 0
}

func quoteArgv(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		b, _ := json.Marshal(a)
		out[i] = string(b)
	}
	return out
}

func secretsCheck(confPath string, names []string) int {
	cfg, err := secretsrc.LoadConfig(confPath)
	if err != nil {
		return fail("%v", err)
	}
	r := secretsrc.NewResolver(cfg, secretsrc.Options{})
	if len(names) == 0 {
		for _, e := range cfg.Secrets {
			names = append(names, e.Name)
		}
	}
	bad := 0
	for _, n := range names {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		v, err := r.Resolve(ctx, n)
		cancel()
		if err != nil {
			bad++
			fmt.Printf("%-24s error: %v\n", n, err)
			continue
		}
		tooShort, warns := mask.Assess(v)
		clear(v)
		if tooShort {
			bad++
			fmt.Printf("%-24s NOT MASKED: the value is shorter than %d bytes, too short for the masking list (it would hide ordinary text); sessions skip it\n", n, mask.DefaultMinLen)
			continue
		}
		fmt.Printf("%-24s ok\n", n)
		if len(warns) > 0 {
			fmt.Printf("%-24s warning: weak value: %s. %s\n", "", strings.Join(warns, "; "), weakAdvice)
		}
	}
	if bad > 0 {
		return 1
	}
	return 0
}

func secretsAdd(confPath string, args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fail("usage: cotty secrets add NAME [--command 'PROG ARG...' | --pass PATH | --secret-service ATTRS | --ref REF]")
	}
	name := args[0]
	fs := flag.NewFlagSet("secrets add", flag.ContinueOnError)
	command := fs.String("command", "", "a command whose standard output is the value (split on spaces, or a JSON array; no shell)")
	pass := fs.String("pass", "", "a pass(1) entry")
	ss := fs.String("secret-service", "", "Secret Service attributes, attr=val[,attr=val]")
	refFlag := fs.String("ref", "", "a reference as written in secrets.conf")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return fail("the value is never taken from the command line; run `cotty secrets add %s` and type it", name)
	}
	if !secretNameRE.MatchString(name) {
		return fail("bad name %q (letters, digits, . _ -; up to 64)", name)
	}
	cfg, err := loadSecretsConf(confPath)
	if err != nil {
		return fail("%v", err)
	}
	for _, e := range cfg.Secrets {
		if e.Name == name {
			return fail("%s is already on the list (cotty secrets remove %s first)", name, name)
		}
	}
	set := 0
	for _, v := range []string{*command, *pass, *ss, *refFlag} {
		if v != "" {
			set++
		}
	}
	if set > 1 {
		return fail("give one source")
	}
	var ref string
	var cmdArgv []string
	switch {
	case *command != "":
		cmdArgv, err = parseArgv(*command)
		if err != nil {
			return fail("--command: %v", err)
		}
		if _, dup := cfg.Commands[name]; dup {
			return fail("a command named %s already exists in secrets.conf", name)
		}
		ref = "cmd:" + name
	case *pass != "":
		ref = "pass:" + *pass
	case *ss != "":
		ref = "secret-service:" + *ss
	case *refFlag != "":
		ref = *refFlag
	default:
		v, err := readSecretValue(name)
		if err != nil {
			return fail("%v", err)
		}
		defer clear(v)
		tooShort, warns := mask.Assess(v)
		if tooShort {
			return fail("the value is shorter than %d bytes: cotty does not mask values that short (they would hide ordinary text); not added", mask.DefaultMinLen)
		}
		if len(warns) > 0 {
			fmt.Fprintf(os.Stderr, "warning: weak value: %s. %s\n", strings.Join(warns, "; "), weakAdvice)
		}
		if err := envFileSet(cfg.EnvFile, name, v); err != nil {
			return fail("%v", err)
		}
		ref = "file:" + name
	}
	if _, err := secretsrc.ParseRef(ref); err != nil {
		return fail("%v", err)
	}
	if err := confAdd(confPath, name, ref, cmdArgv); err != nil {
		return fail("%v", err)
	}
	fmt.Printf("%s added (%s); new sessions mask it, a running one when an agent calls term_mask %s\n", name, ref, name)
	if !strings.HasPrefix(ref, "file:") {
		fmt.Printf("run `cotty secrets check %s` to read it once: values under %d bytes are not masked, and weak ones are flagged\n", name, mask.DefaultMinLen)
	}
	return 0
}

func secretsRemove(confPath, name string) int {
	cfg, err := secretsrc.LoadConfig(confPath)
	if err != nil {
		return fail("%v", err)
	}
	var ref *secretsrc.Ref
	for _, e := range cfg.Secrets {
		if e.Name == name {
			r := e.Ref
			ref = &r
		}
	}
	if ref == nil {
		return fail("%s is not on the list", name)
	}
	cmdName := ""
	if ref.Scheme == secretsrc.SchemeCmd {
		cmdName = ref.Arg
		for _, e := range cfg.Secrets {
			if e.Name != name && e.Ref.Scheme == secretsrc.SchemeCmd && e.Ref.Arg == cmdName {
				cmdName = "" // still used by another secret
			}
		}
	}
	if err := confRemove(confPath, name, cmdName); err != nil {
		return fail("%v", err)
	}
	if ref.Scheme == secretsrc.SchemeFile {
		if err := envFileRemove(cfg.EnvFile, ref.Arg); err != nil {
			return fail("%v", err)
		}
	}
	fmt.Printf("%s removed\n", name)
	return 0
}

// parseArgv takes a JSON array or words separated by spaces.
func parseArgv(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	var argv []string
	if strings.HasPrefix(s, "[") {
		if err := json.Unmarshal([]byte(s), &argv); err != nil {
			return nil, err
		}
	} else {
		argv = strings.Fields(s)
	}
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("empty command")
	}
	return argv, nil
}

// readSecretValue reads one line from the terminal with echo off (inside
// a cotty session the lock lights for it), or from standard input when it
// is not a terminal.
func readSecretValue(name string) ([]byte, error) {
	var r io.Reader = os.Stdin
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		if old, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS); err == nil {
			fmt.Fprintf(tty, "Value of %s (not shown): ", name)
			t := *old
			t.Lflag &^= unix.ECHO
			t.Lflag |= unix.ICANON
			_ = unix.IoctlSetTermios(int(tty.Fd()), unix.TCSETS, &t)
			defer func() {
				_ = unix.IoctlSetTermios(int(tty.Fd()), unix.TCSETS, old)
				fmt.Fprintln(tty)
			}()
			r = tty
		}
	}
	br := bufio.NewReaderSize(r, 4096)
	line, err := br.ReadSlice('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		clear(line)
		return nil, fmt.Errorf("reading the value: %w", err)
	}
	v := bytes.TrimRight(line, "\r\n")
	out := append([]byte(nil), v...)
	clear(line)
	if len(out) == 0 {
		return nil, errors.New("empty value")
	}
	return out, nil
}

// writePrivate replaces path with content (mode 0600, directory 0700),
// through a temporary file and a rename.
func writePrivate(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// readPrivate reads a file that may not exist yet.
func readPrivate(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// envFileSet appends KEY=VALUE to the env file (replacing an earlier line
// for the key). The value is quoted when the reader would otherwise trim
// or unquote it.
func envFileSet(path, key string, v []byte) error {
	if bytes.ContainsAny(v, "\n\r\x00") {
		return errors.New("the value must be one line without NUL bytes")
	}
	old, err := readPrivate(path)
	if err != nil {
		return err
	}
	defer clear(old)
	var buf bytes.Buffer
	defer func() { clear(buf.Bytes()) }()
	for _, line := range bytes.SplitAfter(old, []byte("\n")) {
		if envLineKey(line) == key {
			clear(line)
			continue
		}
		buf.Write(line)
	}
	if buf.Len() > 0 && !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
		buf.WriteByte('\n')
	}
	buf.WriteString(key)
	buf.WriteByte('=')
	t := bytes.TrimSpace(v)
	// Quote when the reader would otherwise trim, unquote, or cut an
	// inline comment (" #") from the value.
	quoted := len(t) != len(v) || len(v) >= 1 && (v[0] == '"' || v[0] == '\'') ||
		bytes.Contains(v, []byte(" #")) || bytes.Contains(v, []byte("\t#"))
	if quoted {
		q := byte('"')
		if bytes.IndexByte(v, '"') >= 0 {
			q = '\''
		}
		if bytes.IndexByte(v, q) >= 0 && (bytes.Contains(v, []byte(" #")) || bytes.Contains(v, []byte("\t#"))) {
			// The reader takes the first matching quote followed by a
			// comment as the end: no quoting keeps this value whole.
			return errors.New("the value holds both quote characters and \" #\"; use another source (--command, --pass)")
		}
		buf.WriteByte(q)
		buf.Write(v)
		buf.WriteByte(q)
	} else {
		buf.Write(v)
	}
	buf.WriteByte('\n')
	return writePrivate(path, buf.Bytes())
}

// envFileRemove drops the lines of key from the env file.
func envFileRemove(path, key string) error {
	old, err := readPrivate(path)
	if err != nil || old == nil {
		return err
	}
	defer clear(old)
	var buf bytes.Buffer
	defer func() { clear(buf.Bytes()) }()
	for _, line := range bytes.SplitAfter(old, []byte("\n")) {
		if envLineKey(line) != key {
			buf.Write(line)
		}
	}
	return writePrivate(path, buf.Bytes())
}

func envLineKey(line []byte) string {
	l := bytes.TrimSpace(line)
	if len(l) == 0 || l[0] == '#' {
		return ""
	}
	l = bytes.TrimPrefix(l, []byte("export "))
	k, _, ok := bytes.Cut(l, []byte("="))
	if !ok {
		return ""
	}
	return string(bytes.TrimSpace(k))
}

const confHeader = `# cotty masking list: NAME = reference (values never go in this file).
# Edit with ` + "`cotty secrets`" + ` or by hand; see docs/mcp.md.
`

// confAdd inserts NAME = REF at the end of [secrets] and, for a command,
// NAME = ["argv"...] at the end of [commands], then checks that the
// result parses.
func confAdd(path, name, ref string, argv []string) error {
	old, err := readPrivate(path)
	if err != nil {
		return err
	}
	text := string(old)
	if text == "" {
		text = confHeader
	}
	text = sectionAppend(text, "secrets", name+" = "+ref)
	if argv != nil {
		b, _ := json.Marshal(argv)
		text = sectionAppend(text, "commands", name+" = "+string(b))
	}
	if _, err := secretsrc.ParseConfig(path, text); err != nil {
		return err
	}
	return writePrivate(path, []byte(text))
}

// confRemove drops name from [secrets] and, when cmdName is set, that
// entry from [commands].
func confRemove(path, name, cmdName string) error {
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var out []string
	section := ""
	for _, line := range strings.SplitAfter(string(old), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.TrimSpace(t[1 : len(t)-1])
		}
		k, _, ok := strings.Cut(t, "=")
		key := strings.TrimSpace(k)
		if ok && ((section == "secrets" && key == name) || (cmdName != "" && section == "commands" && key == cmdName)) {
			continue
		}
		out = append(out, line)
	}
	text := strings.Join(out, "")
	if _, err := secretsrc.ParseConfig(path, text); err != nil {
		return err
	}
	return writePrivate(path, []byte(text))
}

// sectionAppend adds line at the end of [section], creating the section
// at the end of the text when missing.
func sectionAppend(text, section, line string) string {
	lines := strings.SplitAfter(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	in, last := false, -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			in = strings.TrimSpace(t[1:len(t)-1]) == section
			if in {
				last = i
			}
			continue
		}
		if in && t != "" {
			last = i
		}
	}
	if last < 0 {
		if len(lines) > 0 && !strings.HasSuffix(lines[len(lines)-1], "\n") {
			lines[len(lines)-1] += "\n"
		}
		return strings.Join(lines, "") + "\n[" + section + "]\n" + line + "\n"
	}
	if !strings.HasSuffix(lines[last], "\n") {
		lines[last] += "\n"
	}
	out := append(append(append([]string(nil), lines[:last+1]...), line+"\n"), lines[last+1:]...)
	return strings.Join(out, "")
}
