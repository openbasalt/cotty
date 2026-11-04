// Command vteval compares terminal emulator libraries on real program
// output. Each scenario runs a program in a PTY, feeds it scripted input,
// records every byte the program printed up to a snapshot point, and then
// replays the recording into charmbracelet/x/vt, hinshun/vt10x and tmux
// (the oracle: `tmux capture-pane -p` on a pane that cats the recording).
// It prints, per scenario, how many rows each library renders differently
// from tmux, and whether the cursor matches.
//
// It is a development tool for the choice documented in docs/vt.md; it is
// not part of the cotty binary, and it is its own Go module so vt10x
// stays out of cotty's dependencies. Run it where tmux, bash, zsh, vim, less,
// htop and git are installed:
//
//	(cd tools/vteval && go run . -out /path/to/dir)
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/x/vt"
	"github.com/creack/pty"
	"github.com/hinshun/vt10x"
)

const (
	cols = 100
	rows = 30
)

// step is one scripted action: wait, then send input.
type step struct {
	wait  time.Duration
	input string
}

type scenario struct {
	name  string
	argv  []string
	steps []step
}

func scenarios(dir string) []scenario {
	sample := filepath.Join(dir, "sample.txt")
	var b strings.Builder
	for i := 1; i <= 400; i++ {
		fmt.Fprintf(&b, "line %03d: the quick brown fox jumps over the lazy dog %s\n", i, strings.Repeat("=", i%40))
	}
	_ = os.WriteFile(sample, []byte(b.String()), 0o600)
	repo := filepath.Join(dir, "repo")
	if _, err := os.Stat(repo); err != nil {
		script := "set -e; git init -q " + repo + "; cd " + repo + "; git config user.email t@example.com; git config user.name t; git config commit.gpgsign false;" +
			"for i in $(seq 1 30); do echo $i > f$((i%5)); git add -A; git commit -qm \"commit number $i with a longer subject line to wrap around\"; " +
			"if [ $((i%7)) = 0 ]; then git checkout -qb b$i; fi; done"
		if out, err := exec.Command("bash", "-c", script).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "repo setup: %v %s\n", err, out)
		}
	}
	ps1 := `PS1='\[\e[1;32m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '`
	return []scenario{
		{"bash-ls-colours", []string{"bash", "--norc", "--noprofile", "-i"}, []step{
			{300 * time.Millisecond, ps1 + "\r"},
			{200 * time.Millisecond, "ls --color=always -la /usr/bin | head -40\r"},
			{500 * time.Millisecond, "printf 'wide: \\u4f60\\u597d\\u4e16\\u754c emoji: \\U0001F600 combining: e\\u0301 tab:\\tend\\n'\r"},
			{300 * time.Millisecond, "printf '%0250d\\n' 7\r"},
			{300 * time.Millisecond, "printf '\\u4f60\\u597d|\\e[20Gcol20 \\e[1;33mbold\\e[0m \\e[2Kcleared\\rCR\\n'\r"},
			{500 * time.Millisecond, ""},
		}},
		{"bash-seq-scroll", []string{"bash", "--norc", "--noprofile", "-i"}, []step{
			{300 * time.Millisecond, "seq 1 500\r"},
			{500 * time.Millisecond, "echo done\r"},
			{300 * time.Millisecond, ""},
		}},
		{"zsh-zle", []string{"zsh", "-f", "-i"}, []step{
			{400 * time.Millisecond, "autoload -U colors && colors; PROMPT='%F{green}%n%f %F{blue}%~%f %# '\r"},
			{300 * time.Millisecond, "echo hello world"},
			{200 * time.Millisecond, "\x01"},         // C-a
			{200 * time.Millisecond, "\x1b[C\x1b[C"}, // right right
			{200 * time.Millisecond, "XX"},
			{200 * time.Millisecond, "\r"},
			{300 * time.Millisecond, "for i in 1 2 3; do\r"},
			{200 * time.Millisecond, "echo $i\r"},
			{200 * time.Millisecond, "done\r"},
			{500 * time.Millisecond, ""},
		}},
		{"vim-insert", []string{"vim", "-u", "NONE", "-N", sample}, []step{
			{800 * time.Millisecond, ":syntax on\r"},
			{200 * time.Millisecond, ":set number\r"},
			{200 * time.Millisecond, "50G"},
			{200 * time.Millisecond, "oinserted by vteval \x1b"},
			{200 * time.Millisecond, "\x04"}, // C-d half page
			{300 * time.Millisecond, ""},
		}},
		{"less-scroll", []string{"less", sample}, []step{
			{500 * time.Millisecond, " "},
			{200 * time.Millisecond, "j"},
			{200 * time.Millisecond, "/fox\r"},
			{400 * time.Millisecond, ""},
		}},
		{"htop", []string{"htop", "-d", "10"}, []step{
			{1500 * time.Millisecond, ""},
		}},
		{"git-log-graph", []string{"bash", "--norc", "--noprofile", "-i"}, []step{
			{300 * time.Millisecond, "cd " + repo + " && git -c color.ui=always log --graph --decorate --all --oneline | head -40\r"},
			{700 * time.Millisecond, ""},
		}},
		{"git-log-pager", []string{"bash", "--norc", "--noprofile", "-i"}, []step{
			{300 * time.Millisecond, "cd " + repo + " && git -c color.ui=always -c core.pager='less -R' log --stat\r"},
			{800 * time.Millisecond, " "},
			{400 * time.Millisecond, ""},
		}},
	}
}

// record runs a scenario and returns everything the program printed.
func record(sc scenario) ([]byte, error) {
	cmd := exec.Command(sc.argv[0], sc.argv[1:]...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLUMNS=", "LINES=", "LANG=C.UTF-8")
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var out bytes.Buffer
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				mu.Lock()
				out.Write(buf[:n])
				mu.Unlock()
				// Answer cursor position and device attribute queries the
				// way a terminal would, so programs do not stall.
				answer(f, buf[:n])
			}
			if err != nil {
				close(done)
				return
			}
		}
	}()
	for _, s := range sc.steps {
		time.Sleep(s.wait)
		if s.input != "" {
			_, _ = f.Write([]byte(s.input))
		}
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	snap := bytes.Clone(out.Bytes())
	mu.Unlock()
	_ = cmd.Process.Kill()
	_ = f.Close()
	<-done
	_ = cmd.Wait()
	return snap, nil
}

// answer replies to the queries programs commonly send at start-up.
func answer(f io.Writer, b []byte) {
	if bytes.Contains(b, []byte("\x1b[6n")) {
		_, _ = f.Write([]byte("\x1b[1;1R"))
	}
	if bytes.Contains(b, []byte("\x1b[c")) || bytes.Contains(b, []byte("\x1b[0c")) {
		_, _ = f.Write([]byte("\x1b[?62;22c"))
	}
}

func xvtRows(data []byte) ([]string, [2]int) {
	e := vt.NewEmulator(cols, rows)
	go func() { _, _ = io.Copy(io.Discard, e) }()
	_, _ = e.Write(data)
	out := make([]string, rows)
	for y := range rows {
		var b strings.Builder
		for x := 0; x < cols; x++ {
			c := e.CellAt(x, y)
			switch {
			case c == nil:
				b.WriteByte(' ')
			case c.Content == "" && c.Width == 0:
				// continuation of a wide cell
			case c.Content == "":
				b.WriteByte(' ')
			default:
				b.WriteString(c.Content)
			}
		}
		out[y] = strings.TrimRight(b.String(), " ")
	}
	p := e.CursorPosition()
	_ = e.Close()
	return out, [2]int{p.X, p.Y}
}

func vt10xRows(data []byte) ([]string, [2]int) {
	t := vt10x.New(vt10x.WithWriter(io.Discard), vt10x.WithSize(cols, rows))
	_, _ = t.Write(data)
	t.Lock()
	defer t.Unlock()
	out := make([]string, rows)
	for y := range rows {
		var b strings.Builder
		for x := 0; x < cols; x++ {
			r := t.Cell(x, y).Char
			if r == 0 {
				r = ' '
			}
			b.WriteRune(r)
		}
		out[y] = strings.TrimRight(b.String(), " ")
	}
	c := t.Cursor()
	return out, [2]int{c.X, c.Y}
}

func tmuxRows(rec string) ([]string, [2]int, error) {
	sock := "vteval-" + strconv.Itoa(os.Getpid())
	tm := func(args ...string) ([]byte, error) {
		return exec.Command("tmux", append([]string{"-L", sock, "-f", "/dev/null"}, args...)...).CombinedOutput()
	}
	defer func() { _, _ = tm("kill-server") }()
	if out, err := tm("new-session", "-d", "-x", strconv.Itoa(cols), "-y", strconv.Itoa(rows),
		"stty raw -echo; cat "+rec+"; sleep 30"); err != nil {
		return nil, [2]int{}, fmt.Errorf("tmux: %v %s", err, out)
	}
	_, _ = tm("set-option", "-g", "status", "off")
	_, _ = tm("resize-window", "-x", strconv.Itoa(cols), "-y", strconv.Itoa(rows))
	time.Sleep(1500 * time.Millisecond)
	out, err := tm("capture-pane", "-p")
	if err != nil {
		return nil, [2]int{}, fmt.Errorf("capture: %v %s", err, out)
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	for len(lines) < rows {
		lines = append(lines, "")
	}
	for i := range lines {
		lines[i] = strings.TrimRight(expandTabs(lines[i]), " ")
	}
	cur, _ := tm("display-message", "-p", "#{cursor_x} #{cursor_y}")
	var cx, cy int
	_, _ = fmt.Sscanf(string(cur), "%d %d", &cx, &cy)
	return lines[:rows], [2]int{cx, cy}, nil
}

// expandTabs turns the tabs tmux keeps in captured text into spaces up
// to the next multiple of eight columns (wide runes count two).
func expandTabs(s string) string {
	var b strings.Builder
	col := 0
	for _, r := range s {
		if r == '\t' {
			n := 8 - col%8
			b.WriteString(strings.Repeat(" ", n))
			col += n
			continue
		}
		b.WriteRune(r)
		if r >= 0x1100 {
			col += 2
		} else {
			col++
		}
	}
	return b.String()
}

func diff(a, b []string) (n int, first string) {
	for i := range a {
		if a[i] != b[i] {
			if n == 0 {
				first = fmt.Sprintf("row %d\n      want %q\n      got  %q", i, a[i], b[i])
			}
			n++
		}
	}
	return n, first
}

// fuzz feeds random streams biased towards escape sequences to both
// libraries and counts panics.
func fuzz(n int) {
	rng := rand.New(rand.NewPCG(1, 2))
	alphabet := []string{"\x1b[", "\x1b]", "\x1bP", "\x07", "\x1b\\", ";", "?", "1", "9", "99999", "m", "H", "J", "K", "r", "h", "l", "@", "L", "M", "P", "X", "S", "T", "\r", "\n", "\t", "\b", "a", "\u4f60", "\u0301", "\U0001F600", "\x9b", "\xff", "\x1b(0", "q"}
	panics := map[string]int{}
	for i := 0; i < n; i++ {
		var b strings.Builder
		for j := 0; j < 2000; j++ {
			b.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		data := []byte(b.String())
		for _, lib := range []struct {
			name string
			run  func([]byte)
		}{
			{"x/vt", func(d []byte) { xvtRows(d) }},
			{"vt10x", func(d []byte) { vt10xRows(d) }},
		} {
			func() {
				defer func() {
					if r := recover(); r != nil {
						panics[lib.name]++
					}
				}()
				lib.run(data)
			}()
		}
	}
	fmt.Printf("fuzz: %d streams, panics: x/vt %d, vt10x %d\n", n, panics["x/vt"], panics["vt10x"])
}

func main() {
	outDir := flag.String("out", "", "directory for recordings (default: a temp dir)")
	verbose := flag.Bool("v", false, "print the first differing row")
	fuzzN := flag.Int("fuzz", 0, "also feed N random byte streams to both libraries and count panics")
	flag.Parse()
	if *fuzzN > 0 {
		fuzz(*fuzzN)
	}
	dir := *outDir
	if dir == "" {
		d, err := os.MkdirTemp("", "vteval")
		if err != nil {
			panic(err)
		}
		dir = d
	}
	_ = os.MkdirAll(dir, 0o700)
	fmt.Printf("%-16s %10s %12s %12s\n", "scenario", "bytes", "x/vt rows", "vt10x rows")
	for _, sc := range scenarios(dir) {
		data, err := record(sc)
		if err != nil {
			fmt.Printf("%-16s error: %v\n", sc.name, err)
			continue
		}
		rec := filepath.Join(dir, sc.name+".rec")
		_ = os.WriteFile(rec, data, 0o600)
		want, wcur, err := tmuxRows(rec)
		if err != nil {
			fmt.Printf("%-16s error: %v\n", sc.name, err)
			continue
		}
		xr, xcur := xvtRows(data)
		vr, vcur := vt10xRows(data)
		xn, xf := diff(want, xr)
		vn, vf := diff(want, vr)
		mark := func(c [2]int) string {
			if c == wcur {
				return ""
			}
			return "*"
		}
		fmt.Printf("%-16s %10d %11d%s %11d%s\n", sc.name, len(data), xn, mark(xcur), vn, mark(vcur))
		if *verbose {
			if xf != "" {
				fmt.Printf("   x/vt  %s\n", xf)
			}
			if vf != "" {
				fmt.Printf("   vt10x %s\n", vf)
			}
		}
	}
	fmt.Println("(rows = rows differing from tmux capture-pane; * = cursor position differs)")
}
