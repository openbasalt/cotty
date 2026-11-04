package confine

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// systemTool returns the path of a system program (systemd-run,
// systemctl) at a fixed, root-owned place, never through the person's
// PATH: cotty runs it outside the confinement, and a PATH entry the agent
// can write (a project's node_modules/.bin, a direnv-added bin) would run
// the agent's program with the person's rights.
func systemTool(name string) (string, error) {
	for _, d := range []string{"/usr/bin", "/bin", "/run/current-system/sw/bin"} {
		p := filepath.Join(d, name)
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		if err := rootOwnedChain(real); err != nil {
			return "", fmt.Errorf("%s: %w", real, err)
		}
		return real, nil
	}
	return "", fmt.Errorf("%s not found in /usr/bin or /bin", name)
}

// rootOwnedChain checks that p and every directory above it belong to
// root and are not writable by group or others (a sticky directory such
// as /tmp never qualifies).
func rootOwnedChain(p string) error {
	for d := p; ; d = filepath.Dir(d) {
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is not owned by root or is writable by others", d)
		}
		if d == "/" {
			return nil
		}
	}
}

// abstractSocketsAtRisk returns the listening abstract Unix sockets that an
// agent could reach without Landlock scoping (ABI < 6) and that matter:
// X11 displays (keystrokes of every X client), D-Bus buses, ICE session
// managers, input methods and terminal emulators' remote control.
func abstractSocketsAtRisk() []string {
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 8 || !strings.HasPrefix(fl[7], "@") {
			continue
		}
		name := fl[7]
		low := strings.ToLower(name)
		for _, k := range []string{"/.x11-unix/", "dbus", "/.ice-unix/", "ibus", "fcitx", "kitty", "wezterm", "xwayland", "pulse", "pipewire"} {
			if strings.Contains(low, k) && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}
