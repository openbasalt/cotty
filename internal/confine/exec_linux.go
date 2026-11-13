package confine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// RunExec is the exec stage: it confines itself and becomes the agent. It
// returns only on failure.
func RunExec() {
	// Every step below is per thread at least; the thread that executes
	// the agent is this one.
	runtime.LockOSThread()
	specFile := os.NewFile(3, "spec")
	var sp Spec
	if err := json.NewDecoder(specFile).Decode(&sp); err != nil {
		execFail(125, "spec: %v", err)
	}
	specFile.Close()

	if err := checkNoCaps(); err != nil {
		execFail(125, "%v", err)
	}
	// No core dumps: the hard limit too, so the agent cannot raise it.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		execFail(125, "RLIMIT_CORE: %v", err)
	}
	if err := os.Chdir(sp.Workdir); err != nil {
		execFail(125, "%v", err)
	}
	if err := confineAppArmor(); err != nil {
		execFail(125, "%v", err)
	}
	if err := setNoNewPrivs(); err != nil {
		execFail(125, "no_new_privs: %v", err)
	}
	if abi := LandlockABI(); abi < 6 && !sp.Landlock.NoScopesOK {
		execFail(125, "landlock ABI %d cannot scope abstract sockets and signals, and the launcher did not accept that", abi)
	}
	if abi, err := ApplyLandlock(sp.Landlock); landlockApplied(abi, err, sp.Landlock.NoLandlockOK) != nil {
		execFail(125, "landlock: %v", err)
	}
	if sp.Seccomp && SeccompSupported() {
		if err := InstallSeccomp(); err != nil {
			execFail(125, "%v", err)
		}
	}
	// Only stdio crosses into the agent.
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		for fd := 3; fd < 1024; fd++ {
			unix.CloseOnExec(fd)
		}
	}
	path, err := lookPath(sp.Argv[0], GetEnv(sp.Env, "PATH"))
	if err != nil {
		execFail(127, "%v", err)
	}
	err = syscall.Exec(path, sp.Argv, sp.Env)
	execFail(126, "exec %s: %v", path, err)
}

func execFail(code int, f string, a ...any) {
	fmt.Fprintf(os.Stderr, "cotty agent: "+f+"\n", a...)
	os.Exit(code)
}

// checkNoCaps refuses to continue when this process holds any capability:
// with one, the agent could change its mounts.
func checkNoCaps() error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch k {
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
			if strings.Trim(strings.TrimSpace(v), "0") != "" {
				return fmt.Errorf("refusing to start the agent: %s is %s, want none", k, strings.TrimSpace(v))
			}
		}
	}
	return nil
}

// lookPath finds name in the agent's PATH (in its own view of the files).
func lookPath(name, path string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, d := range filepath.SplitList(path) {
		if d == "" {
			d = "."
		}
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in the agent's PATH (a program under $HOME needs `cotty agent --ro DIR` or a profile entry)", name)
}
