package confine

import "errors"

var errNoLandlock = errors.New("this kernel has no Landlock (not built in, or not in the lsm= boot list): " +
	"only the mount view would limit the agent's files, and abstract sockets and signals would not be scoped. " +
	"Use a kernel with Landlock, or start with --allow-no-landlock to accept that (sessions then report the agent weak)")

// Spec is everything the confined stages need, computed outside by the
// launcher and passed to them as JSON on a pipe (never in the environment
// or on the command line, which the agent could read).
type Spec struct {
	Profile    string `json:"profile"`
	Project    string `json:"project"`  // real path
	Home       string `json:"home"`     // real path of $HOME, covered by a tmpfs
	RuntimeDir string `json:"runtime"`  // real path of $XDG_RUNTIME_DIR, covered by a tmpfs
	AgentDir   string `json:"agentDir"` // the agent endpoint directory inside (empty: none)
	SelfBin    string `json:"selfBin"`  // where the cotty binary is bound inside
	UID        int    `json:"uid"`
	GID        int    `json:"gid"`

	// Hide lists directories covered with an empty tmpfs (only when they
	// exist). Binds whose target lies below one are put back on top.
	Hide []string `json:"hide"`
	// Rehide are hidden socket directories that a bind of a parent brings
	// back (a recursive copy taken before Hide); they are covered again,
	// after the binds.
	Rehide []string `json:"rehide,omitempty"`
	// HideDirs are profile directories the agent sees empty (home.hide),
	// covered after the links are made. Unlike Rehide they fail closed: the
	// start fails when one is missing or a link lies on its path.
	HideDirs []string `json:"hideDirs,omitempty"`
	// Binds are mounted in order; parents come before children.
	Binds []Bind `json:"binds"`
	// Links are symbolic links recreated inside (a profile's launcher link
	// whose target is visible through another bind), made after the binds.
	Links []Link `json:"links"`
	// Devices are host device nodes under /dev bound into the private
	// /dev (null, zero, ... plus profile devices).
	Devices []string `json:"devices"`

	PTY bool `json:"pty"`

	Landlock LandlockPlan `json:"landlock"`
	Seccomp  bool         `json:"seccomp"`

	Env     []string `json:"env"`
	Argv    []string `json:"argv"`
	Workdir string   `json:"workdir"`
}

// Bind is one path made visible inside the confinement.
type Bind struct {
	Source string `json:"source"` // path outside (real path)
	Target string `json:"target"` // path inside
	RW     bool   `json:"rw"`
	Dir    bool   `json:"dir"`
	Why    string `json:"why"` // project, profile, flag, git, self, socket
	// NoFollow: no link may lie on the way to Target inside (the start
	// fails if one does); Target itself may be a link, which the mount
	// covers instead of following (a protected path that is a link).
	NoFollow bool `json:"noFollow,omitempty"`
}

// LandlockPlan lists the file hierarchies the agent gets, by kind.
type LandlockPlan struct {
	RO      []string `json:"ro"`      // read and execute
	RW      []string `json:"rw"`      // read, write, execute, create, remove, rename across dirs
	Dev     []string `json:"dev"`     // read, write and ioctl on devices
	Sockets []string `json:"sockets"` // pathname Unix sockets the agent may connect to (ABI 9)
	// NoScopesOK lets the exec stage go on when the kernel cannot scope
	// abstract sockets and signals (ABI < 6); the launcher sets it only
	// after its own check or the person's explicit override.
	NoScopesOK bool `json:"noScopesOK"`
	// NoLandlockOK lets the exec stage go on without Landlock at all (ABI
	// 0); the launcher sets it only on the person's explicit
	// --allow-no-landlock (review COT-4).
	NoLandlockOK bool `json:"noLandlockOK,omitempty"`
}

// landlockGate decides, from the kernel's Landlock ABI, whether the
// launcher may start the agent: without Landlock (ABI 0) only when the
// person accepted that explicitly (review COT-4: the agent used to start
// without it, still reported confined).
func landlockGate(abi int, allowNone bool) error {
	if abi > 0 || allowNone {
		return nil
	}
	return errNoLandlock
}

// landlockApplied decides, in the exec stage, whether a failed
// ApplyLandlock stops the start: always, unless the kernel has no
// Landlock and the launcher accepted that (NoLandlockOK).
func landlockApplied(abi int, err error, noLandlockOK bool) error {
	if err == nil || (abi == 0 && noLandlockOK) {
		return nil
	}
	return err
}

// Link is a symbolic link recreated inside the confinement.
type Link struct {
	Path   string `json:"path"`   // where the link is
	Target string `json:"target"` // its content, as read outside
}
