package confine

import (
	"errors"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// LandlockABI returns the Landlock ABI the kernel supports: 0 when
// Landlock is absent or disabled at boot.
func LandlockABI() int {
	v, err := llsys.LandlockGetABIVersion()
	if err != nil {
		return 0
	}
	return v
}

// Access right groups, as raw bits so they read like the kernel header.
const (
	llExec       = llsys.AccessFSExecute
	llReadFile   = llsys.AccessFSReadFile
	llReadDir    = llsys.AccessFSReadDir
	llWriteFile  = llsys.AccessFSWriteFile
	llTruncate   = llsys.AccessFSTruncate
	llIoctlDev   = llsys.AccessFSIoctlDev
	llRefer      = llsys.AccessFSRefer
	llResolveUnx = llsys.AccessFSResolveUnix

	llRead  = llExec | llReadFile | llReadDir
	llWrite = llsys.AccessFSWriteFile | llsys.AccessFSRemoveDir | llsys.AccessFSRemoveFile |
		llsys.AccessFSMakeChar | llsys.AccessFSMakeDir | llsys.AccessFSMakeReg |
		llsys.AccessFSMakeSock | llsys.AccessFSMakeFifo | llsys.AccessFSMakeBlock |
		llsys.AccessFSMakeSym | llRefer | llTruncate

	// llHandled is every filesystem right up to ABI 9. Network rights stay
	// unhandled: the network is open in cotty v1.
	llHandled = llRead | llWrite | llIoctlDev | llResolveUnx

	llScopes = llsys.ScopeAbstractUnixSocket | llsys.ScopeSignal
)

// ApplyLandlock restricts the calling process (all threads) to the plan,
// with the best ABI the kernel offers. It returns the ABI used.
func ApplyLandlock(plan LandlockPlan) (int, error) {
	abi := LandlockABI()
	if abi == 0 {
		return 0, errors.New("landlock is not available")
	}
	cfg, err := landlock.NewConfig(landlock.AccessFSSet(llHandled), landlock.ScopedSet(llScopes))
	if err != nil {
		return abi, err
	}
	var rules []landlock.Rule
	supported := llSupportedFS(abi)
	add := func(access uint64, paths []string) {
		// Rights the kernel does not know are dropped here, so a rule never
		// ends up empty (an error) or asks for "refer" on ABI 1 (which
		// would make go-landlock give up on Landlock altogether).
		access &= supported
		for _, p := range paths {
			var st unix.Stat_t
			if unix.Stat(p, &st) != nil {
				continue // missing: nothing to grant
			}
			a := access
			if st.Mode&unix.S_IFMT != unix.S_IFDIR {
				// Directory rights cannot be granted on a file.
				a &= llFileRights
			}
			if a != 0 {
				rules = append(rules, landlock.PathAccess(landlock.AccessFSSet(a), p))
			}
		}
	}
	add(llRead, plan.RO)
	add(llRead|llWrite, plan.RW)
	add(llRead|llWriteFile|llTruncate|llIoctlDev, plan.Dev)
	add(llResolveUnx, plan.Sockets)
	return abi, cfg.BestEffort().Restrict(rules...)
}

// llSupportedFS returns the filesystem rights Landlock ABI abi knows.
func llSupportedFS(abi int) uint64 {
	var s uint64
	if abi >= 1 {
		s = llRead | llsys.AccessFSWriteFile | llsys.AccessFSRemoveDir | llsys.AccessFSRemoveFile |
			llsys.AccessFSMakeChar | llsys.AccessFSMakeDir | llsys.AccessFSMakeReg |
			llsys.AccessFSMakeSock | llsys.AccessFSMakeFifo | llsys.AccessFSMakeBlock | llsys.AccessFSMakeSym
	}
	if abi >= 2 {
		s |= llRefer
	}
	if abi >= 3 {
		s |= llTruncate
	}
	if abi >= 5 {
		s |= llIoctlDev
	}
	if abi >= 9 {
		s |= llResolveUnx
	}
	return s
}

// llFileRights are the rights that apply to a file that is not a
// directory (the kernel's ACCESS_FILE, plus resolving a socket).
const llFileRights = llExec | llReadFile | llWriteFile | llTruncate | llIoctlDev | llResolveUnx

// setNoNewPrivs sets no_new_privs on the calling thread; the Landlock call
// sets it on every thread as well.
func setNoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}
