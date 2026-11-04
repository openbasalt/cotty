package guard

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Facts is what the kernel offers for the guard, read without loading
// anything (safe for `cotty doctor` as any user).
type Facts struct {
	Kernel     string   `json:"kernel"`
	LSMs       []string `json:"lsms"`       // active LSMs, in order; nil when unreadable
	BPFLSM     bool     `json:"bpf_lsm"`    // "bpf" is in the active list
	BTF        bool     `json:"btf"`        // /sys/kernel/btf/vmlinux exists
	LSMKnown   bool     `json:"lsm_known"`  // the active list could be read
	Explain    string   `json:"explain"`    // one sentence for doctor
	BootParam  string   `json:"boot_param"` // the lsm= value that would add bpf, when missing
	SecurityFS bool     `json:"securityfs"` // /sys/kernel/security is mounted
}

// ReadFacts inspects the running kernel.
func ReadFacts() Facts {
	f := Facts{}
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		f.Kernel = unix.ByteSliceToString(u.Release[:])
	}
	if b, err := os.ReadFile(LSMFile); err == nil {
		f.LSMKnown = true
		f.SecurityFS = true
		for _, l := range strings.Split(strings.TrimSpace(string(b)), ",") {
			if l != "" {
				f.LSMs = append(f.LSMs, l)
				if l == "bpf" {
					f.BPFLSM = true
				}
			}
		}
	} else if _, err := os.Stat("/sys/kernel/security"); err == nil {
		f.SecurityFS = true
	}
	if _, err := os.Stat(BTFFile); err == nil {
		f.BTF = true
	}
	switch {
	case !f.LSMKnown:
		f.Explain = "the active LSM list (" + LSMFile + ") cannot be read; the guard needs securityfs and the bpf LSM"
	case !f.BPFLSM:
		f.BootParam = "lsm=" + strings.Join(append(withoutCapability(f.LSMs), "bpf"), ",")
		f.Explain = "the bpf LSM is not active, so cotty-guard cannot enforce anything; add it to the kernel command line: " + f.BootParam
	case !f.BTF:
		f.Explain = "the kernel has no BTF (" + BTFFile + "); the guard's programs need it (CONFIG_DEBUG_INFO_BTF)"
	default:
		f.Explain = "the bpf LSM is active and the kernel has BTF: cotty-guard can run"
	}
	return f
}

// withoutCapability drops "capability", which is always first and is not
// named in lsm= (the kernel adds it by itself).
func withoutCapability(l []string) []string {
	var out []string
	for _, s := range l {
		if s != "capability" {
			out = append(out, s)
		}
	}
	return out
}
