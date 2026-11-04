//go:build linux && (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64)

package daemon

import (
	"testing"

	"github.com/cilium/ebpf"
)

// The committed object parses, every program is an LSM program on a hook
// CheckHooks knows, and every map is pinned by name (so a restart keeps
// the tags). Only the ELF is read: nothing is loaded into the kernel.
func TestEmbeddedObject(t *testing.T) {
	spec, err := loadGuardbpf()
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, u := range usedArgs {
		known[u.hook] = true
	}
	seen := map[string]bool{}
	for name, p := range spec.Programs {
		if p.Type != ebpf.LSM {
			t.Errorf("%s: type %s, want LSM", name, p.Type)
		}
		if !known[p.AttachTo] {
			t.Errorf("%s: hook %q is not checked by CheckHooks", name, p.AttachTo)
		}
		seen[p.AttachTo] = true
	}
	for h := range known {
		if !seen[h] {
			t.Errorf("CheckHooks lists %s, which no program uses", h)
		}
	}
	for name, m := range spec.Maps {
		if name == ".bss" || name == ".data" || name == ".rodata" {
			continue
		}
		if m.Pinning != ebpf.PinByName {
			t.Errorf("map %s is not pinned by name", name)
		}
	}
}
