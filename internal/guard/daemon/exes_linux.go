//go:build linux && (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64)

package daemon

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"syscall"
)

// exeKey is a registered broker: its pid and start time.
type exeKey struct {
	Tgid  uint32 `json:"tgid"`
	Start uint64 `json:"start"`
}

// exeID is the executable a broker ran when it registered.
type exeID struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
}

type exeEntry struct {
	exeKey
	exeID
}

// exesFile is kept next to the daemon's socket, in a root-owned directory.
const exesFile = "broker-exes.json"

func (d *daemon) exesPath() string {
	return filepath.Join(filepath.Dir(d.opts.SocketPath), exesFile)
}

// knownExe returns the executable broker k registered with, if any.
func (d *daemon) knownExe(k exeKey) *exeID {
	d.mu.Lock()
	defer d.mu.Unlock()
	if id, ok := d.exes[k]; ok {
		return &id
	}
	return nil
}

// loadExes reads the record a previous run of the daemon left. Only a
// root-owned regular file closed to others is trusted; anything else
// starts empty (brokers then pass only while the installed file is the
// one they run).
func loadExes(path string) map[exeKey]exeID {
	out := map[exeKey]exeID{}
	f, err := os.OpenFile(path, os.O_RDONLY|syscallNoFollow, 0)
	if err != nil {
		return out
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 || !ownedByRoot(fi) {
		log.Printf("cotty-guard: ignoring %s (not a root-owned file closed to others)", path)
		return out
	}
	var list []exeEntry
	if err := json.NewDecoder(f).Decode(&list); err != nil {
		return out
	}
	for _, e := range list {
		out[e.exeKey] = e.exeID
	}
	return out
}

// saveExesLocked writes the record (temporary file and rename).
func (d *daemon) saveExesLocked() {
	list := make([]exeEntry, 0, len(d.exes))
	for k, v := range d.exes {
		list = append(list, exeEntry{k, v})
	}
	b, _ := json.Marshal(list)
	path := d.exesPath()
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscallNoFollow, 0o600)
	if err != nil {
		d.warn("%s: %v", path, err)
		return
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		d.warn("%s: %v %v", path, werr, cerr)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		d.warn("%s: %v", path, err)
	}
}

const syscallNoFollow = syscall.O_NOFOLLOW

func ownedByRoot(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}
