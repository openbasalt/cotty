package main

// Attacks of the second review round (docs/security.md): a forged
// listener that admits without proving a secret (N1), and a process that
// races the broker for the session pts while it is created (N2). Same
// exit codes as every attack: 0 escaped, 1 denied, 2 does not apply.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/cotty/internal/peer"
	"github.com/openbasalt/cotty/internal/proto"
	"github.com/openbasalt/cotty/internal/session"
)

func r2Command(name string, args []string) bool {
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch name {
	case "__broker":
		// Run as .../cotty __broker ...: the comm and argv a broker has.
		forgedBroker(arg(0), arg(1), atoi(arg(2)), arg(3))
	case "race-pts":
		racePTS(atoi(arg(0)), arg(1))
	default:
		return false
	}
	return true
}

// forgedBroker: cotty __broker SOCK META SECS MODE (the probe binary copied
// to a file named cotty) is a forged session listener that passes every
// consistency check of the attach client: it writes the session metadata
// with its own pid and start time, makes itself non-dumpable, runs with
// comm "cotty" and argv[1] "__broker". It admits every hello at once,
// without a challenge and without a proof, as admission MODE (approval:
// "an attached person approved"; insecure: a -dev-insecure broker). Exit 0
// (escaped) when the client went on after that admission (it sent another
// frame: keystrokes, a resize, a request), 1 when it hung up.
func forgedBroker(sock, meta string, secs int, mode string) {
	if mode == "" {
		mode = "approval"
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		skip("prctl: %v", err)
	}
	_ = os.Remove(sock)
	old := unix.Umask(0o177) // a socket of mode 0600, as a broker's
	l, err := net.Listen("unix", sock)
	unix.Umask(old)
	if err != nil {
		denied("cannot listen on %s: %v", sock, err)
	}
	defer os.Remove(sock)
	st, _ := peer.ReadStat(os.Getpid())
	name := strings.TrimSuffix(filepath.Base(sock), ".sock")
	if err := session.WriteMeta(meta, session.Meta{Name: name, BrokerPID: os.Getpid(), BrokerStart: st.StartTime,
		Created: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		denied("cannot write the session metadata %s: %v", meta, err)
	}
	defer os.Remove(meta)
	res := make(chan string, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Duration(secs) * time.Second))
				f, err := proto.ReadFrame(c)
				if err != nil || f.Type != proto.FrameJSON {
					return
				}
				var req proto.Request
				if json.Unmarshal(f.Payload, &req) != nil || req.Op != "hello" {
					return
				}
				var h proto.Hello
				_ = json.Unmarshal(req.Args, &h)
				_ = proto.WriteJSON(c, proto.Response{ID: req.ID, OK: true, Result: proto.HelloResult{V: proto.Version,
					Session: name, Role: h.Role, Assurance: proto.AssuranceStrong, BrokerPID: os.Getpid(),
					Policy: proto.PolicyAuto, Admission: mode}})
				if _, err := proto.ReadFrame(c); err != nil {
					res <- "hung up"
					return
				}
				res <- fmt.Sprintf("a %s client accepted the %q admission without any proof and went on", h.Role, mode)
			}(c)
		}
	}()
	select {
	case r := <-res:
		_ = l.Close()
		if r == "hung up" {
			denied("the client refused the admission without proof (it hung up)")
		}
		escaped("%s", r)
	case <-time.After(time.Duration(secs) * time.Second):
		_ = l.Close()
		denied("no client went on within %d s", secs)
	}
}

// racePTS: race-pts SECS OUT watches /dev/pts for SECS seconds and tries
// to open every new terminal as soon as it appears, again and again
// while it is locked (EIO), the way a process of the user would race a
// broker for its session pts (review N2). Every terminal it opened is
// written to OUT ("opened /dev/pts/N") and kept open until the end; a
// terminal that refused it is written as "refused /dev/pts/N: ERR".
// Exit 0 when it ran (the caller compares OUT with the session pts), 2
// when /dev/pts cannot be watched.
func racePTS(secs int, out string) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		skip("inotify: %v", err)
	}
	if _, err := unix.InotifyAddWatch(fd, "/dev/pts", unix.IN_CREATE); err != nil {
		skip("watch /dev/pts: %v", err)
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		skip("%v", err)
	}
	var mu sync.Mutex
	logf := func(s string, a ...any) {
		mu.Lock()
		fmt.Fprintf(f, s+"\n", a...)
		_ = f.Sync()
		mu.Unlock()
	}
	logf("ready")
	var kept []int
	try := func(p string) {
		end := time.Now().Add(3 * time.Second)
		var last error
		for time.Now().Before(end) {
			t, err := unix.Open(p, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err == nil {
				mu.Lock()
				kept = append(kept, t)
				mu.Unlock()
				logf("opened %s", p)
				return
			}
			last = err
			if err != unix.EIO {
				break
			}
		}
		logf("refused %s: %v", p, last)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil || n <= 0 {
				return
			}
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				nb := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(ev.Len)]
				name := strings.TrimRight(string(nb), "\x00")
				off += unix.SizeofInotifyEvent + int(ev.Len)
				if name != "" && name != "ptmx" {
					go try("/dev/pts/" + name)
				}
			}
		}
	}()
	time.Sleep(time.Duration(secs) * time.Second)
	logf("done")
	os.Exit(0)
}
