// Package guard is cotty's layer 3 (docs/PLAN.md section 4, docs/guard.md):
// BPF LSM programs (bpf/guard.bpf.c) loaded by the root daemon
// cotty-guard, the daemon itself, and the client used by `cotty agent`
// (register the agent's cgroup before it starts), the broker (a peer's
// tag, through the peer.Guard interface) and `cotty doctor`.
//
// Unprivileged processes talk to the daemon over a Unix seqpacket socket
// (SocketPath). Every request can only add restrictions: register the
// caller's own cgroup as an agent, tag the caller itself, protect a
// terminal the caller owns. Nothing removes a tag. Queries (status, the
// tag of a pid, whether a terminal is still protected) are answered from
// the kernel's maps, so the answer never depends on anything the agent can
// write. The maps and the programs stay pinned when the daemon stops, so
// a restart or an upgrade keeps every tag, registration and protection;
// only `cotty-guard uninstall` removes them.
package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Paths used by the daemon.
const (
	// SocketDir is root-owned (0755); the socket in it is 0666 and every
	// request is checked against the caller's kernel credentials.
	SocketDir  = "/run/cotty-guard"
	SocketPath = SocketDir + "/guard.sock"
	// PinPath holds the pinned maps and links (bpffs, root only).
	PinPath = "/sys/fs/bpf/cotty"
	// EnforcingMarker is created by the daemon when it starts enforcing
	// and removed only by `cotty-guard uninstall`: while it exists the
	// pinned programs enforce, and the attach client refuses to trust a
	// session it cannot verify because the daemon does not answer (it
	// fails closed instead of skipping the check).
	EnforcingMarker = SocketDir + "/enforcing"
	// AuditPath is the daemon's audit log (internal/audit format).
	AuditPath = "/var/log/cotty/guard.audit.jsonl"
	// LSMFile lists the active LSMs.
	LSMFile = "/sys/kernel/security/lsm"
	// BTFFile is the kernel's own BTF, needed for CO-RE and BPF LSM.
	BTFFile = "/sys/kernel/btf/vmlinux"
	// ExceptionsPath lists the executables that may open a session pts
	// without it being their controlling terminal (docs/guard.md, The pts
	// exception list). It must be root-owned and closed to group and
	// others; absent or empty means no exception.
	ExceptionsPath = "/etc/cotty/guard-exceptions.conf"
)

// AgentCgroupPrefix is the name prefix of every cgroup the guard accepts
// as an agent cgroup (same as peer.AgentCgroupPrefix and the launcher's
// scope names).
const AgentCgroupPrefix = "cotty-agent"

// Operations of the socket protocol.
const (
	OpStatus   = "status"   // -> Status
	OpRegister = "register" // register the caller's own cgroup; fds: allowed sockets (O_PATH)
	OpTagSelf  = "tag-self" // tag the calling process
	OpTagOf    = "tag-of"   // fds: one pidfd; -> Tag
	// OpProtectPTS: fds: the pts (O_PATH is enough) and its master; the
	// caller must be a registered broker holding the master of that very
	// pts. Protected while the caller runs.
	OpProtectPTS = "protect-pts"
	OpCheckPTS   = "check-pts"   // fds: the pts; OK only when protected for the caller
	OpReleasePTS = "release-pts" // fds: the pts; the caller's protection ends
	// OpRegisterBroker: the caller (the installed cotty binary running
	// __broker) becomes the registered broker of session Name; fds: its
	// runtime directories ($XDG_RUNTIME_DIR/cotty and its agent
	// directory), where from then on only registered brokers may bind,
	// link, rename or remove. A name belongs to its first registrant
	// (pid and start time) for as long as that process runs: a second
	// broker with the same name is refused.
	OpRegisterBroker = "register-broker"
	// OpClaimSocket: fds: O_PATH descriptors of sockets the caller (the
	// registered broker of Name) bound; from then on nobody else, other
	// brokers included, may unlink, rename or replace them while the
	// caller runs.
	OpClaimSocket = "claim-socket"
	// OpVerifyBroker: fds: one connected Unix socket; OK when the process
	// that listens on its other end is the registered broker of session
	// Name of the caller's uid, running the installed cotty binary
	// (attach.BrokerVerifier).
	OpVerifyBroker = "verify-broker"
	// OpPTSException: fds: the pts (O_PATH is enough); the caller must be
	// the process that protected it. Answers the last process that opened
	// it through the exception list (Response.Exception), when that
	// process still runs.
	OpPTSException = "pts-exception"
	OpUntag        = "untag"      // always refused
	OpUnregister   = "unregister" // always refused
	maxRequest     = 64 << 10     // bytes of one request or response
	maxRequestFDs  = 64           // descriptors in one request
)

// Per-user limits of the daemon, so one user cannot fill the kernel maps
// (16384 entries each) and block everybody else's agents and sessions.
const (
	MaxAgentsPerUser      = 1024
	MaxProtectionsPerUser = 1024
	MaxBrokersPerUser     = 256 // registered session names (and their sockets)
	MaxConnsPerUser       = 64  // open connections to the daemon
)

// Request is one message to the daemon. File descriptors travel as
// SCM_RIGHTS with the message.
type Request struct {
	Op string `json:"op"`
	// Guard, for register: the last Guard descriptors are directories the
	// agent may not change (create, link, rename or remove entries, or
	// rename or remove the directory), without being allowed to connect
	// to the sockets in them (the cotty runtime directory, where the
	// person's session sockets live). The other descriptors are allowed
	// sockets or socket directories, which are guarded too.
	Guard int `json:"guard,omitempty"`
	// Name, for register-broker, claim-socket and verify-broker: the
	// session name.
	Name string `json:"name,omitempty"`
	// Slot, for claim-socket: 0 the person socket, 1 the agent socket.
	Slot int `json:"slot,omitempty"`
}

// Response is the daemon's answer.
type Response struct {
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Tag    string  `json:"tag,omitempty"`
	Status *Status `json:"status,omitempty"`
	// Skipped lists allowlist entries the daemon did not accept, with why.
	Skipped []string `json:"skipped,omitempty"`
	// Kept, for protect-pts: the terminal was already protected for the
	// caller (a protection that survived a daemon restart).
	Kept bool `json:"kept,omitempty"`
	// PID, for verify-broker: the verified listener, in the daemon's pid
	// namespace.
	PID int `json:"pid,omitempty"`
	// Exception, for pts-exception: the running process that opened the
	// pts through the exception list (nil when there is none).
	Exception *ExceptionUse `json:"exception,omitempty"`
}

// ExceptionUse is a process that opened a session pts through the
// exception list: a program outside the session (a pinentry-curses
// started by gpg-agent) that is reading the person's keys.
type ExceptionUse struct {
	PID   int    `json:"pid"`   // in the daemon's pid namespace
	Start uint64 `json:"start"` // clock ticks since boot (/proc/PID/stat field 22)
	Exe   string `json:"exe"`   // the listed path of its executable
}

// Status describes the running guard.
type Status struct {
	Loaded   bool     `json:"loaded"`
	Kernel   string   `json:"kernel"`
	LSMs     []string `json:"lsms"`
	Programs []string `json:"programs"`
	Agents   int      `json:"agents"`   // registered agent cgroups
	Ptys     int      `json:"ptys"`     // protected session terminals
	Brokers  int      `json:"brokers"`  // registered brokers
	Dropped  uint64   `json:"dropped"`  // denial events not logged (rate limit, full ring buffer)
	Pinned   string   `json:"pinned"`   // pin directory
	Audit    string   `json:"audit"`    // audit log path
	Denials  uint64   `json:"denials"`  // since the daemon started
	Since    string   `json:"since"`    // daemon start time, RFC 3339
	Version  string   `json:"version"`  // protocol version
	Warnings []string `json:"warnings"` // things the daemon could not set up
	// Exceptions are the executables that may open a session pts
	// without it being their controlling terminal (ExceptionsPath).
	Exceptions []string `json:"exceptions"`
}

// ProtocolVersion is reported in Status.Version.
const ProtocolVersion = "5"

// ErrNotRunning is returned by the client when no daemon answers.
var ErrNotRunning = errors.New("cotty-guard is not running")

// FormatTag renders an agent id as the tag string the broker sees.
func FormatTag(agent uint64) string {
	if agent == 0 {
		return ""
	}
	return "agent:" + strconv.FormatUint(agent, 10)
}

// ParseTag is the inverse of FormatTag.
func ParseTag(tag string) (uint64, error) {
	s, ok := strings.CutPrefix(tag, "agent:")
	if !ok {
		return 0, fmt.Errorf("bad tag %q", tag)
	}
	return strconv.ParseUint(s, 10, 64)
}

// KernelDev converts a stat st_dev (userspace encoding) to the kernel's
// internal dev_t (major << 20 | minor), which the BPF programs read from
// super_block.s_dev.
func KernelDev(stDev uint64) uint64 {
	return uint64(unix.Major(stDev))<<20 | uint64(unix.Minor(stDev))
}

// WriteMsg writes one JSON message with optional descriptors.
func WriteMsg(fd int, v any, fds []int) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxRequest {
		return errors.New("message too large")
	}
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	for {
		err := unix.Sendmsg(fd, b, oob, nil, 0)
		if err != unix.EINTR {
			return err
		}
		// A socket with SO_SNDTIMEO (the client's) returns EINTR when a
		// signal arrives, even with SA_RESTART (signal(7)); the Go runtime
		// sends SIGURG to preempt goroutines. A SOCK_SEQPACKET message is
		// sent whole or not at all, so sending it again is safe.
	}
}

// ReadMsg reads one JSON message and the descriptors that came with it.
// It returns ErrClosed when the peer closed.
func ReadMsg(fd int, v any) ([]int, error) {
	buf := make([]byte, maxRequest)
	oob := make([]byte, unix.CmsgSpace(4*maxRequestFDs))
	n, oobn, flags, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_CMSG_CLOEXEC)
	for err == unix.EINTR {
		// Interrupted before a message was taken (see WriteMsg): read
		// again. Each retry restarts the SO_RCVTIMEO timeout.
		n, oobn, flags, _, err = unix.Recvmsg(fd, buf, oob, unix.MSG_CMSG_CLOEXEC)
	}
	if err != nil {
		return nil, err
	}
	var fds []int
	if oobn > 0 {
		msgs, perr := unix.ParseSocketControlMessage(oob[:oobn])
		if perr == nil {
			for i := range msgs {
				if got, err := unix.ParseUnixRights(&msgs[i]); err == nil {
					fds = append(fds, got...)
				}
			}
		}
	}
	if n == 0 && oobn == 0 {
		return nil, ErrClosed
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		CloseFDs(fds)
		return nil, errors.New("message truncated")
	}
	if err := json.Unmarshal(buf[:n], v); err != nil {
		CloseFDs(fds)
		return nil, fmt.Errorf("bad message: %w", err)
	}
	return fds, nil
}

// ErrClosed is returned by ReadMsg when the peer closed the connection.
var ErrClosed = errors.New("connection closed")

// CloseFDs closes descriptors received with a message.
func CloseFDs(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}
