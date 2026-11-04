#!/usr/bin/env bash
# Extra escape rows for cotty-guard (layer 3), run after inside.sh by
# tests/attacks/guard.sh, as the agent. Same row format as inside.sh.
set -u
# shellcheck disable=SC1090
. "$1"
cd "$PROJECT" || exit 1
GP=$(dirname "$PROBE")/guardprobe

# OPEN: the review item of the next row. Only in guard-only mode is a
# failure the guard's (in none every row is expected to fail, in layer2
# and both layer 2 answers first).
OPEN=""
row() {
	local d=$3
	[ "$1" = FAIL ] && [ -n "$OPEN" ] && [ "${GUARD_MODE:-}" = guard-only ] && d="[open: $OPEN] $d"
	OPEN=""
	printf '%-4s  %-26s %s\n' "$1" "$2" "$d"
}
known_open() { OPEN=$1; }
deny() {
	local name=$1 out rc
	shift
	out=$(timeout -s KILL 20 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-110)
	case $rc in
	0) row FAIL "$name" "ESCAPED: $out" ;;
	2) row SKIP "$name" "$out" ;;
	127) row SKIP "$name" "command not found, nothing tried: $out" ;;
	*) row PASS "$name" "denied: $out" ;;
	esac
}

# The guard's own socket: an agent can neither drop its tag nor register.
# Only meaningful with the guard running: in none and layer2 the socket
# is absent and a refused connect proves nothing. register-again runs
# last (below): when it succeeds it registers the agent's cgroup, and
# every later row would then run under the guard.
case ${GUARD_MODE:-} in
none | layer2) row SKIP guard-untag "the guard is not running in mode $GUARD_MODE" ;;
*) deny guard-untag "$GP" untag ;;
esac

# A cotty session's pts, protected by its broker through the guard (by
# inode, so it holds even where /dev/pts is the host's). Without a session
# (modes none and layer2) the person's pts stands in, unprotected.
SPTS=${SESSION_PTS:-$PERSON_PTS}
SDEV=${SESSION_PTS_DEV:-${PERSON_PTS_DEV:-x}}
SHOLDER=${SESSION_SHELL_PID:-${PTS_HOLDER_PID:-0}}
if [ "$(stat -c %d "$SPTS" 2>/dev/null)" != "$SDEV" ]; then
	# Same name, other devpts instance (layer 2): it is the agent's own pts.
	row PASS guard-session-pts "the session pts is not visible (private devpts instance)"
else
	# Opened for writing only: a read would block on a terminal. Without
	# a protection (mode none) this is the baseline: it opens.
	deny guard-session-pts "$PROBE" open-write "$SPTS"
fi
# S22: the same pts taken from the process that holds it with
# pidfd_getfd(2), which does not go through file_open.
known_open S22
deny guard-pts-pidfd-getfd "$PROBE" pidfd-getfd "$SHOLDER" "$SPTS"
# Moving out of the agent's cgroup through its own (user-owned) scope.
OWN_CG=$(sed -n 's/^0:://p' /proc/self/cgroup)
# (bash: a failed redirection exits 1, where dash exits 2, the skip code.)
deny guard-cgroup-own-procs bash -c "echo \$\$ >'/sys/fs/cgroup$OWN_CG/cgroup.procs'"
deny guard-cgroup-parent-procs bash -c "echo \$\$ >'/sys/fs/cgroup$OWN_CG/../cgroup.procs'"

# An exec that gains file capabilities (newuidmap carries cap_setuid on
# most distributions). Denied by the guard (exec fails with EPERM) or
# harmless under no_new_privs (it runs, without the capabilities).
FCAP=""
for f in /usr/bin/newuidmap /usr/bin/newgidmap /usr/sbin/mtr-packet /usr/bin/ping; do
	if [ -x "$f" ] && command -v getcap >/dev/null && [ -n "$(getcap "$f" 2>/dev/null)" ]; then
		FCAP=$f
		break
	fi
done
if [ -z "$FCAP" ]; then
	row SKIP guard-filecap-exec "no file capability binary found"
else
	out=$(sh -c "exec '$FCAP' 2>&1" 2>&1)
	rc=$?
	nnp=$(sed -n 's/^NoNewPrivs:\t*//p' /proc/self/status)
	if [ $rc -eq 126 ] || echo "$out" | grep -q 'Operation not permitted'; then
		row PASS guard-filecap-exec "exec of $FCAP refused: $(echo "$out" | head -1 | cut -c1-80)"
	elif [ "$nnp" = 1 ]; then
		row PASS guard-filecap-exec "$FCAP ran without its capabilities (no_new_privs)"
	else
		row FAIL guard-filecap-exec "ESCAPED: $FCAP ran with file capabilities (exit $rc)"
	fi
fi

# Reading the person's processes through /proc while visible (guard-only
# mode shares the host's /proc): every person process, not only one.
leaked=0
for d in /proc/[0-9]*; do
	[ -O "$d" ] || continue
	if head -c1 "$d/environ" >/dev/null 2>&1; then
		# The agent's own processes are in its cgroup or below (with layer
		# 2 the cgroup namespace shows that cgroup as "/").
		cg=$(sed -n 's/^0:://p' "$d/cgroup" 2>/dev/null)
		case $cg in "$OWN_CG" | "${OWN_CG%/}"/*) ;; *) leaked=$((leaked + 1)) ;; esac
	fi
done
if [ $leaked -eq 0 ]; then
	row PASS guard-proc-environ-all "no environ of a process outside the agent was readable"
else
	row FAIL guard-proc-environ-all "ESCAPED: $leaked environ files outside the agent were readable"
fi
# --- rows added after the final review: escapes around the guard's
# cgroup, signal and socket rules (VICTIM_CG, VICTIM_PID and
# RENAME_SOCK come from guard.sh; all are processes of the person) ---
if [ -n "${VICTIM_CG:-}" ]; then
	# S20: a child started directly in another cgroup of the user.
	known_open S20
	deny guard-clone-into-cgroup "$PROBE" clone-into-cgroup "$VICTIM_CG"
	# S21: freezing or killing a cgroup of the person (a broker's) without
	# a signal. (bash: a failed redirection exits 1; dash exits 2, which
	# deny reads as skip.)
	known_open S21
	deny guard-cgroup-freeze bash -c "echo 1 >'$VICTIM_CG/cgroup.freeze' && echo 0 >'$VICTIM_CG/cgroup.freeze' && echo froze and thawed $VICTIM_CG"
	known_open S21
	deny guard-cgroup-kill bash -c "echo 1 >'$VICTIM_CG/cgroup.kill' && echo killed every process in $VICTIM_CG"
else
	row SKIP guard-clone-into-cgroup "no victim cgroup"
fi
if [ -n "${VICTIM_PID:-}" ]; then
	# S21: rlimits and SIGIO reach a process of the person without kill(2).
	known_open S21
	deny guard-prlimit-outside "$PROBE" prlimit "$VICTIM_PID"
	known_open S21
	deny guard-sigio-kill "$PROBE" sigio "$VICTIM_PID"
fi
if [ -n "${RENAME_SOCK:-}" ]; then
	# S19: a socket of the person renamed into the agent's allowed
	# directory (same tmpfs) passes the directory allowlist.
	known_open S19
	deny guard-socket-rename-allowed bash -c "d='${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/cotty'; mv '$RENAME_SOCK' \"\$d/lab-renamed.sock\" || exit 1; '$PROBE' connect \"\$d/lab-renamed.sock\"; rc=\$?; mv \"\$d/lab-renamed.sock\" '$RENAME_SOCK'; exit \$rc"
fi

if [ -n "${VICTIM_PID:-}" ]; then
	# Priorities of a process of the person (set to the current value).
	deny guard-setnice-outside "$PROBE" setnice "$VICTIM_PID"
fi

# The cotty runtime directory and the agent endpoint directory (guarded
# for agents, the guard rule for B3): no socket planted, linked or
# symlinked there (a fake session `cotty attach` would pick), and the
# runtime directory cannot be renamed away.
RTI=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
if [ -z "${NO_LAYER2:-}" ]; then
	row PASS guard-plant-in-cotty-dir "the cotty runtime directory is not visible (private runtime directory, layer 2)"
elif [ ! -d "$RTI/cotty/agent" ]; then
	row SKIP guard-plant-in-cotty-dir "no $RTI/cotty/agent"
else
	deny guard-bind-in-cotty-dir "$PROBE" bind-in "$RTI/cotty"
	deny guard-bind-in-agent-dir "$PROBE" bind-in "$RTI/cotty/agent"
	own=$RTI/cotty-guard-own-$$
	: >"$own"
	deny guard-link-into-agent-dir bash -c "ln '$own' '$RTI/cotty/agent/linked.sock' && rm -f '$RTI/cotty/agent/linked.sock'"
	deny guard-symlink-into-cotty-dir bash -c "ln -s '$own' '$RTI/cotty/99.sock' && rm -f '$RTI/cotty/99.sock'"
	deny guard-rename-cotty-dir bash -c "mv '$RTI/cotty' '$RTI/cotty.moved' && mv '$RTI/cotty.moved' '$RTI/cotty'"
	rm -f "$own"
fi

# Last: it registers the cgroup when it succeeds.
case ${GUARD_MODE:-} in
none | layer2) row SKIP guard-register-again "the guard is not running in mode $GUARD_MODE" ;;
*) deny guard-register-again "$GP" register-again ;;
esac
echo "DONE guard-inside.sh"
