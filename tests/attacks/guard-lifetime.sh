#!/usr/bin/env bash
# Lifetime of the guard's protections (findings B4 and B5): a real cotty
# session's pts protection and its `strong` level across a long idle
# period, a guard restart, a stop and an uninstall, and an agent's tag
# across a restart. Run it in a throwaway VM with cotty-guard running and
# sudo (tests/lab/vm.sh guard NAME), never on a host.
#
#   IDLE=660 guard-lifetime.sh     (seconds of idle session; default 660,
#                                   more than the daemon's old 600 s
#                                   connection timeout)
#
# Rows as in the other matrices: PASS, FAIL, SKIP. Exit 1 on FAIL.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
COTTY=${COTTY:-/usr/local/bin/cotty}
PROBE=${PROBE:-$HERE/../../bin/probe}
GUARDPROBE=${GUARDPROBE:-$HERE/../../bin/guardprobe}
IDLE=${IDLE:-660}
RT=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
for b in "$COTTY" "$PROBE" "$GUARDPROBE"; do [ -x "$b" ] || { echo "missing $b" >&2; exit 2; }; done
"$GUARDPROBE" status >/dev/null || { echo "guard-lifetime.sh: cotty-guard is not running" >&2; exit 2; }
sudo -n true || { echo "guard-lifetime.sh: needs sudo (restarts the guard)" >&2; exit 2; }

W=$(mktemp -d "$HOME/cotty-lifetime.XXXXXX")
S=gl$RANDOM
ROWS=""
row() {
	ROWS+=$'\n'"$(printf '%-4s  %-34s %s' "$1" "$2" "$3")"
	printf '%-4s  %-34s %s\n' "$1" "$2" "$3"
}
deny() {
	local name=$1 out rc
	shift
	out=$(timeout 30 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-120)
	case $rc in
	0) row FAIL "$name" "ESCAPED: $out" ;;
	2) row SKIP "$name" "$out" ;;
	*) row PASS "$name" "denied: $out" ;;
	esac
}
expect() { # expect NAME DETAIL CONDITION...
	local name=$1 detail=$2
	shift 2
	if "$@"; then row PASS "$name" "$detail"; else row FAIL "$name" "not true: $detail"; fi
}
AGENT_UNIT=""
cleanup() {
	pid=$(sed -n 's/.*"broker_pid":\([0-9]*\).*/\1/p' "$RT/cotty/$S.json" 2>/dev/null)
	[ -n "$pid" ] && kill "$pid" 2>/dev/null
	[ -n "$AGENT_UNIT" ] && systemctl --user stop "$AGENT_UNIT" 2>/dev/null
	sudo -n systemctl start cotty-guard 2>/dev/null
}
trap cleanup EXIT
# start_guard starts the daemon and waits until it answers (a session
# started before that would run without it).
start_guard() {
	sudo -n systemctl start cotty-guard
	for _ in $(seq 50); do "$GUARDPROBE" status >/dev/null 2>&1 && return 0; sleep 0.2; done
	return 1
}

# assurance prints the session's level as an agent under `cotty agent`
# sees it: strong needs layer 2 and the guard's tag (review N21), so a
# guard-tagged agent without layer 2 would lower the level to confined.
assurance() {
	local out
	out=$("$COTTY" agent --quiet --profile generic --project "$W" --ro "$(dirname "$PROBE")" -- \
		sh -c '"$1" agent-state "$COTTY_AGENT_DIR/$2.sock"' sh "$PROBE" "$S" 2>/dev/null </dev/null)
	echo "$out" | sed -n 's/^session=\([a-z]*\).*/\1/p'
}
# wait_level LEVEL: the session reaches LEVEL within 15 s.
wait_level() {
	local i got=""
	for i in $(seq 15); do
		got=$(assurance)
		[ "$got" = "$1" ] && return 0
		sleep 1
	done
	echo "level $got" >&2
	return 1
}
pts_rows() { # pts_rows PHASE
	deny "$1-pts-by-path" "$PROBE" open-tty "$PTS"
	deny "$1-pts-via-proc-fd" "$PROBE" open-tty "/proc/$SHELL_PID/fd/0"
}

# Protections held by other sessions before this one (their brokers run).
PTYS0=$("$GUARDPROBE" status | sed -n 's/.* ptys=\([0-9]*\).*/\1/p')

# --- a session and a registered agent ---
out=$("$PROBE" in-pty 30 "reattach code" "$COTTY" new -d --ai --name "$S" -- bash --norc --noprofile 2>&1)
echo "$out" | grep -q 'reattach code' || { echo "cotty new failed: $out" >&2; exit 2; }
ASOCK=$RT/cotty/agent/$S.sock
BROKER=$(sed -n 's/.*"broker_pid":\([0-9]*\).*/\1/p' "$RT/cotty/$S.json")
PTS=$(sed -n 's/.*"pts":"\([^"]*\)".*/\1/p' "$RT/cotty/$S.json")
SHELL_PID=$(pgrep -P "$BROKER" | head -1)
[ -n "$PTS" ] && [ -n "$SHELL_PID" ] || { echo "no session pts or shell" >&2; exit 2; }
AGENT_UNIT=cotty-agent-life$$.scope
systemd-run --user --scope --quiet --unit="$AGENT_UNIT" -- \
	"$GUARDPROBE" run-registered --allow "$RT/cotty/agent" --guard "$RT/cotty" -- sleep 86399 >"$W/agent.log" 2>&1 &
for _ in $(seq 100); do AGENT_PID=$(pgrep -f '^sleep 86399$' | head -1); [ -n "$AGENT_PID" ] && break; sleep 0.1; done
[ -n "$AGENT_PID" ] || echo "the registered agent did not start: $(cat "$W/agent.log")"
TAG0=$("$GUARDPROBE" tag-of "$AGENT_PID")
echo "session $S: broker $BROKER, shell $SHELL_PID, pts $PTS; agent $AGENT_PID tagged $TAG0"

# --- start ---
expect start-strong "the session reports strong" wait_level strong
pts_rows start
expect start-agent-tagged "the agent is tagged ($TAG0)" test "${TAG0#agent:}" != "$TAG0"
deny start-steal-protection "$GUARDPROBE" steal-pts "$PTS"
# N2: only a registered broker may protect a pts, even one whose master it
# holds (before, any process of the user could protect any of its
# terminals, a new session's pts among them).
deny start-protect-not-broker "$GUARDPROBE" protect-pts

# --- B4: a long idle session ---
echo "idle for $IDLE s"
sleep "$IDLE"
pts_rows idle
expect idle-strong "after $IDLE s idle the session still reports strong" wait_level strong

# --- B5: a restart in the middle of the session ---
sudo -n systemctl restart cotty-guard
sleep 3
pts_rows restart
TAG1=$("$GUARDPROBE" tag-of "$AGENT_PID")
expect restart-agent-tag-kept "the agent's tag survived the restart ($TAG1)" test "$TAG1" = "$TAG0"
expect restart-strong "strong again once the restarted guard confirms the protection" wait_level strong

# --- a stopped guard: enforcement stays, the session is not strong ---
sudo -n systemctl stop cotty-guard
sleep 1
pts_rows stopped
expect stopped-not-strong "not strong while the guard does not answer" wait_level confined
sudo -n systemctl start cotty-guard
sleep 1
expect started-strong "strong again after the start" wait_level strong

# --- G3 (round 3): a package upgrade replaces the installed cotty with a
# new inode (and the package restarts the guard); the running broker,
# registered with the old inode, is still vouched for. A process that
# runs a copy of cotty somewhere else is not.
expect upgrade-before-verified "the guard vouches for the broker before the upgrade" \
	"$GUARDPROBE" verify "$RT/cotty/$S.sock" "$S"
sudo -n cp -p "$COTTY" "$COTTY.cotty-lab-new" && sudo -n mv -f "$COTTY.cotty-lab-new" "$COTTY"
expect upgrade-inode-replaced "the installed cotty is a new file now" \
	bash -c "[ \"\$(stat -c %i '$COTTY')\" != \"\$(sudo -n stat -L -c %i /proc/$BROKER/exe 2>/dev/null)\" ]"
expect upgrade-running-verified "the running broker is vouched for after the replacement" \
	"$GUARDPROBE" verify "$RT/cotty/$S.sock" "$S"
sudo -n systemctl restart cotty-guard
start_guard
expect upgrade-restart-verified "and after the guard restarted (the record is kept)" \
	"$GUARDPROBE" verify "$RT/cotty/$S.sock" "$S"
expect upgrade-restart-strong "the session is strong again after the restart" wait_level strong

# --- uninstall: the protection lapsed; never strong again ---
sudo -n systemctl stop cotty-guard
sudo -n cotty-guard uninstall
sudo -n systemctl start cotty-guard
sleep 4
expect uninstall-not-strong "after the protection lapsed the session stays below strong" wait_level confined
sleep 3
pts_rows reprotected
expect uninstall-still-not-strong "still below strong after the session protected its pts again" test "$(assurance)" != strong

# --- the protection ends with the broker ---
kill "$BROKER"
sleep 2
expect broker-gone-released "the session's protection is gone once its broker exited (back to $PTYS0, within the 30 s sweep)" \
	bash -c "for i in \$(seq 40); do n=\$('$GUARDPROBE' status | sed -n 's/.* ptys=\([0-9]*\).*/\1/p'); [ \"\$n\" -le ${PTYS0:-0} ] && exit 0; sleep 1; done; exit 1"

# --- N9: an upgrade whose pinned maps have another layout ---
# The guard stops, a pinned map is swapped for one as another build would
# have made it, the guard starts: a map that only grew is migrated with
# its entries; one whose value changed refuses the start and leaves the
# old programs enforcing (before, both wiped every pin: fail open).
PIN=/sys/fs/bpf/cotty
if command -v bpftool >/dev/null && sudo -n bpftool version >/dev/null 2>&1 && command -v python3 >/dev/null; then
	# remake MAP KEYSIZE VALUESIZE ENTRIES: replace the pinned MAP by a hash
	# of that layout holding the old entries that fit.
	remake() {
		# Made next to the pin directory, then moved in (a rename within
		# bpffs): creating a pin in the daemon's directory is refused.
		sudo -n bpftool map create "/sys/fs/bpf/cotty-lab-$1" type hash key "$2" value "$3" entries "$4" name "$1" || return 1
		sudo -n bpftool -j map dump pinned "$PIN/$1" | python3 -c '
import json, sys
ks, vs = int(sys.argv[1]), int(sys.argv[2])
for e in json.load(sys.stdin):
    k = [int(x, 16) for x in e["key"]][:ks]
    v = ([int(x, 16) for x in e["value"]] + [0] * vs)[:vs]
    print(" ".join("%d" % b for b in k) + "|" + " ".join("%d" % b for b in v))
' "$2" "$3" | while IFS='|' read -r k v; do
			sudo -n bpftool map update pinned "/sys/fs/bpf/cotty-lab-$1" key $k value $v
		done
		sudo -n mv "/sys/fs/bpf/cotty-lab-$1" "$PIN/$1"
	}
	entries() { sudo -n bpftool -j map show pinned "$PIN/$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["max_entries"])'; }
	count() { sudo -n bpftool -j map dump pinned "$PIN/$1" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))'; }
	sudo -n systemctl stop cotty-guard
	n0=$(count allowed_socks)
	remake allowed_socks 24 1 4096
	start_guard
	expect upgrade-map-migrated "allowed_socks of an older size migrated (entries $n0 -> $(count allowed_socks), size $(entries allowed_socks))" \
		bash -c "[ \"\$(sudo -n bpftool -j map show pinned $PIN/allowed_socks | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"max_entries\"])')\" = 16384 ] && systemctl is-active -q cotty-guard"
	sudo -n systemctl stop cotty-guard
	remake brokers 4 4 16384
	sudo -n systemctl reset-failed cotty-guard 2>/dev/null
	sudo -n systemctl start cotty-guard
	sleep 3
	expect upgrade-incompatible-refused "a pinned map with another value layout refuses the start" bash -c '! systemctl is-active -q cotty-guard'
	expect upgrade-incompatible-keeps-enforcing "the old programs stay attached (pinned links kept)" sudo -n test -e "$PIN/link_cotty_file_open"
	sudo -n systemctl stop cotty-guard
	sudo -n systemctl reset-failed cotty-guard 2>/dev/null
	sudo -n cotty-guard uninstall >/dev/null
	start_guard
else
	row SKIP upgrade-map-migrated "no bpftool or python3 (or no sudo for it)"
fi

echo
echo "guard lifetime matrix, $(uname -r), $(. /etc/os-release && echo "$PRETTY_NAME"), idle $IDLE s"
PASS=$(echo "$ROWS" | grep -c '^PASS')
FAIL=$(echo "$ROWS" | grep -c '^FAIL')
SKIP=$(echo "$ROWS" | grep -c '^SKIP')
echo "summary: $PASS pass, $FAIL fail, $SKIP skip"
rm -rf "$W"
[ "$FAIL" -eq 0 ]
