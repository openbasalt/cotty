#!/usr/bin/env bash
# The guard's pts exception list (docs/guard.md, The pts exception list).
# Run it with cotty-guard loaded, as an unprivileged user with
# passwordless sudo, in a throwaway VM (never on a machine you care
# about): it rewrites /etc/cotty/guard-exceptions.conf and restores it.
#
# A root-owned copy of the probe stands in for pinentry-curses
# (fake-pinentry: opens the session pts by name, echo off, reads a line).
# A shared session with a scripted person attached types the secret when
# the lock lights.
#
#   exc-listed-*      the listed executable, started outside the session
#                     and outside any agent, opens the pts; the lock names
#                     it "(exception, for PARENT)"; it gets the person's keys, the
#                     agent does not; the guard logs and audits the use
#   exc-unlisted      the same program at a path that is not listed
#   exc-copy-*        a copy of the listed file (root's or the user's)
#   exc-symlink       a symbolic link to the listed file: the same file
#                     runs, so it passes (the documented semantics: the
#                     guard matches the file, not the path)
#   exc-agent-*       the listed executable started by an agent (a
#                     registered agent cgroup, a descendant in a new
#                     session, a self-tagged launcher)
#   exc-traced        the listed executable under a tracer
#   exc-config-*      a list writable by group or owned by the user is
#                     refused whole; an empty or absent list allows nothing
#   exc-daemon-*      the list lives with the daemon: stopped cleanly, the
#                     listed executable is refused; started again, allowed;
#                     killed (no clean stop), allowed until the heartbeat
#                     is 90 s old, refused after
#
# The lock names the listed program's parent ("exception, for bash": the
# test script started it).
#
# Rows: PASS, FAIL, SKIP. Exit 1 on FAIL.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
COTTY=${COTTY:-/usr/local/bin/cotty}
PROBE=${PROBE:-$HERE/../../bin/probe}
GUARDPROBE=${GUARDPROBE:-$HERE/../../bin/guardprobe}
for b in "$COTTY" "$PROBE" "$GUARDPROBE"; do [ -x "$b" ] || { echo "missing $b" >&2; exit 2; }; done
RT=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
STATE=${XDG_STATE_HOME:-$HOME/.local/state}/cotty
W=$HOME/cotty-gexc/$(date +%Y%m%d-%H%M%S)
mkdir -p "$W"
chmod 700 "$W"
SECRET=COTTY-EXCSECRET-$RANDOM$RANDOM$RANDOM
(umask 077 && echo "$SECRET" >"$W/secret")
# shellcheck source=tests/attacks/session-lib.sh
. "$HERE/session-lib.sh"
[ "$GUARD_STATE" = loaded ] || { echo "guard-exceptions.sh: cotty-guard is not loaded" >&2; exit 2; }
sudo -n true || { echo "guard-exceptions.sh: needs passwordless sudo" >&2; exit 2; }

LIB=/usr/libexec/cotty-lab
OPENER=$LIB/fake-pinentry
sudo -n install -d -o root -g root -m 0755 "$LIB"
sudo -n install -o root -g root -m 0755 "$PROBE" "$OPENER"
sudo -n install -o root -g root -m 0755 "$PROBE" "$LIB/fake-pinentry-copy"
cp "$PROBE" "$W/fake-pinentry"
ln -s "$OPENER" "$W/fake-pinentry-link"
START=$(date -u +%Y-%m-%dT%H:%M:%S)
JSTART=$(date '+%Y-%m-%d %H:%M:%S')
exc_save
cleanup() {
	stop_sessions
	exc_restore
	sudo -n rm -rf "$LIB"
}
trap cleanup EXIT

start_session gx$RANDOM
# The session's foreground job waits, as git does while gpg asks: only the
# program outside reads the terminal (the shell's line editor would
# compete for the keys).
"$PROBE" agent-type "$ASOCK" "sleep 900" >/dev/null
sleep 1

# open_row NAME WANT CMD...: CMD opens the session pts (fake-pinentry,
# outside the session); WANT is allow or deny.
open_row() {
	local name=$1 want=$2
	shift 2
	if [ "$want" = allow ]; then allow "$name" "$@"; else deny "$name" "$@"; fi
}

exc_set "$OPENER"
check exc-status-lists "the guard lists $OPENER" exc_listed "$OPENER"

# --- the listed executable, outside the session ---
n=$(locks)
"$PROBE" agent-events "$ASOCK" 12 >"$W/events" 2>&1 &
ev=$!
sleep 1
"$OPENER" fake-pinentry "$PTS" 20 "$W/read" >"$W/opener.out" 2>&1 &
op=$!
LOCK=$(lock_after "$n" 15)
# The agent tries to type while the lock is lit.
"$PROBE" agent-type "$ASOCK" "echo agent-typed-during-lock" >"$W/agent-type.out" 2>&1
atrc=$?
wait $op
orc=$?
wait $ev
evrc=$?
if [ $orc -eq 0 ]; then
	row PASS exc-listed-opens "$(tr '\n' ' ' <"$W/opener.out" | cut -c1-100)"
else
	row FAIL exc-listed-opens "the listed executable was refused: $(tr '\n' ' ' <"$W/opener.out" | cut -c1-100)"
fi
case $LOCK in
*"fake-pinentry (exception, for bash)"*) row PASS exc-listed-lock "lock: $LOCK" ;;
*) row FAIL exc-listed-lock "lock \"$LOCK\", want fake-pinentry (exception, for bash)" ;;
esac
if [ "$(cat "$W/read" 2>/dev/null)" = "$SECRET" ]; then
	row PASS exc-listed-gets-keys "the program read the person's secret"
else
	row FAIL exc-listed-gets-keys "the program read \"$(head -c 40 "$W/read" 2>/dev/null)\""
fi
if [ $atrc -ne 0 ] && grep -qi 'secret' "$W/agent-type.out"; then
	row PASS exc-listed-agent-input-refused "$(tr '\n' ' ' <"$W/agent-type.out" | cut -c1-100)"
else
	row FAIL exc-listed-agent-input-refused "agent input during the lock: exit $atrc $(tr '\n' ' ' <"$W/agent-type.out" | cut -c1-100)"
fi
case $evrc in
1) row PASS exc-listed-agent-frozen "$(tr '\n' ' ' <"$W/events" | cut -c1-100)" ;;
0) row FAIL exc-listed-agent-frozen "the agent saw the prompt key by key: $(tr '\n' ' ' <"$W/events" | cut -c1-100)" ;;
*) row FAIL exc-listed-agent-frozen "agents never saw a secret prompt: $(tr '\n' ' ' <"$W/events" | cut -c1-100)" ;;
esac
deny exc-listed-agent-reads-secret "$PROBE" agent-read "$ASOCK" "$SECRET"
sleep 1
if sudo -n journalctl -u cotty-guard --since "$JSTART" --no-pager 2>/dev/null | grep -q "exception used: .*$OPENER"; then
	row PASS exc-listed-logged "$(sudo -n journalctl -u cotty-guard --since "$JSTART" --no-pager | grep -m1 'exception used' | sed 's/.*cotty-guard: //' | cut -c1-120)"
else
	row FAIL exc-listed-logged "no 'exception used' line in the guard's journal"
fi
if sudo -n cat /var/log/cotty/guard.audit.jsonl 2>/dev/null | awk -v s="$START" -F'"time":"' '{ split($2, a, "\""); if (a[1] >= s) print }' | grep '"guard.exception"' | grep -q "$OPENER"; then
	row PASS exc-listed-audited "guard.exception record with $OPENER"
else
	row FAIL exc-listed-audited "no guard.exception record for $OPENER"
fi
check exc-listed-session-audit "the session audit log marks the prompt as an exception" grep -q '"exception":true' "$STATE/audit.jsonl"

# --- other files, other paths ---
open_row exc-unlisted deny "$PROBE" fake-pinentry "$PTS" 2
open_row exc-copy-user deny "$W/fake-pinentry" fake-pinentry "$PTS" 2
open_row exc-copy-root deny "$LIB/fake-pinentry-copy" fake-pinentry "$PTS" 2
# Same file through a link: allowed by design (the kernel runs the listed
# file; the person types the secret again at its lock).
open_row exc-symlink allow "$W/fake-pinentry-link" fake-pinentry "$PTS" 3

# --- started by an agent ---
UNIT=cotty-agent-exc$$
open_row exc-agent-registered deny systemd-run --user --scope --quiet --collect --unit="${UNIT}a" -- \
	"$GUARDPROBE" run-registered -- "$OPENER" fake-pinentry "$PTS" 2
open_row exc-agent-descendant deny systemd-run --user --scope --quiet --collect --unit="${UNIT}b" -- \
	"$GUARDPROBE" run-registered -- bash -c "sleep 0.1; setsid $OPENER fake-pinentry $PTS 2"
# Outside an agent cgroup the launcher tags itself (and its children).
open_row exc-agent-tag-self deny "$GUARDPROBE" run-registered -- "$OPENER" fake-pinentry "$PTS" 2

# --- under a tracer ---
if command -v strace >/dev/null; then
	open_row exc-traced deny strace -f -o /dev/null "$OPENER" fake-pinentry "$PTS" 2
else
	row SKIP exc-traced "strace is not installed"
fi

# --- the list itself ---
sudo -n chmod 0664 "$EXC"
exc_reload
open_row exc-config-group-writable deny "$OPENER" fake-pinentry "$PTS" 2
if sudo -n journalctl -u cotty-guard --since "$JSTART" --no-pager 2>/dev/null | grep -q "refusing $EXC: mode 0664"; then
	row PASS exc-config-refusal-logged "$(sudo -n journalctl -u cotty-guard --since "$JSTART" --no-pager | grep -m1 "refusing $EXC" | sed 's/.*cotty-guard: //' | cut -c1-120)"
else
	row FAIL exc-config-refusal-logged "no refusal line for a group-writable list"
fi
sudo -n chmod 0644 "$EXC"
sudo -n chown "$(id -u)" "$EXC"
exc_reload
open_row exc-config-user-owned deny "$OPENER" fake-pinentry "$PTS" 2
exc_set "# nothing listed"
open_row exc-config-empty deny "$OPENER" fake-pinentry "$PTS" 2
sudo -n rm -f "$EXC"
exc_reload
open_row exc-config-absent deny "$OPENER" fake-pinentry "$PTS" 2
# Listed again: allowed again (the reload takes the list back).
exc_set "$OPENER"
open_row exc-config-reloaded allow "$OPENER" fake-pinentry "$PTS" 3

# --- the daemon goes away ---
# guard_up: wait until the daemon answers and lists the opener again.
guard_up() {
	local i
	for i in $(seq 100); do exc_listed "$OPENER" && return 0; sleep 0.2; done
	return 1
}
if systemctl cat cotty-guard >/dev/null 2>&1; then
	sudo -n systemctl stop cotty-guard
	open_row exc-daemon-stopped deny "$OPENER" fake-pinentry "$PTS" 2
	sudo -n systemctl start cotty-guard
	if guard_up; then
		open_row exc-daemon-restarted allow "$OPENER" fake-pinentry "$PTS" 3
	else
		row FAIL exc-daemon-restarted "the daemon did not come back with the list"
	fi
	# A crash: no clean stop, so the kernel keeps the list until the
	# heartbeat is stale. stop right after the kill keeps systemd from
	# restarting it.
	sudo -n systemctl kill -s KILL cotty-guard
	sudo -n systemctl stop cotty-guard 2>/dev/null
	KILLED=$(date +%s)
	open_row exc-daemon-killed-fresh allow "$OPENER" fake-pinentry "$PTS" 2
	sleep $((92 - ($(date +%s) - KILLED)))
	open_row exc-daemon-killed-stale deny "$OPENER" fake-pinentry "$PTS" 2
	sudo -n systemctl reset-failed cotty-guard 2>/dev/null
	sudo -n systemctl start cotty-guard
	if guard_up; then
		open_row exc-daemon-killed-restarted allow "$OPENER" fake-pinentry "$PTS" 3
	else
		row FAIL exc-daemon-killed-restarted "the daemon did not come back with the list"
	fi
else
	row SKIP exc-daemon "cotty-guard does not run as a systemd unit"
fi

summary "guard pts exception list"
