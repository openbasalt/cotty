#!/usr/bin/env bash
# Runs confined (started by tests/attacks/broker.sh through `cotty
# agent`): attacks on the session broker from inside the agent's
# confinement. Rows print as PASS|FAIL|SKIP NAME DETAIL. Targets come from
# the file $1 (paths and pids as seen outside).
set -u
# shellcheck disable=SC1090
. "$1"

row() { printf '%-4s  %-30s %s\n' "$1" "$2" "$3"; }
deny() {
	local name=$1 out rc
	shift
	out=$(timeout 60 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-140)
	case $rc in
	0) row FAIL "$name" "ESCAPED: $out" ;;
	2) [ "$1" = "$PROBE" ] && row SKIP "$name" "$out" || row PASS "$name" "denied: $out" ;;
	127) row SKIP "$name" "command not found, nothing tried: $out" ;;
	*) row PASS "$name" "denied: $out" ;;
	esac
}
allow() { # allow NAME WANT CMD...: must succeed and print WANT
	local name=$1 want=$2 out rc
	shift 2
	out=$(timeout 60 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-140)
	if [ $rc -eq 0 ] && [[ $out == *"$want"* ]]; then row PASS "$name" "ok $out"; else row FAIL "$name" "exit $rc: $out"; fi
}

AD=${COTTY_AGENT_DIR:-}
ASOCK=$AD/$S.sock

# The agent's own way in: the agent endpoint, assurance confined (strong
# with the guard loaded: AGENT_LEVEL from broker.sh).
allow c-agent-endpoint "assurance ${AGENT_LEVEL:-confined}" "$PROBE" hello "$ASOCK" agent
allow c-agent-endpoint-require "assurance ${AGENT_LEVEL:-confined}" "$PROBE" hello "$AD/$RS.sock" agent
deny c-hello-person-agentsock "$PROBE" hello "$ASOCK" person
deny c-hello-control-agentsock "$PROBE" hello "$ASOCK" control
deny c-agent-dir-plant-socket "$PROBE" open-write "$AD/fake.sock"
deny c-agent-reads-secret "$PROBE" agent-read "$ASOCK" "$SECRET"

# The person's side of the broker is not in the agent's view.
deny c-main-socket-visible sh -c "if test -e '$SOCK'; then echo '$SOCK is visible'; else echo '$SOCK is not in the view'; exit 1; fi"
deny c-hello-person-main "$PROBE" hello "$SOCK" person
deny c-session-dir-listing ls "$RTOUT/cotty/$S.json"
deny c-attach-fresh-pty "$PROBE" in-pty 15 "cotty:$S " cotty attach "$S"
deny c-systemd-run-attach systemd-run --user --pty --quiet cotty attach "$S"
# Shows only that admission is out of view (no session found), not that
# guessing is hard: the u- row tests the guessing.
deny c-admission-not-visible "$PROBE" brute cotty "$S" 3

# Terminals and processes of the session.
deny c-pts-by-path "$PROBE" open-tty "$PTS"
deny c-pts-via-proc-fd "$PROBE" open-tty "/proc/$SHELL_PID/fd/0"
deny c-ptrace-broker "$PROBE" ptrace "$BROKER"
deny c-proc-mem-broker "$PROBE" proc-mem "$BROKER"
deny c-vm-readv-broker "$PROBE" vm-readv "$BROKER"
if [ -n "$ATTACH_PID" ]; then
	deny c-ptrace-attach-client "$PROBE" ptrace "$ATTACH_PID"
	deny c-proc-mem-attach-client "$PROBE" proc-mem "$ATTACH_PID"
fi
deny c-pts-pidfd-getfd "$PROBE" pidfd-getfd "$SHELL_PID" "$PTS"

# Files that record the session.
deny c-read-audit "$PROBE" open-read "$STATE/audit.jsonl"
deny c-read-broker-log "$PROBE" open-read "$RTOUT/cotty/$S.log"
deny c-read-history "$PROBE" open-read "$STATE/sessions/$S/history"
echo "DONE broker-inside.sh"
