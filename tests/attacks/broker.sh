#!/usr/bin/env bash
# Escape matrix against the session broker (WP-E). Run it as an
# unprivileged user in a throwaway VM (tests/lab/vm.sh broker-matrix NAME),
# with cotty installed root-owned (/usr/local/bin/cotty), never on a
# machine you care about.
#
# Outside it starts a shared session, a scripted person attached to it
# (tests/attacks/probe person: denies every attach request, types a secret
# at the lock), puts a secret through a `read -rs` prompt, and then
# attacks the broker twice:
#
#   - unconfined: as an ordinary process of the same user (an agent
#     started without `cotty agent`, assurance weak);
#   - confined: tests/attacks/broker-inside.sh under `cotty agent`
#     (assurance confined).
#
# Rows: PASS (denied, or allowed work that must work), FAIL (an escape the
# docs say is closed at that level), GAP (an escape the docs list as open
# at that level: closed only by the guard, layer 3; with the guard loaded
# a GAP row that gets through is a FAIL), SKIP. A FAIL whose detail
# starts with "[open: ITEM]" is a weakness of the final review that is
# not fixed yet (expected to fail until that fix lands). Exit 1 on FAIL.
#
# Optional, with the guard loaded (each adds minutes):
#   COTTY_MATRIX_IDLE_SECS=620   wait that long with the session idle,
#                                then try the pts again (the guard drops
#                                idle client connections after 600 s)
#   COTTY_MATRIX_GUARD_RESTART=1 restart cotty-guard (sudo -n systemctl
#                                restart cotty-guard) mid-session, then
#                                try the pts again
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
COTTY=${COTTY:-/usr/local/bin/cotty}
PROBE=${PROBE:-$HERE/../../bin/probe}
GUARDPROBE=${GUARDPROBE:-$HERE/../../bin/guardprobe}
[ -x "$COTTY" ] || { echo "no cotty binary at $COTTY" >&2; exit 2; }
[ -x "$PROBE" ] || { echo "no probe binary at $PROBE" >&2; exit 2; }
RT=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
STATE=${XDG_STATE_HOME:-$HOME/.local/state}/cotty

W=$HOME/cotty-bmatrix/$(date +%Y%m%d-%H%M%S)
P=$W/project
T=$W/tools
mkdir -p "$P" "$T"
chmod 700 "$W"
cp "$HERE/broker-inside.sh" "$PROBE" "$T/"
S=bm$RANDOM
RS=${S}rc
SECRET=COTTY-BSECRET-$RANDOM$RANDOM$RANDOM
(umask 077 && echo "$SECRET" >"$W/secret")

ROWS=""
# OPEN: the review item of the next row, if it is a known open weakness.
OPEN=""
row() {
	local d=$3
	[ "$1" = FAIL ] && [ -n "$OPEN" ] && d="[open: $OPEN] $d"
	OPEN=""
	ROWS+=$'\n'"$(printf '%-4s  %-30s %s' "$1" "$2" "$d")"
}
known_open() { OPEN=$1; }
# judge NAME RC OUT: the verdict of an attack that exited with RC.
judge() {
	local name=$1 rc=$2 out=$3
	case $rc in
	0) row FAIL "$name" "ESCAPED: $out" ;;
	2) row SKIP "$name" "$out" ;;
	127) row SKIP "$name" "command not found, nothing tried: $out" ;;
	*) row PASS "$name" "denied: $out" ;;
	esac
}
# deny NAME CMD...: must fail (probe exit 1; 2 is skip for the probe).
deny() {
	local name=$1 out rc
	shift
	out=$(timeout 90 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-150)
	[ $rc -eq 2 ] && [ "$1" != "$PROBE" ] && rc=1
	judge "$name" $rc "$out"
}
# gap NAME WHY CMD...: an attempt the docs list as open at this level
# without the guard. With the guard loaded it must be denied.
gap() {
	local name=$1 why=$2 out rc
	shift 2
	out=$(timeout 30 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-100)
	case $rc in
	0) if [ "$GUARD_STATE" = loaded ]; then
		row FAIL "$name" "ESCAPED with the guard loaded ($why): $out"
	else
		OPEN=""
		row GAP "$name" "reachable ($why): $out"
	fi ;;
	127) row SKIP "$name" "command not found: $out" ;;
	*) row PASS "$name" "denied: $out" ;;
	esac
}
allow() {
	local name=$1 out rc
	shift
	out=$(timeout 90 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tail -2 | tr '\n' ' ' | cut -c1-150)
	if [ $rc -eq 0 ]; then row PASS "$name" "ok $out"; else row FAIL "$name" "exit $rc: $out"; fi
}
check() { # check NAME DETAIL CONDITION...
	local name=$1 detail=$2
	shift 2
	if "$@"; then row PASS "$name" "$detail"; else row FAIL "$name" "not true: $detail"; fi
}

PERSON=""
cleanup() {
	[ -n "$PERSON" ] && kill "$PERSON" 2>/dev/null
	for s in "$S" "$RS"; do
		pid=$(sed -n 's/.*"broker_pid":\([0-9]*\).*/\1/p' "$RT/cotty/$s.json" 2>/dev/null)
		[ -n "$pid" ] && kill "$pid" 2>/dev/null
	done
}
trap cleanup EXIT

# --- the session and its person ---
# cotty new presents its creator token as a person: it needs a terminal.
out=$("$PROBE" in-pty 30 "reattach code" "$COTTY" new -d --ai --name "$S" -- bash --norc --noprofile 2>&1)
code=$(echo "$out" | grep -o '[0-9A-Z]\{5\}-[0-9A-Z]\{5\}' | head -1)
[ -n "$code" ] || { echo "cotty new failed: $out" >&2; exit 2; }
(umask 077 && echo "$code" >"$W/code")
"$PROBE" in-pty 30 "reattach code" "$COTTY" new -d --ai --require-confined --name "$RS" -- bash --norc --noprofile >/dev/null 2>&1
SOCK=$RT/cotty/$S.sock
ASOCK=$RT/cotty/agent/$S.sock
BROKER=$(sed -n 's/.*"broker_pid":\([0-9]*\).*/\1/p' "$RT/cotty/$S.json")
PTS=$(sed -n 's/.*"pts":"\([^"]*\)".*/\1/p' "$RT/cotty/$S.json")
SHELL_PID=$(pgrep -P "$BROKER" | head -1)

"$PROBE" person "$COTTY" "$S" "$W/code" "$W/person.log" "$W/secret" &
PERSON=$!
for _ in $(seq 100); do grep -q attached "$W/person.log" 2>/dev/null && break; sleep 0.1; done
grep -q attached "$W/person.log" || { echo "the person did not attach: $(cat "$W/person.log")" >&2; exit 2; }
ATTACH_PID=$(pgrep -f "^$COTTY attach $S\$" | head -1)

# A secret prompt in the session: the agent starts it, the person types.
"$PROBE" agent-type "$ASOCK" "PS1='$ '; read -rs SEC; echo got-\${#SEC}-chars" >/dev/null
for _ in $(seq 100); do grep -q typed-secret "$W/person.log" && break; sleep 0.1; done
sleep 2
# Settings of the session's children.
"$PROBE" agent-type "$ASOCK" "echo \"core=\$(ulimit -Hc) hist=\$HISTFILE\" > $W/session-env.txt" >/dev/null
sleep 2

# With cotty-guard loaded (layer 3) a confined agent is tagged: strong.
AGENT_LEVEL=confined
GUARD_STATE="not loaded"
if "$COTTY" guard status >/dev/null 2>&1; then
	AGENT_LEVEL=strong
	GUARD_STATE=loaded
fi
cat >"$P/targets.env" <<EOF
S=$S
RS=$RS
SOCK=$SOCK
BROKER=$BROKER
SHELL_PID=$SHELL_PID
ATTACH_PID=$ATTACH_PID
PTS=$PTS
SECRET=$SECRET
RTOUT=$RT
STATE=$STATE
PROBE=$T/probe
AGENT_LEVEL=$AGENT_LEVEL
EOF

# --- setup checks ---
check secret-prompt-seen "the person typed the secret at the lock" grep -q typed-secret "$W/person.log"
check secret-start-audited "the audit log has the secret prompt (start), never its content" grep -q '"secret.start"' "$STATE/audit.jsonl"
check session-core-limit "session children have RLIMIT_CORE 0 (hard): $(cat "$W/session-env.txt" 2>/dev/null)" grep -q 'core=0 ' "$W/session-env.txt"
check session-histfile "HISTFILE is in the session state dir" grep -q "hist=$STATE/sessions/$S/history" "$W/session-env.txt"

# --- unconfined (assurance weak) ---
deny u-hello-person-main "$PROBE" hello "$SOCK" person
deny u-hello-control-main "$PROBE" hello "$SOCK" control
deny u-hello-person-agentsock "$PROBE" hello "$ASOCK" person
deny u-control-no-tty "$COTTY" share --off "$S"
deny u-kill-no-tty "$COTTY" kill "$S"
# An attach from a fresh terminal must prove the reattach code before the
# attached person is even asked (review N1: an approval alone proves
# nothing to the client about the broker): no attach request without it.
before=$(grep -c request-denied "$W/person.log")
deny u-attach-fresh-pty "$PROBE" in-pty 15 "cotty:$S " "$COTTY" attach "$S"
after=$(grep -c request-denied "$W/person.log")
check u-attach-needs-code "an attach without the code raised no attach request ($before -> $after requests)" test "$after" -eq "$before"
if command -v systemd-run >/dev/null; then
	deny u-systemd-run-pty-attach "$PROBE" in-pty 15 "cotty:$S " systemd-run --user --pty --quiet "$COTTY" attach "$S"
	after2=$(grep -c request-denied "$W/person.log")
	check u-systemd-run-needs-code "systemd-run --user --pty attach raised no attach request without the code ($after -> $after2)" test "$after2" -eq "$after"
	deny u-systemd-run-control systemd-run --user --quiet --wait --pipe "$COTTY" share --off "$S"
fi
check u-still-shared "the session is still shared after the control attempts" test -S "$ASOCK"
deny u-agent-reads-secret "$PROBE" agent-read "$ASOCK" "$SECRET"
gap u-pts-by-path "same uid opens its own pts; guard rule file_open" "$PROBE" open-tty "$PTS"
gap u-pts-via-proc-fd "the session shell is dumpable; guard rule file_open" "$PROBE" open-tty "/proc/$SHELL_PID/fd/0"
gap u-ptrace-shell "ptrace of the session shell (Yama permitting); guard rule ptrace_access_check" "$PROBE" ptrace "$SHELL_PID"
# A ptrace attach that got through may leave the shell stopped; the rows
# below need it running.
kill -CONT "$SHELL_PID" 2>/dev/null
# A command in the session (it may open its own terminal) sends the pts
# to a process outside over SCM_RIGHTS.
rm -f "$W/fd.ready"
"$PROBE" recv-fd "$W/fd.sock" "$W/fd.ready" >"$W/recvfd.out" 2>&1 &
RP=$!
for _ in $(seq 50); do [ -s "$W/fd.ready" ] && break; sleep 0.1; done
"$PROBE" agent-type "$ASOCK" "$T/probe send-tty $W/fd.sock /dev/tty >/dev/null" >/dev/null
wait "$RP"
RRC=$?
RDETAIL=$(tr '\n' ' ' <"$W/recvfd.out" | cut -c1-100)
case $RRC in
0) if [ "$GUARD_STATE" = loaded ]; then row FAIL u-pts-scm-rights "ESCAPED: $RDETAIL"; else row GAP u-pts-scm-rights "reachable (a session command passes its pts out; guard rule file_receive): $RDETAIL"; fi ;;
2) row SKIP u-pts-scm-rights "$RDETAIL" ;;
*) row PASS u-pts-scm-rights "denied: $RDETAIL" ;;
esac
# An agent CLI started inside the session (guard-tagged, its controlling
# terminal is the session pts) opens /dev/tty.
if [ "$GUARD_STATE" = loaded ] && [ -x "$GUARDPROBE" ]; then
	cp "$GUARDPROBE" "$T/"
	rm -f "$W/devtty.out"
	"$PROBE" agent-type "$ASOCK" "systemd-run --user --scope --quiet --collect --unit=cotty-agent-tty\$RANDOM -- $T/guardprobe run-registered -- $T/probe open-tty /dev/tty >$W/devtty.out 2>&1; echo rc=\$? >>$W/devtty.out" >/dev/null
	for _ in $(seq 100); do grep -q '^rc=' "$W/devtty.out" 2>/dev/null && break; sleep 0.1; done
	DT=$(tr '\n' ' ' <"$W/devtty.out" 2>/dev/null | cut -c1-120)
	case $(sed -n 's/^rc=//p' "$W/devtty.out" 2>/dev/null) in
	0) row FAIL u-tagged-dev-tty "ESCAPED: $DT" ;;
	1)
		# Denied by the guard means EPERM or EACCES; any other error (no
		# controlling terminal, ENXIO) proves nothing about the rule.
		if grep -qi 'permission denied\|operation not permitted' "$W/devtty.out"; then
			row PASS u-tagged-dev-tty "denied: $DT"
		else
			row SKIP u-tagged-dev-tty "failed for another reason than the guard rule: $DT"
		fi ;;
	*) row SKIP u-tagged-dev-tty "$DT" ;;
	esac
else
	row SKIP u-tagged-dev-tty "needs the guard (a guard-tagged agent inside the session)"
fi
deny u-broker-fds ls "/proc/$BROKER/fd"
deny u-broker-environ "$PROBE" open-read "/proc/$BROKER/environ"
deny u-ptrace-broker "$PROBE" ptrace "$BROKER"
deny u-proc-mem-broker "$PROBE" proc-mem "$BROKER"
deny u-vm-readv-broker "$PROBE" vm-readv "$BROKER"
if [ -n "$ATTACH_PID" ]; then
	deny u-ptrace-attach-client "$PROBE" ptrace "$ATTACH_PID"
	deny u-proc-mem-attach-client "$PROBE" proc-mem "$ATTACH_PID"
	deny u-vm-readv-attach-client "$PROBE" vm-readv "$ATTACH_PID"
else
	row SKIP u-attach-client "attach client pid not found"
fi
# The search must have something to search: the audit log and the
# broker logs exist and are not empty.
if [ -s "$STATE/audit.jsonl" ] && ls "$RT/cotty/"*.log >/dev/null 2>&1; then
	if grep -rqF "$SECRET" "$STATE" "$RT/cotty"; then
		row FAIL u-secret-in-audit-or-logs "the secret is in $(grep -rlF "$SECRET" "$STATE" "$RT/cotty" | head -1)"
	else
		row PASS u-secret-in-audit-or-logs "searched $(find "$STATE" "$RT/cotty" -type f | wc -l) files ($(du -sk "$STATE" | cut -f1) KiB of state), the secret is in none"
	fi
else
	row SKIP u-secret-in-audit-or-logs "no audit log or broker log to search"
fi
known_open S22
gap u-pts-pidfd-getfd "pidfd_getfd of the shell's fd 0 skips file_open; review S22" "$PROBE" pidfd-getfd "$SHELL_PID" "$PTS"
deny u-hello-agent-require-confined "$PROBE" hello "$RT/cotty/agent/$RS.sock" agent

# --- confined (assurance confined) ---
"$COTTY" agent --profile generic --pty always --project "$P" --ro "$T" -- \
	bash "$T/broker-inside.sh" "$P/targets.env" >"$W/inside.raw" 2>&1 </dev/null
RC=$?
tr -d '\r' <"$W/inside.raw" >"$W/inside.out"
grep -E '^cotty agent' "$W/inside.out"
ROWS+=$'\n'"$(grep -E '^(PASS|FAIL|SKIP|GAP) ' "$W/inside.out")"
if grep -q '^DONE ' "$W/inside.out"; then
	row PASS c-inside-completed "broker-inside.sh ran to the end (cotty agent exit $RC)"
else
	row FAIL c-inside-completed "broker-inside.sh did not finish (exit $RC); see $W/inside.out"
fi

# --- rows added after the final review (expected to fail until fixed) ---
# person_cmd BYTES: the scripted person types BYTES (hotkeys included).
person_cmd() {
	printf '%b' "$1" >"$W/person.log.cmd"
	kill -USR2 "$PERSON"
	sleep 0.5
}
if [ -n "$PERSON" ] && kill -0 "$PERSON" 2>/dev/null; then
	# B1: with shell integration (OSC 133), the command the person runs
	# in private mode reaches the agent through state.last_command.
	cat >"$W/osc133.sh" <<'EOS'
PS1=$'\[\e]133;A\a\]$ \[\e]133;B\a\]'
PS0=$'\e]133;C\a'
PROMPT_COMMAND='printf "\e]133;D;%s\a" $?'
EOS
	"$PROBE" agent-type "$ASOCK" ". $W/osc133.sh" >/dev/null
	sleep 2
	PMARK=COTTY-PRIV-$RANDOM$RANDOM$RANDOM
	person_cmd '\x1dp'
	sleep 1
	person_cmd "export PRIVTOK=$PMARK\r"
	sleep 2
	known_open B1
	deny u-private-mode-last-command "$PROBE" agent-read "$ASOCK" "$PMARK"
	person_cmd '\x1dp'
	sleep 1
	person_cmd 'true\r'
	sleep 1

	# B2: an agent subscribed to state gets one event per key the person
	# types at a secret prompt (the person types one key at a time).
	"$PROBE" agent-events "$ASOCK" 14 >"$W/events.out" 2>&1 &
	evpid=$!
	sleep 1
	n=$(grep -c typed-secret "$W/person.log")
	"$PROBE" agent-type "$ASOCK" "read -rs SEC2; echo got2-\${#SEC2}-chars" >/dev/null
	for _ in $(seq 100); do [ "$(grep -c typed-secret "$W/person.log")" -gt "$n" ] && break; sleep 0.1; done
	wait "$evpid"
	evrc=$?
	known_open B2
	judge u-state-events-during-secret $evrc "$(tr '\n' ' ' <"$W/events.out" | cut -c1-150)"

	# B6: a fake password prompt behind a pipeline whose process group
	# leader is a system binary: the lock names the leader, not the
	# interpreter that reads the keys. `sleep 3;` outlasts the 2 s window
	# that marks a job as started by the agent.
	cat >"$W/fakepw.py" <<EOS
import getpass
open("$W/fake-lock-captured", "w").write(str(len(getpass.getpass("[sudo] password for $(id -un): "))))
EOS
	n=$(grep -c lock-shown "$W/person.log")
	"$PROBE" agent-type "$ASOCK" "sleep 3; sleep 6 | python3 $W/fakepw.py" >/dev/null
	for _ in $(seq 150); do [ "$(grep -c lock-shown "$W/person.log")" -gt "$n" ] && break; sleep 0.1; done
	# The lock segment ends at the status line's next field (two spaces);
	# the rest (agent> ...) repeats what the agent typed.
	lock=$(grep lock-shown "$W/person.log" | tail -n +$((n + 1)) | head -1 | cut -c12- | sed 's/  .*//')
	sleep 8
	if [ -z "$lock" ]; then
		row SKIP u-fake-lock-pipeline "the lock never lit for the fake prompt"
	elif echo "$lock" | grep -q python; then
		row PASS u-fake-lock-pipeline "the lock names the reader: $lock"
	else
		known_open B6
		row FAIL u-fake-lock-pipeline "the lock showed \"$lock\" while python3 read the keys ($( [ -s "$W/fake-lock-captured" ] && echo "it captured $(cat "$W/fake-lock-captured") chars" || echo "nothing captured"))"
	fi

	# N3: a trusted non-interpreter reads the password under a forged
	# name (a symlink called sudo to sed; coreutils may be a multi-call
	# binary that picks its tool from the name): the lock must name sed.
	n=$(grep -c lock-shown "$W/person.log")
	"$PROBE" agent-type "$ASOCK" "ln -sf \$(command -v sed) $W/sudo; printf '[sudo] password for $(id -un): '; stty -echo; $W/sudo q >$W/renamed-captured; stty echo; echo" >/dev/null
	for _ in $(seq 150); do [ "$(grep -c lock-shown "$W/person.log")" -gt "$n" ] && break; sleep 0.1; done
	lock=$(grep lock-shown "$W/person.log" | tail -n +$((n + 1)) | head -1 | cut -c12- | sed 's/  .*//')
	sleep 3
	if [ -z "$lock" ]; then
		row SKIP u-fake-lock-renamed "the lock never lit for the renamed reader"
	elif echo "$lock" | grep -q '(as sudo)'; then
		row PASS u-fake-lock-renamed "the lock names the executable: $lock"
	else
		row FAIL u-fake-lock-renamed "the lock showed \"$lock\" while sed, started as sudo, read the keys"
	fi

	# N4: a row the person wrote in private mode (on the top row, after
	# clear), moved down by the agent afterwards without scrolling (insert
	# line, reverse index) and changed by one cell on every row (insert
	# character), stays hidden.
	MMARK=COTTY-MOVED-$RANDOM$RANDOM
	person_cmd '\x1dp'
	sleep 1
	person_cmd "clear; echo $MMARK\r"
	sleep 2
	person_cmd '\x1dp'
	sleep 1
	"$PROBE" agent-type "$ASOCK" "printf '\\033[3;1H\\033[2L\\033[1;1H\\033M'; for i in \$(seq 1 \$(tput lines)); do printf '\\033[%d;1H\\033[@' \$i; done; printf '\\033[999;1H\\n'" >/dev/null
	sleep 2
	deny u-private-moved-rows "$PROBE" agent-read "$ASOCK" "$MMARK"

	# N5: the agent prints a row equal to one the person printed in
	# private mode; it must read its own row (no [private] answer that
	# tells it the person saw that text).
	ON=$RANDOM$RANDOM
	person_cmd '\x1dp'
	sleep 1
	person_cmd "printf '%s%s\\\\n' ORACLE- $ON\r"
	sleep 2
	person_cmd '\x1dp'
	sleep 1
	"$PROBE" agent-type "$ASOCK" "printf '%s%s\\n' ORACLE- $ON" >/dev/null
	sleep 2
	if "$PROBE" agent-read "$ASOCK" "ORACLE-$ON" >/dev/null 2>&1; then
		row PASS u-private-no-text-oracle "the agent reads its own row equal to a private one"
	else
		row FAIL u-private-no-text-oracle "the agent's row equal to a private row read [private]: an oracle for private text"
	fi

	# T1 (round 3): a row the person wrote in private mode stays hidden
	# when the agent's view freezes later: at a secret prompt the agent
	# starts itself (read -rs here; sudo -k; sudo true does the same where
	# sudo asks a password), and when the person turns private mode on
	# again.
	FMARK=COTTY-FROZEN-$RANDOM$RANDOM
	person_cmd '\x1dp'
	sleep 1
	person_cmd "clear; echo $FMARK\r"
	sleep 2
	person_cmd '\x1dp'
	sleep 1
	"$PROBE" agent-type "$ASOCK" "read -rs FV; echo frozen-done" >/dev/null
	sleep 2
	deny u-private-then-secret-freeze "$PROBE" agent-read "$ASOCK" "$FMARK"
	person_cmd '\r'
	sleep 2
	person_cmd '\x1dp'
	sleep 1
	deny u-private-then-private-freeze "$PROBE" agent-read "$ASOCK" "$FMARK"
	person_cmd '\x1dp'
	sleep 1

	# T2 (round 3): any program may print OSC 133 marks. The agent prints
	# a forged B and C around a row the person wrote in private mode;
	# state.shell.last_command must not copy that row.
	OMARK=COTTY-OSC133-$RANDOM$RANDOM
	person_cmd '\x1dp'
	sleep 1
	person_cmd "clear; echo note $OMARK\r"
	sleep 2
	person_cmd '\x1dp'
	sleep 1
	"$PROBE" agent-type "$ASOCK" "printf '\\e7\\e[1;1H\\e]133;B\\a\\e[1;70H\\e]133;C\\a\\e8'" >/dev/null
	sleep 2
	deny u-forged-osc133-private-row "$PROBE" agent-read "$ASOCK" "$OMARK"

	# N15: the person types a password right after an agent Enter, before
	# the agent's command turned echo off: held, not echoed.
	TMARK=COTTY-TYPEAHEAD-$RANDOM$RANDOM
	"$PROBE" agent-type "$ASOCK" "sleep 0.08; stty -echo; read V; stty echo; echo tlen-\${#V}" >/dev/null
	printf '%s\r' "$TMARK" >"$W/person.log.cmd"
	kill -USR2 "$PERSON"
	sleep 3
	deny u-typeahead-agent-enter "$PROBE" agent-read "$ASOCK" "$TMARK"

	# sudo-rs: sudo relaying the terminal for its command (raw mode, echo
	# off) must not light the lock; the lab user's sudo needs no password.
	if sudo -n true 2>/dev/null; then
		n=$(grep -c lock-shown "$W/person.log")
		"$PROBE" agent-type "$ASOCK" "sudo -n sleep 3; echo sudo-relay-done" >/dev/null
		sleep 4
		if [ "$(grep -c lock-shown "$W/person.log")" -gt "$n" ]; then
			row FAIL u-sudo-command-not-secret "the lock lit while sudo ran a command: $(grep lock-shown "$W/person.log" | tail -1 | cut -c1-80)"
		else
			row PASS u-sudo-command-not-secret "no lock while sudo ran its command ($(sudo --version 2>/dev/null | head -1))"
		fi
	else
		row SKIP u-sudo-command-not-secret "sudo needs a password here"
	fi
else
	row SKIP u-private-mode-last-command "the person is not attached"
fi

# B4, B5 (opt-in, guard loaded): the pts protection must outlive an idle
# session and a guard restart, or the session must stop reporting strong.
if [ "$GUARD_STATE" = loaded ] && [ -n "${COTTY_MATRIX_IDLE_SECS:-}" ]; then
	sleep "$COTTY_MATRIX_IDLE_SECS"
	known_open B4
	deny u-pts-after-idle "$PROBE" open-tty "$PTS"
fi
if [ "$GUARD_STATE" = loaded ] && [ "${COTTY_MATRIX_GUARD_RESTART:-0}" = 1 ]; then
	if sudo -n systemctl restart cotty-guard; then
		sleep 3
		known_open B5
		deny u-pts-after-guard-restart "$PROBE" open-tty "$PTS"
		# The level a confined agent is given now (an unconfined probe
		# would only ever be weak).
		lvl=$("$COTTY" agent --quiet --profile generic --project "$P" --ro "$T" -- \
			sh -c '"$1" hello "$COTTY_AGENT_DIR/$2.sock" agent' sh "$T/probe" "$S" 2>&1 </dev/null)
		if echo "$lvl" | grep -q 'assurance strong' && "$PROBE" open-tty "$PTS" >/dev/null 2>&1; then
			known_open B5
			row FAIL u-strong-after-guard-restart "the session still reports strong while its pts opens: $lvl"
		else
			row PASS u-strong-after-guard-restart "$lvl"
		fi
	else
		row SKIP u-pts-after-guard-restart "cannot restart cotty-guard (sudo -n)"
	fi
fi

# --- reattach code guessing (no person attached) ---
kill -USR1 "$PERSON"
wait "$PERSON" 2>/dev/null
PERSON=""
check person-detached "the person detached and noted the new code" grep -q detached "$W/person.log"
deny u-reattach-code-brute "$PROBE" brute "$COTTY" "$S" 6
# S4: the lockout after wrong codes is global, so the guesses also lock
# the real person out. Try right away, then again after the lockout.
"$PROBE" person "$COTTY" "$S" "$W/code" "$W/person2.log" &
PERSON=$!
for _ in $(seq 100); do grep -q 'attached\|attach-failed' "$W/person2.log" 2>/dev/null && break; sleep 0.1; done
if grep -q '^attached' "$W/person2.log"; then
	row PASS person-not-locked-out "the person attached right after the guesses"
else
	known_open S4
	row FAIL person-not-locked-out "the guesses locked the real person out too: $(tail -1 "$W/person2.log" 2>/dev/null | cut -c1-100)"
	wait "$PERSON" 2>/dev/null
	sleep 31
	"$PROBE" person "$COTTY" "$S" "$W/code" "$W/person2.log" &
	PERSON=$!
	for _ in $(seq 100); do grep -q '^attached' "$W/person2.log" 2>/dev/null && break; sleep 0.1; done
fi
check person-reattach "the person reattaches with the real code after the guesses" grep -q '^attached' "$W/person2.log"

# B3: a process of the user replaces the session socket; the person's
# attach client sends the reattach code to whatever listens there.
kill -USR1 "$PERSON"
wait "$PERSON" 2>/dev/null
PERSON=""
if mv "$SOCK" "$SOCK.real" 2>/dev/null; then
	known_open B3
	if [ "$GUARD_STATE" = loaded ]; then
		row FAIL u-session-socket-replace "ESCAPED with the guard loaded: a process of the user renamed the session socket"
	else
		row GAP u-session-socket-replace "a process of the user can rename and replace the session socket (same uid)"
	fi
	"$PROBE" fake-broker "$SOCK" "$W/fake-broker.log" 25 >"$W/fake-broker.out" 2>&1 &
	fb=$!
	for _ in $(seq 30); do [ -S "$SOCK" ] && break; sleep 0.1; done
	"$PROBE" person "$COTTY" "$S" "$W/code" "$W/person3.log" &
	p3=$!
	wait "$fb"
	fbrc=$?
	kill "$p3" 2>/dev/null
	wait "$p3" 2>/dev/null
	rm -f "$SOCK"
	mv "$SOCK.real" "$SOCK"
	known_open B3
	judge u-attach-trusts-fake-socket $fbrc "$(tr '\n' ' ' <"$W/fake-broker.out" | cut -c1-150)"
else
	row PASS u-session-socket-replace "the session socket cannot be renamed"
fi

# --- review round 2, N1: session takeover ---
meta_pid() { sed -n 's/.*"broker_pid":\([0-9]*\).*/\1/p' "$RT/cotty/$1.json" 2>/dev/null; }
# second_broker NAME ARGS...: a second real broker with the session's name
# (the installed binary, any process of the user can start it) must be
# refused, and the session's socket and broker must stay as they were.
second_broker() {
	local name=$1 ino0 ino1 pid1 out rc
	shift
	ino0=$(stat -c %i "$SOCK")
	out=$(timeout 20 "$COTTY" __broker -name "$S" "$@" -- bash --norc --noprofile </dev/null 2>&1)
	rc=$?
	ino1=$(stat -c %i "$SOCK" 2>/dev/null)
	pid1=$(meta_pid "$S")
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-120)
	if [ $rc -ne 0 ] && [ "$ino1" = "$ino0" ] && [ "$pid1" = "$BROKER" ] && "$PROBE" connect "$SOCK" >/dev/null 2>&1; then
		row PASS "$name" "refused (exit $rc), the session socket and broker unchanged: $out"
	else
		row FAIL "$name" "ESCAPED: exit $rc, socket inode $ino0 -> $ino1, broker $BROKER -> $pid1: $out"
	fi
}
second_broker u-second-broker-same-name
second_broker u-second-broker-insecure -dev-insecure
if [ "$GUARD_STATE" = loaded ]; then
	out=$(timeout 20 "$PROBE" in-pty 15 "reattach code" "$COTTY" new -d --dev-insecure --name "${S}i" -- bash --norc --noprofile 2>&1)
	if echo "$out" | grep -q 'reattach code [0-9A-Z]'; then
		row FAIL u-insecure-broker-with-guard "ESCAPED: a -dev-insecure session started next to the guard"
		kill "$(meta_pid "${S}i")" 2>/dev/null
	else
		row PASS u-insecure-broker-with-guard "refused: $(echo "$out" | tr '\n' ' ' | cut -c1-120)"
	fi
	# The guard vouches for a session's broker by session name, not for
	# "a registered broker of the user".
	allow u-verify-broker-own-session "$GUARDPROBE" verify "$SOCK" "$S"
	deny u-verify-broker-other-session "$GUARDPROBE" verify "$SOCK" "$RS"
else
	row SKIP u-insecure-broker-with-guard "the guard is not loaded"
fi
# A forged listener that passes every consistency check (metadata with
# its own pid, not dumpable, comm cotty, argv __broker) and admits the
# client at once, without a challenge, as an approval or as an insecure
# broker: the client must refuse it (it proves no secret).
mkdir -p "$W/forged"
cp "$PROBE" "$W/forged/cotty"
for mode in approval insecure; do
	FK=fk$RANDOM
	"$W/forged/cotty" __broker "$RT/cotty/$FK.sock" "$RT/cotty/$FK.json" 20 "$mode" >"$W/forged-$mode.out" 2>&1 &
	fp=$!
	for _ in $(seq 30); do { [ -S "$RT/cotty/$FK.sock" ] || ! kill -0 $fp 2>/dev/null; } && break; sleep 0.1; done
	if [ -S "$RT/cotty/$FK.sock" ]; then
		"$PROBE" in-pty 15 "cotty:$FK " "$COTTY" attach "$FK" >"$W/forged-attach-$mode.out" 2>&1
	fi
	wait $fp
	frc=$?
	judge "u-attach-forged-$mode" $frc "$(tr '\n' ' ' <"$W/forged-$mode.out" | cut -c1-90) / client: $(tr '\n' ' ' <"$W/forged-attach-$mode.out" 2>/dev/null | tail -c 120)"
	rm -f "$RT/cotty/$FK.sock" "$RT/cotty/$FK.json"
done

# --- review round 2, N2: a process races the broker for a new session pts
# (inotify on /dev/pts, open retried while the pty is locked) ---
"$PROBE" race-pts 12 "$W/race.out" &
rp=$!
for _ in $(seq 30); do grep -q ready "$W/race.out" 2>/dev/null && break; sleep 0.1; done
RACE=${S}r
"$PROBE" in-pty 30 "reattach code" "$COTTY" new -d --name "$RACE" -- bash --norc --noprofile >/dev/null 2>&1
RPTS=$(sed -n 's/.*"pts":"\([^"]*\)".*/\1/p' "$RT/cotty/$RACE.json" 2>/dev/null)
wait $rp
kill "$(meta_pid "$RACE")" 2>/dev/null
if [ -z "$RPTS" ]; then
	row SKIP u-pts-race-open "the race session did not start"
elif grep -qx "opened $RPTS" "$W/race.out"; then
	if [ "$GUARD_STATE" = loaded ]; then
		row FAIL u-pts-race-open "ESCAPED with the guard loaded: a racing process opened $RPTS before it was protected"
	else
		row GAP u-pts-race-open "without the guard any process of the user opens a session pts: $RPTS"
	fi
else
	row PASS u-pts-race-open "never opened $RPTS: $(grep "$RPTS" "$W/race.out" | head -1)"
fi

echo
echo "broker escape matrix, guard $GUARD_STATE, $(uname -r), $(. /etc/os-release && echo "$PRETTY_NAME"), $("$COTTY" doctor --json | sed -n 's/.*"value": "ABI \([0-9]*\)".*/landlock ABI \1/p' | head -1)"
echo "u- rows: unconfined process of the same user (agent assurance weak); c- rows: under cotty agent (assurance confined)"
printf '%-4s  %-30s %s\n' RES CHECK DETAIL
echo "$ROWS" | sed '/^$/d'
PASS=$(echo "$ROWS" | grep -c '^PASS')
FAIL=$(echo "$ROWS" | grep -c '^FAIL')
KNOWN=$(echo "$ROWS" | grep -c '^FAIL .*\[open: ')
GAP=$(echo "$ROWS" | grep -c '^GAP')
SKIP=$(echo "$ROWS" | grep -c '^SKIP')
echo
echo "summary: $PASS pass, $FAIL fail ($KNOWN of them open review items), $GAP gap (documented, guard needed), $SKIP skip (work dir $W)"
[ "$FAIL" -eq 0 ]
