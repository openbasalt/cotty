# Shared by tests/attacks/gpg.sh and tests/attacks/guard-exceptions.sh
# (sourced, not run): the row helpers of broker.sh, a shared session with
# a scripted person attached (tests/attacks/probe person: denies attach
# requests, types SECRET whenever the lock lights), and the guard's pts
# exception list. Lab VMs only.

ROWS=""
row() { ROWS+=$'\n'"$(printf '%-4s  %-32s %s' "$1" "$2" "$3")"; }
# deny NAME CMD...: must fail (exit 1; the probe's 2 is a skip).
deny() {
	local name=$1 out rc
	shift
	out=$(timeout 60 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-140)
	case $rc in
	0) row FAIL "$name" "ESCAPED: $out" ;;
	2) row SKIP "$name" "$out" ;;
	127) row SKIP "$name" "command not found: $out" ;;
	*) row PASS "$name" "denied: $out" ;;
	esac
}
# allow NAME CMD...: must succeed.
allow() {
	local name=$1 out rc
	shift
	out=$(timeout 60 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tail -2 | tr '\n' ' ' | cut -c1-140)
	if [ $rc -eq 0 ]; then row PASS "$name" "ok: $out"; else row FAIL "$name" "exit $rc: $out"; fi
}
check() { # check NAME DETAIL CONDITION...
	local name=$1 detail=$2
	shift 2
	if "$@"; then row PASS "$name" "$detail"; else row FAIL "$name" "not true: $detail"; fi
}
summary() { # summary TITLE
	echo
	echo "$1, $(uname -r), $(. /etc/os-release && echo "$PRETTY_NAME")"
	printf '%-4s  %-32s %s\n' RES CHECK DETAIL
	echo "$ROWS" | sed '/^$/d'
	local pass fail gap skip
	pass=$(echo "$ROWS" | grep -c '^PASS')
	fail=$(echo "$ROWS" | grep -c '^FAIL')
	gap=$(echo "$ROWS" | grep -c '^GAP')
	skip=$(echo "$ROWS" | grep -c '^SKIP')
	echo
	echo "summary: $pass pass, $fail fail, $gap gap (documented), $skip skip (work dir $W)"
	[ "$fail" -eq 0 ]
}

GUARD_STATE="not loaded"
"$COTTY" guard status >/dev/null 2>&1 && GUARD_STATE=loaded

meta() { sed -n "s/.*\"$2\":\"\{0,1\}\([^\",}]*\).*/\1/p" "$RT/cotty/$1.json" 2>/dev/null; }

# start_session NAME: a shared session (--ai) with the scripted person
# attached; sets SOCK ASOCK PTS BROKER PERSON.
PERSON=""
SESSIONS=""
start_session() {
	local name=$1 out code
	out=$("$PROBE" in-pty 30 "reattach code" "$COTTY" new -d --ai --name "$name" -- bash --norc --noprofile 2>&1)
	code=$(echo "$out" | grep -o '[0-9A-Z]\{5\}-[0-9A-Z]\{5\}' | head -1)
	[ -n "$code" ] || { echo "cotty new failed: $out" >&2; exit 2; }
	(umask 077 && echo "$code" >"$W/code")
	SESSIONS+=" $name"
	SOCK=$RT/cotty/$name.sock
	ASOCK=$RT/cotty/agent/$name.sock
	PTS=$(meta "$name" pts)
	BROKER=$(meta "$name" broker_pid)
	"$PROBE" person "$COTTY" "$name" "$W/code" "$W/person.log" "$W/secret" &
	PERSON=$!
	for _ in $(seq 100); do grep -q attached "$W/person.log" 2>/dev/null && break; sleep 0.1; done
	grep -q attached "$W/person.log" || { echo "the person did not attach: $(cat "$W/person.log")" >&2; exit 2; }
	"$PROBE" agent-type "$ASOCK" "PS1='$ '" >/dev/null
	sleep 1
}

stop_sessions() {
	[ -n "$PERSON" ] && kill "$PERSON" 2>/dev/null
	local s pid
	for s in $SESSIONS; do
		pid=$(meta "$s" broker_pid)
		[ -n "$pid" ] && kill "$pid" 2>/dev/null
	done
}

# locks: the number of locks the person saw so far; lock_after N: the
# text of the first lock seen after N (empty when none within SECS).
locks() { grep -c lock-shown "$W/person.log" 2>/dev/null; }
lock_after() {
	local n=$1 secs=${2:-20} i
	for i in $(seq $((secs * 10))); do
		[ "$(locks)" -gt "$n" ] && break
		sleep 0.1
	done
	grep lock-shown "$W/person.log" | tail -n +$((n + 1)) | head -1 | cut -c12- | sed 's/  .*//'
}

# The guard's pts exception list (root-owned; the daemon reloads it on
# SIGHUP). EXC_SAVED keeps what was there before the test.
EXC=/etc/cotty/guard-exceptions.conf
EXC_SAVED=""
exc_save() {
	if sudo -n test -e "$EXC"; then
		EXC_SAVED=$W/exceptions.saved
		sudo -n cat "$EXC" >"$EXC_SAVED"
	fi
}
exc_restore() {
	if [ -n "$EXC_SAVED" ]; then
		sudo -n install -o root -g root -m 0644 "$EXC_SAVED" "$EXC"
	else
		sudo -n rm -f "$EXC"
	fi
	exc_reload
}
exc_reload() {
	local pid
	pid=$(systemctl show -p MainPID --value cotty-guard 2>/dev/null)
	if [ -n "$pid" ] && [ "$pid" != 0 ]; then
		sudo -n kill -HUP "$pid"
	else
		sudo -n pkill -HUP -x cotty-guard
	fi
	sleep 1
}
# exc_set LINES...: writes the list (root-owned, 0644) and reloads.
exc_set() {
	sudo -n install -d -o root -g root -m 0755 /etc/cotty
	printf '%s\n' "$@" | sudo -n tee "$EXC" >/dev/null
	sudo -n chown root:root "$EXC"
	sudo -n chmod 0644 "$EXC"
	exc_reload
}
# exc_listed PATH: the running guard lists PATH as an exception.
exc_listed() { "$COTTY" guard status 2>/dev/null | grep -q "\"$1\""; }
