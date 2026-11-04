#!/usr/bin/env bash
# GPG passphrase prompts in a cotty session (docs/security.md, GPG). Run it
# as an unprivileged user with passwordless sudo in a throwaway VM, with
# cotty installed root-owned (/usr/local/bin/cotty), with or without
# cotty-guard, never on a machine you care about.
#
# A shared session with a scripted person attached (it types the
# passphrase whenever the lock lights); the agent runs the signing
# commands. A test key with a passphrase lives in throwaway GNUPGHOMEs.
#
#   loopback   pinentry-mode loopback (gpg.conf) and allow-loopback-pinentry
#              (gpg-agent.conf): gpg asks on its own terminal, in the
#              foreground job. The lock must light, the agent's view must
#              stay frozen, the passphrase must never reach the agent, and
#              `git commit -S` must sign. Works with and without the guard.
#   pinentry   pinentry-curses started by a gpg-agent outside the session,
#              GPG_TTY pointing at the session pts. With the guard and
#              /usr/bin/pinentry-curses on the exception list, the lock
#              reads "pinentry-curses (exception, for gpg-agent)" and
#              signing works; with the guard and no exception, pinentry
#              is refused the pts; without the guard, the broker finds
#              pinentry outside the session holding the pts and lights
#              the lock: "(outside the session, for gpg-agent)", agent
#              view frozen, the passphrase never reaches the agent.
#
# Rows: PASS, FAIL, GAP (documented open), SKIP. Exit 1 on FAIL.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
COTTY=${COTTY:-/usr/local/bin/cotty}
PROBE=${PROBE:-$HERE/../../bin/probe}
[ -x "$COTTY" ] || { echo "no cotty binary at $COTTY" >&2; exit 2; }
[ -x "$PROBE" ] || { echo "no probe binary at $PROBE" >&2; exit 2; }
command -v gpg >/dev/null || { echo "gpg is not installed" >&2; exit 2; }
RT=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
STATE=${XDG_STATE_HOME:-$HOME/.local/state}/cotty
W=$HOME/cotty-gpg/$(date +%Y%m%d-%H%M%S)
mkdir -p "$W"
chmod 700 "$W"
# The passphrase is also the secret the scripted person types at a lock.
PASS=COTTY-GPGPASS-$RANDOM$RANDOM$RANDOM
(umask 077 && echo "$PASS" >"$W/secret")
# shellcheck source=tests/attacks/session-lib.sh
. "$HERE/session-lib.sh"

PINENTRY=$(command -v pinentry-curses || true)
cleanup() {
	stop_sessions
	for g in "$W"/gnupg-*; do [ -d "$g" ] && GNUPGHOME=$g gpgconf --kill gpg-agent 2>/dev/null; done
	[ "$GUARD_STATE" = loaded ] && [ -n "${EXC_TOUCHED:-}" ] && exc_restore
}
trap cleanup EXIT

# gnupg_home NAME AGENTCONF GPGCONF: a GNUPGHOME with the test key (made
# once, then copied), the given gpg-agent.conf and gpg.conf lines.
KEYHOME=$W/gnupg-key
mkdir -m 700 "$KEYHOME"
GNUPGHOME=$KEYHOME gpg --batch -q --pinentry-mode loopback --passphrase "$PASS" \
	--quick-gen-key "cotty lab <lab@example.invalid>" ed25519 sign never 2>"$W/keygen.err" ||
	{ echo "key generation failed: $(cat "$W/keygen.err")" >&2; exit 2; }
FPR=$(GNUPGHOME=$KEYHOME gpg --list-keys --with-colons | awk -F: '/^fpr/ { print $10; exit }')
GNUPGHOME=$KEYHOME gpgconf --kill gpg-agent
gnupg_home() {
	local g=$W/gnupg-$1
	cp -a "$KEYHOME" "$g"
	rm -f "$g"/S.* "$g"/*.lock
	# No passphrase cache: every signature asks.
	printf '%s\n' "default-cache-ttl 0" "max-cache-ttl 0" "$2" >"$g/gpg-agent.conf"
	printf '%s\n' "$3" >"$g/gpg.conf"
	echo "$g"
}

# A repository to sign commits in.
REPO=$W/repo
git init -q "$REPO"
git -C "$REPO" config user.name "cotty lab"
git -C "$REPO" config user.email lab@example.invalid
git -C "$REPO" config user.signingkey "$FPR"
git -C "$REPO" config gpg.program gpg

start_session gpg$RANDOM

# sign_in_session LABEL GNUPGHOME CMD: the agent types CMD (with GNUPGHOME
# and GPG_TTY set) in the session; the person types the passphrase when
# the lock lights. Sets LOCK (the lock text, empty when none), EVRC and
# EVOUT (agent-events during the prompt), RES (the command's exit code),
# ATRC (with AGENT_TRY: the agent's typing attempt during the lock).
sign_in_session() {
	local label=$1 g=$2 cmd=$3 n
	rm -f "$W/$label.rc"
	n=$(locks)
	"$PROBE" agent-events "$ASOCK" 15 >"$W/$label.events" 2>&1 &
	local ev=$!
	sleep 1
	"$PROBE" agent-type "$ASOCK" "export GNUPGHOME=$g GPG_TTY=\$(tty); cd $REPO; timeout 25 $cmd >$W/$label.out 2>&1; echo \$? >$W/$label.rc" >/dev/null
	LOCK=$(lock_after "$n" 20)
	# With AGENT_TRY set, the agent tries to type while the lock is lit
	# (the person starts typing 200 ms after it lights, one key per 60 ms).
	ATRC=none
	if [ -n "${AGENT_TRY:-}" ] && [ -n "$LOCK" ]; then
		"$PROBE" agent-type "$ASOCK" "echo agent-typed-during-lock" >"$W/$label.agent-type" 2>&1
		ATRC=$?
	fi
	for _ in $(seq 300); do [ -s "$W/$label.rc" ] && break; sleep 0.1; done
	wait "$ev"
	EVRC=$?
	EVOUT=$(tr '\n' ' ' <"$W/$label.events" | cut -c1-120)
	RES=$(cat "$W/$label.rc" 2>/dev/null || echo none)
}

# events_row NAME: the agent-events verdict (exit 1: at most one change
# per prompt start and end; 0: one per key; 2: no prompt was ever seen).
events_row() {
	case $EVRC in
	1) row PASS "$1" "agent view frozen during the prompt: $EVOUT" ;;
	0) row FAIL "$1" "the agent saw the prompt key by key: $EVOUT" ;;
	*) row FAIL "$1" "agents never saw a secret prompt: $EVOUT" ;;
	esac
}

# --- loopback: gpg asks on its own terminal ---
GL=$(gnupg_home loopback "allow-loopback-pinentry" "pinentry-mode loopback")
sign_in_session loop-commit "$GL" "git commit -S --allow-empty -qm lab-signed-loopback"
if [ -n "$LOCK" ]; then row PASS gpg-loopback-lock "lock lit for git commit -S: $LOCK"; else row FAIL gpg-loopback-lock "no lock while gpg asked for the passphrase"; fi
events_row gpg-loopback-agent-frozen
if [ "$RES" = 0 ] && GNUPGHOME=$GL git -C "$REPO" verify-commit HEAD >/dev/null 2>&1; then
	row PASS gpg-loopback-commit-signed "git commit -S signed with the passphrase the person typed (verify-commit ok)"
else
	row FAIL gpg-loopback-commit-signed "commit exit $RES: $(tr '\n' ' ' <"$W/loop-commit.out" 2>/dev/null | cut -c1-120)"
fi
sign_in_session loop-clearsign "$GL" "sh -c 'echo lab | gpg --clearsign >$W/clear.asc'"
if [ -n "$LOCK" ] && [ "$RES" = 0 ]; then
	row PASS gpg-loopback-clearsign "gpg --clearsign: lock ($LOCK), signed"
else
	row FAIL gpg-loopback-clearsign "lock \"$LOCK\", exit $RES: $(tr '\n' ' ' <"$W/loop-clearsign.out" 2>/dev/null | cut -c1-100)"
fi
deny gpg-loopback-agent-reads-pass "$PROBE" agent-read "$ASOCK" "$PASS"

# --- pinentry-curses from a gpg-agent outside the session (GPG_TTY) ---
if [ -z "$PINENTRY" ]; then
	row SKIP gpg-pinentry "pinentry-curses is not installed"
else
	GP=$(gnupg_home pinentry "pinentry-program $PINENTRY" "")
	# Started here, outside the session and outside any agent.
	GNUPGHOME=$GP gpgconf --launch gpg-agent
	if [ "$GUARD_STATE" = loaded ]; then
		EXC_TOUCHED=1
		exc_save
		# No exception: the guard refuses pinentry the session pts.
		exc_set "# empty"
		sign_in_session pin-noexc "$GP" "git commit -S --allow-empty -qm lab-signed-noexc"
		if [ "$RES" != 0 ] && [ -z "$LOCK" ]; then
			row PASS gpg-pinentry-no-exception "refused without an exception (commit exit $RES: $(tr '\n' ' ' <"$W/pin-noexc.out" | cut -c1-80))"
		else
			row FAIL gpg-pinentry-no-exception "commit exit $RES, lock \"$LOCK\" without an exception"
		fi
		exc_set "$PINENTRY"
		if exc_listed "$PINENTRY"; then
			row PASS gpg-exception-loaded "the guard lists $PINENTRY"
		else
			row FAIL gpg-exception-loaded "the guard does not list $PINENTRY after the reload"
		fi
		sign_in_session pin-exc "$GP" "git commit -S --allow-empty -qm lab-signed-exception"
		case $LOCK in
		*"(exception, for gpg-agent)"*) row PASS gpg-pinentry-exception-lock "lock: $LOCK" ;;
		*) row FAIL gpg-pinentry-exception-lock "lock \"$LOCK\", want pinentry-curses (exception, for gpg-agent)" ;;
		esac
		events_row gpg-pinentry-agent-frozen
		if [ "$RES" = 0 ] && GNUPGHOME=$GP git -C "$REPO" verify-commit HEAD >/dev/null 2>&1; then
			row PASS gpg-pinentry-commit-signed "git commit -S signed through pinentry-curses"
		else
			row FAIL gpg-pinentry-commit-signed "commit exit $RES: $(tr '\n' ' ' <"$W/pin-exc.out" 2>/dev/null | cut -c1-120)"
		fi
		deny gpg-pinentry-agent-reads-pass "$PROBE" agent-read "$ASOCK" "$PASS"
		if sudo -n journalctl -u cotty-guard --since "-5min" --no-pager 2>/dev/null | grep -q "exception used: .*$PINENTRY"; then
			row PASS gpg-exception-logged "the guard logged the exception use"
		else
			row FAIL gpg-exception-logged "no 'exception used' line in the guard's journal"
		fi
		if sudo -n grep -q '"guard.exception"' /var/log/cotty/guard.audit.jsonl 2>/dev/null; then
			row PASS gpg-exception-audited "guard.exception in the guard's audit log"
		else
			row FAIL gpg-exception-audited "no guard.exception record in the guard's audit log"
		fi
		check gpg-secret-start-audited "the session audit log has the exception prompt" grep -q '"exception":true' "$STATE/audit.jsonl"
	else
		AGENT_TRY=1 sign_in_session pin-noguard "$GP" "git commit -S --allow-empty -qm lab-signed-noguard"
		case $LOCK in
		*"(outside the session, for gpg-agent)"*) row PASS gpg-pinentry-no-guard "lock: $LOCK" ;;
		"") row FAIL gpg-pinentry-no-guard "without the guard no lock lit for pinentry-curses (commit exit $RES)" ;;
		*) row FAIL gpg-pinentry-no-guard "lock \"$LOCK\", want pinentry-curses (outside the session, for gpg-agent)" ;;
		esac
		events_row gpg-pinentry-no-guard-agent-frozen
		if [ "$RES" = 0 ] && GNUPGHOME=$GP git -C "$REPO" verify-commit HEAD >/dev/null 2>&1; then
			row PASS gpg-pinentry-no-guard-signed "git commit -S signed through pinentry-curses (outside the session)"
		else
			row FAIL gpg-pinentry-no-guard-signed "commit exit $RES: $(tr '\n' ' ' <"$W/pin-noguard.out" 2>/dev/null | cut -c1-120)"
		fi
		deny gpg-pinentry-no-guard-agent-reads-pass "$PROBE" agent-read "$ASOCK" "$PASS"
		if [ "$ATRC" != none ] && [ "$ATRC" != 0 ] && grep -qi secret "$W/pin-noguard.agent-type"; then
			row PASS gpg-pinentry-no-guard-agent-input "agent input refused during the lock: $(tr '\n' ' ' <"$W/pin-noguard.agent-type" | cut -c1-100)"
		else
			row FAIL gpg-pinentry-no-guard-agent-input "agent input during the lock: exit $ATRC $(tr '\n' ' ' <"$W/pin-noguard.agent-type" 2>/dev/null | cut -c1-100)"
		fi
	fi
fi
if grep -rqF "$PASS" "$STATE" "$RT/cotty" 2>/dev/null; then
	row FAIL gpg-pass-in-logs "the passphrase is in $(grep -rlF "$PASS" "$STATE" "$RT/cotty" | head -1)"
else
	row PASS gpg-pass-in-logs "the passphrase is in no audit or broker log"
fi

summary "gpg prompts, guard $GUARD_STATE"
