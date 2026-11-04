#!/usr/bin/env bash
# Escape matrix with cotty-guard (layer 3). Run it in a throwaway VM as an
# unprivileged user (tests/lab/vm.sh guard NAME, then this script over
# ssh), never on a host: it needs the guard's BPF programs loaded.
#
#   guard.sh guard-only   the agent runs WITHOUT layer 2 (no namespaces,
#                         Landlock or seccomp) in a cotty-agent-* scope
#                         registered with the guard: shows what the guard
#                         alone blocks
#   guard.sh both         `cotty agent` (layer 2) with the guard running:
#                         the launcher registers the agent itself
#   guard.sh layer2       `cotty agent` with the guard stopped (the
#                         baseline of tests/attacks/run.sh)
#   guard.sh none         no layer 2 and the guard stopped: the agent runs
#                         as a plain process in a scope (the baseline that
#                         shows what guard-only adds). The guard must be
#                         stopped: with it running, the person's pts
#                         would still be protected and a successful
#                         register-again would put every later row under
#                         the guard, so the baseline would not be one.
#
# Every mode reuses tests/attacks/run.sh (targets, inside.sh, outside
# checks) through a wrapper standing in for `cotty agent`, and adds the
# guard-inside.sh rows (guard socket abuse, the protected person pts, a
# file capability exec). In the guard modes a real cotty session is
# started and its pts is the protected one the rows try (only a
# registered broker can protect a pts). After the run it lists the guard's denials from
# the audit log by hook.
set -u

MODE=${1:-}
case $MODE in guard-only | both | layer2 | none) ;; *)
	echo "usage: guard.sh guard-only|both|layer2|none" >&2
	exit 2
	;;
esac
HERE=$(cd "$(dirname "$0")" && pwd)
COTTY=${COTTY:-$HERE/../../bin/cotty}
PROBE=${PROBE:-$HERE/../../bin/probe}
GUARDPROBE=${GUARDPROBE:-$HERE/../../bin/guardprobe}
AUDIT=${GUARD_AUDIT:-/var/log/cotty/guard.audit.jsonl}
for b in "$COTTY" "$PROBE" "$GUARDPROBE"; do [ -x "$b" ] || { echo "missing $b" >&2; exit 2; }; done

case $MODE in
layer2 | none)
	if "$GUARDPROBE" status >/dev/null 2>&1; then
		echo "guard.sh: cotty-guard is running; stop it for the $MODE baseline" >&2
		exit 2
	fi
	;;
guard-only | both)
	if ! "$GUARDPROBE" status; then
		echo "guard.sh: cotty-guard is not running" >&2
		exit 2
	fi
	;;
esac
echo "mode: $MODE"
# The cotty runtime directory and the agent endpoint directory exist
# whenever a session was ever shared; make them so the plant rows apply.
RTD=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
mkdir -p -m 0700 "$RTD/cotty" "$RTD/cotty/agent"

WRAP=$(mktemp -d "$HOME/cotty-guard-wrap.XXXXXX")
trap 'rm -rf "$WRAP"' EXIT
# The wrapper replaces `cotty agent ... -- bash T/inside.sh TARGETS`.
cat >"$WRAP/cotty" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = agent ] || exec "$REAL_COTTY" "$@"
args=("$@")
for i in "${!args[@]}"; do [ "${args[$i]}" = -- ] && break; done
pre=("${args[@]:0:$i}")
cmd=("${args[@]:$((i + 1))}")
targets=${cmd[-1]}
T=$(dirname "${cmd[1]}")
cp "$GUARD_INSIDE" "$GUARDPROBE" "$T/"
printf '#!/bin/sh\nbash "%s/inside.sh" "$1"\nbash "%s/guard-inside.sh" "$1"\n' "$T" "$T" >"$T/guard-run.sh"
# shellcheck disable=SC1090
. "$targets"
# A real cotty session: its pts is the protected one the guard rows try
# (only a registered broker can protect a pts, review N2). Its shell holds
# the pts for the pidfd_getfd row.
RTD0=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
gs=""
if [ "$GUARD_MODE" = guard-only ] || [ "$GUARD_MODE" = both ]; then
	gs=gm$$
	"$REAL_PROBE" in-pty 30 "reattach code" "$REAL_COTTY" new -d --name "$gs" -- bash --norc --noprofile >/dev/null 2>&1
	gpts=$(sed -n 's/.*"pts":"\([^"]*\)".*/\1/p' "$RTD0/cotty/$gs.json" 2>/dev/null)
	gbroker=$(sed -n 's/.*"broker_pid":\([0-9]*\).*/\1/p' "$RTD0/cotty/$gs.json" 2>/dev/null)
	if [ -n "$gpts" ]; then
		echo "SESSION_PTS=$gpts" >>"$targets"
		echo "SESSION_PTS_DEV=$(stat -c %d "$gpts")" >>"$targets"
		echo "SESSION_SHELL_PID=$(pgrep -P "$gbroker" | head -1)" >>"$targets"
	fi
fi
echo "PERSON_PTS_PROTECTED=0" >>"$targets"
echo "GUARD_MODE=$GUARD_MODE" >>"$targets"
case $GUARD_MODE in none | guard-only) echo NO_LAYER2=1 >>"$targets" ;; esac
# Victims for the rows added after the review (guard-inside.sh): a cgroup
# of the person (a stand-in for a broker's), a plain process of the
# person, and a socket of the person in the runtime directory.
RTD=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
mkdir -p "$RTD/cotty" "$RTD/cotty-lab"
vunit=cotty-lab-victim-$$
systemd-run --user --quiet --collect --unit="$vunit" sleep 900 2>/dev/null &&
	echo "VICTIM_CG=/sys/fs/cgroup$(systemctl --user show -p ControlGroup --value "$vunit.service")" >>"$targets"
sleep 900 &
vpid=$!
echo "VICTIM_PID=$vpid" >>"$targets"
"$PROBE" listen --log "$targets.rename.log" "$RTD/cotty-lab/rename.sock" >/dev/null 2>&1 &
lpid=$!
for _ in $(seq 30); do [ -S "$RTD/cotty-lab/rename.sock" ] && break; sleep 0.1; done
echo "RENAME_SOCK=$RTD/cotty-lab/rename.sock" >>"$targets"
rc=0
case $GUARD_MODE in
guard-only)
	cd "$PROJECT" || exit 1
	echo "cotty agent (guard-only test mode): no layer 2, registered with the guard"
	systemd-run --user --scope --quiet --collect --unit="cotty-agent-g$$" -- \
		"$GUARDPROBE" run-registered --allow "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/cotty/agent" \
		--guard "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/cotty" -- \
		bash "$T/guard-run.sh" "$targets" || rc=$?
	;;
both | layer2)
	"$REAL_COTTY" "${pre[@]}" -- bash "$T/guard-run.sh" "$targets" || rc=$?
	;;
none)
	cd "$PROJECT" || exit 1
	echo "cotty agent (unconfined baseline): no layer 2, not registered"
	systemd-run --user --scope --quiet --collect --unit="cotty-agent-n$$" -- \
		bash "$T/guard-run.sh" "$targets" || rc=$?
	;;
esac
[ -n "$gs" ] && kill "$(sed -n 's/.*"broker_pid":\([0-9]*\).*/\1/p' "$RTD0/cotty/$gs.json" 2>/dev/null)" 2>/dev/null
kill "$vpid" "$lpid" 2>/dev/null
systemctl --user stop "$vunit.service" 2>/dev/null
exit $rc
EOF
chmod +x "$WRAP/cotty"

START=$(date -u +%Y-%m-%dT%H:%M:%S)
export REAL_COTTY=$COTTY REAL_PROBE=$PROBE GUARDPROBE GUARD_MODE=$MODE GUARD_INSIDE=$HERE/guard-inside.sh
COTTY=$WRAP/cotty PROBE=$PROBE bash "$HERE/run.sh"
RC=$?

echo
echo "guard denials during the run (audit log $AUDIT, by hook):"
if sudo -n test -r "$AUDIT" 2>/dev/null; then
	sudo -n cat "$AUDIT" | awk -v s="$START" -F'"time":"' '{ split($2, a, "\""); if (a[1] >= s) print }' |
		grep -o '"hook":"[a-z_]*"' | sort | uniq -c | sort -rn
else
	echo "  (audit log not readable without sudo)"
fi
"$GUARDPROBE" status
exit $RC
