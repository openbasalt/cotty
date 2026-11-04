#!/usr/bin/env bash
# Escape matrix for `cotty agent` (layer 2). Run it as an unprivileged
# user in a throwaway VM (tests/lab/vm.sh matrix NAME), never on a machine
# you care about: it creates fake keys in ~/.ssh and starts agents and
# listeners.
#
# Outside the confinement it sets up targets: a fake SSH key, a process
# whose environment holds a marker, a pty standing for the person's
# terminal, real ssh-agent, gpg-agent, tmux and screen servers, and fake
# listeners (kitty, wezterm, X11 and D-Bus, pathname and abstract) that log
# any connection. Then it runs tests/attacks/inside.sh confined, with the
# person's pty inherited on fd 5, and checks from outside what the inside
# cannot see (listener log, files in the real home, the agent's scope).
#
# Output: one PASS/FAIL/SKIP/GAP line per check and a summary. GAP is an
# attempt that got through where docs/confinement.md lists it as open
# (a pathname socket below Landlock ABI 9). A FAIL whose detail starts
# with "[open: ITEM]" is a weakness of the final review that is not fixed
# yet. Before Landlock ABI 6 abstract sockets read GAP as well (the run
# uses --allow-abstract-sockets after checking the refusal). Exit 1 when
# any check fails.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
COTTY=${COTTY:-$HERE/../../bin/cotty}
PROBE=${PROBE:-$HERE/../../bin/probe}
[ -x "$COTTY" ] || { echo "no cotty binary at $COTTY" >&2; exit 2; }
[ -x "$PROBE" ] || { echo "no probe binary at $PROBE" >&2; exit 2; }
RT=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}

W=$HOME/cotty-matrix/$(date +%Y%m%d-%H%M%S)
P=$W/project
T=$W/tools
mkdir -p "$P" "$T" "$RT/cotty-lab"
cp "$HERE/inside.sh" "$PROBE" "$T/"
MARKER=COTTY-LAB-FAKE-$RANDOM$RANDOM

cleanup() {
	for p in ${PIDS:-}; do kill "$p" 2>/dev/null; done
	tmux -L cottylab kill-server 2>/dev/null
	screen -S cottylab -X quit >/dev/null 2>&1
	[ -n "${SSH_AGENT_PID_LAB:-}" ] && kill "$SSH_AGENT_PID_LAB" 2>/dev/null
}
trap cleanup EXIT

# --- targets ---
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
printf '%s\n' "$MARKER" >"$HOME/.ssh/cotty_lab_fake"
printf 'echo %s\n' "$MARKER" >>"$HOME/.bash_history"
rm -f "$HOME/cotty-lab-escape"

env COTTY_LAB_MARKER="$MARKER" sleep 900 &
VICTIM_PID=$!
PIDS="$VICTIM_PID"

"$PROBE" hold-pty "$W/pts.env" &
PTS_HOLDER_PID=$!
PIDS="$PIDS $PTS_HOLDER_PID"

mkdir -p /tmp/.X11-unix 2>/dev/null
LISTEN=("$RT/cotty-lab/ssh-agent.sock" /tmp/kitty-cottylab @kitty-cottylab "$RT/wezterm/gui-sock-cottylab"
	@/tmp/dbus-cottylab "$RT/cotty-lab/bus")
if [ -w /tmp/.X11-unix ]; then LISTEN+=(/tmp/.X11-unix/X42); fi
LISTEN+=(@/tmp/.X11-unix/X42)
"$PROBE" listen --log "$W/listen.log" "${LISTEN[@]}" >"$W/listen.out" 2>&1 &
PIDS="$PIDS $!"

REAL_SSH=$RT/cotty-lab/real-ssh-agent.sock
rm -f "$REAL_SSH"
if command -v ssh-agent >/dev/null; then
	eval "$(ssh-agent -a "$REAL_SSH" -s)" >/dev/null
	SSH_AGENT_PID_LAB=$SSH_AGENT_PID
	unset SSH_AGENT_PID
fi
GPG_SOCK=""
if command -v gpgconf >/dev/null; then
	gpgconf --launch gpg-agent 2>/dev/null
	GPG_SOCK=$(gpgconf --list-dirs agent-socket 2>/dev/null)
fi
TMUX_SOCK=""
if command -v tmux >/dev/null; then
	tmux -L cottylab new-session -d 'sleep 900' && TMUX_SOCK=$(tmux -L cottylab display -p '#{socket_path}')
fi
SCREEN_SOCK=""
if command -v screen >/dev/null; then
	screen -dmS cottylab sleep 900
	sleep 0.5
	SCREEN_SOCK=$(find /run/screen /var/run/screen "$HOME/.screen" -name '*.cottylab' 2>/dev/null | head -1)
fi
BOOT_FILE=$(find /boot -maxdepth 2 -type f -readable 2>/dev/null | head -1)
PERSON_CGROUP=$(sed -n 's/^0:://p' /proc/self/cgroup)
DOCKER_SOCK=""
[ -S /var/run/docker.sock ] && DOCKER_SOCK=/var/run/docker.sock

for _ in $(seq 50); do [ -s "$W/pts.env" ] && grep -q ready "$W/listen.out" 2>/dev/null && break; sleep 0.1; done
# shellcheck disable=SC1091
. "$W/pts.env"

# A socket in the project created outside: the mount view cannot hide it,
# only Landlock ABI 9 (resolve unix) stops the connect.
LL_ABI=$("$COTTY" doctor --json | sed -n 's/.*"value": "ABI \([0-9]*\)".*/\1/p' | head -1)
"$PROBE" listen --log "$W/project-sock.log" "$P/outside.sock" >/dev/null 2>&1 &
PIDS="$PIDS $!"

# The project: a git repository with a pre-commit hook the agent must not
# change, and everything else git runs with the person's rights: a
# hooksPath in the work tree that does not exist yet (Husky's default), an
# include of a work tree file that does not exist yet, a filter script, a
# submodule git directory, a linked worktree and a nested repository, plus
# pre-commit and lefthook configuration (hook managers run what it names).
(
	cd "$P" && git init -q && git config user.email lab@example.invalid && git config user.name lab &&
		printf '#!/bin/sh\nexit 0\n' >.git/hooks/pre-commit && chmod +x .git/hooks/pre-commit &&
		echo "# lab" >README.md && git add README.md && git commit -qm init &&
		git config core.hooksPath .husky/_ && git config include.path ../lab.gitconfig &&
		mkdir -p scripts && printf '#!/bin/sh\ncat\n' >scripts/clean.sh && chmod +x scripts/clean.sh &&
		git config filter.lab.clean ./scripts/clean.sh &&
		mkdir -p .git/modules/sub/objects .git/modules/sub/hooks && echo 'ref: refs/heads/main' >.git/modules/sub/HEAD &&
		printf '[core]\n\tworktree = ../../../sub\n' >.git/modules/sub/config &&
		git worktree add -q ../wt 2>/dev/null &&
		git init -q vendored && rm -rf .husky &&
		printf 'repos: []\n' >.pre-commit-config.yaml && printf '{}\n' >lefthook.yml
) || { echo "cannot set up the lab project" >&2; exit 2; }
git config --global user.email >/dev/null 2>&1 || git config --global user.email lab@example.invalid
git config --global user.name >/dev/null 2>&1 || git config --global user.name lab
HOOK_SUM=$(sha256sum "$P/.git/hooks/pre-commit" | cut -d' ' -f1)
GIT_INO=$(stat -c %i "$P/.git")

# The sockets that exist outside: a connect row on a socket that does not
# exist proves nothing, so inside.sh skips those (abstract names as @NAME).
OUTSIDE_SOCKS=""
for s in "$RT/bus" "$RT/systemd/private" /run/dbus/system_bus_socket "$REAL_SSH" "$RT/cotty-lab/ssh-agent.sock" \
	"$RT/cotty-lab/bus" "$GPG_SOCK" "$DOCKER_SOCK" "$TMUX_SOCK" "$SCREEN_SOCK" /tmp/kitty-cottylab \
	"$RT/wezterm/gui-sock-cottylab" /tmp/.X11-unix/X42 "$P/outside.sock"; do
	[ -n "$s" ] && [ -S "$s" ] && OUTSIDE_SOCKS="$OUTSIDE_SOCKS $s"
done
for a in /tmp/dbus-cottylab kitty-cottylab /tmp/.X11-unix/X42; do
	grep -q " @$a\$" /proc/net/unix && OUTSIDE_SOCKS="$OUTSIDE_SOCKS @$a"
done
SUB_SUM=$(sha256sum "$P/.git/modules/sub/config" | cut -d' ' -f1)

# A pathname socket in a known socket directory under /var (incus, LXD and
# MySQL keep theirs there): hidden from the agent on every Landlock ABI.
VAR_SOCK=""
if sudo -n true 2>/dev/null; then
	sudo mkdir -p /var/lib/incus && sudo chown "$(id -u)" /var/lib/incus && VAR_SOCK=/var/lib/incus/unix.socket
	"$PROBE" listen --log "$W/var-sock.log" "$VAR_SOCK" >/dev/null 2>&1 &
	PIDS="$PIDS $!"
fi
# Before Landlock ABI 6 abstract sockets are reachable: cotty agent must
# refuse while one that matters listens (the fake X11 one above does),
# unless told otherwise.
EXTRA_FLAGS=()
if [ "${LL_ABI:-0}" -lt 6 ]; then
	EXTRA_FLAGS=(--allow-abstract-sockets)
fi

cat >"$P/targets.env" <<EOF
MARKER=$MARKER
RT=$RT
VICTIM_PID=$VICTIM_PID
PERSON_PTS=$PERSON_PTS
PERSON_PTS_DEV=$PERSON_PTS_DEV
REAL_SSH=$REAL_SSH
GPG_SOCK=$GPG_SOCK
TMUX_SOCK=$TMUX_SOCK
SCREEN_SOCK=$SCREEN_SOCK
BOOT_FILE=$BOOT_FILE
PERSON_CGROUP=$PERSON_CGROUP
DOCKER_SOCK=$DOCKER_SOCK
VAR_SOCK=$VAR_SOCK
PROJECT=$P
PROBE=$T/probe
LL_ABI=${LL_ABI:-0}
PTS_HOLDER_PID=$PTS_HOLDER_PID
OUTSIDE_SOCKS="$OUTSIDE_SOCKS"
EOF

# Watch for the agent's own scope while it runs.
(
	while :; do
		systemctl --user list-units --type=scope --no-legend 'cotty-agent-*' 2>/dev/null
		sleep 0.5
	done
) >"$W/scopes.log" &
PIDS="$PIDS $!"

# --- the confined run; the person's pty is inherited on fd 5 ---
# Tokens in the environment the agent must not inherit.
HF_TOKEN=$MARKER DATABASE_URL="postgres-$MARKER.db.invalid" STRIPE_SECRET_KEY=$MARKER \
	"$COTTY" agent --profile generic --pty always --project "$P" --ro "$T" "${EXTRA_FLAGS[@]}" -- \
	bash "$T/inside.sh" "$P/targets.env" 5<>"$PERSON_PTS" >"$W/inside.raw" 2>&1 </dev/null
RC=$?
tr -d '\r' <"$W/inside.raw" >"$W/inside.out"

# --- report ---
grep -E '^cotty agent' "$W/inside.out"
ROWS=$(grep -E '^(PASS|FAIL|SKIP|GAP) ' "$W/inside.out")
row() { ROWS+=$'\n'"$(printf '%-4s  %-26s %s' "$1" "$2" "$3")"; }
if [ "${LL_ABI:-0}" -lt 6 ] && [ -s "$W/listen.log" ] && ! grep -qv 'connection on @' "$W/listen.log"; then
	row GAP outside-listeners "abstract sockets reached on Landlock ABI $LL_ABI < 6 (documented): $(tr '\n' ';' <"$W/listen.log")"
elif [ -s "$W/listen.log" ]; then
	row FAIL outside-listeners "$(tr '\n' ';' <"$W/listen.log")"
else
	row PASS outside-listeners "no connection reached any fake socket outside (${#LISTEN[@]} listeners)"
fi
if [ -e "$HOME/cotty-lab-escape" ]; then
	row FAIL home-write-persisted "a file written to ~ inside reached the real home"
else
	row PASS home-write-persisted "files written to ~ inside stayed in the private tmpfs"
fi
if [ "$(sha256sum "$P/.git/hooks/pre-commit" | cut -d' ' -f1)" = "$HOOK_SUM" ]; then
	row PASS git-hook-unchanged "the project's pre-commit hook is unchanged"
else
	row FAIL git-hook-unchanged "the project's pre-commit hook was changed"
fi
# Without layer 2 (guard.sh none and guard-only, which add NO_LAYER2 to
# the targets) a layer 2 failure is the baseline, not an open item, and
# there is no relay.
NO_LAYER2=$(sed -n 's/^NO_LAYER2=//p' "$P/targets.env")
# B7: the agent must not be able to rename .git and plant a hook in a
# copy.
if [ "$(stat -c %i "$P/.git")" = "$GIT_INO" ] && [ ! -e "$P/.git/hooks/post-checkout" ]; then
	row PASS git-dir-unchanged "the project's .git is the original directory, no hook was added"
else
	row FAIL git-dir-unchanged ".git was replaced (inode $GIT_INO -> $(stat -c %i "$P/.git")) or a hook added (post-checkout: $([ -e "$P/.git/hooks/post-checkout" ] && echo present || echo absent))"
fi
# S13: control sequences printed inside must not reach the person's
# terminal through the relay; the window title must.
if [ "$NO_LAYER2" = 1 ]; then
	row SKIP relay-osc52 "no cotty agent, no relay"
	row SKIP relay-kitty-rc "no cotty agent, no relay"
	row SKIP relay-osc5113 "no cotty agent, no relay"
	row SKIP relay-title-kept "no cotty agent, no relay"
	row SKIP relay-utf8-c1 "no cotty agent, no relay"
else
	# N12: the OSC 52 payloads behind UTF-8 encoded C1 controls (or ESC
	# plus a C1 byte) must not come through.
	if grep -aqF -e "$(printf COTTY-LAB-U8C1 | base64)" -e "$(printf COTTY-LAB-ESCC1 | base64)" "$W/inside.raw"; then
		row FAIL relay-utf8-c1 "an OSC 52 behind a UTF-8 encoded C1 introducer passed the relay"
	else
		row PASS relay-utf8-c1 "no OSC 52 behind UTF-8 encoded C1 controls passed the relay"
	fi
	if grep -aq $'\e]52;' "$W/inside.raw"; then
		row FAIL relay-osc52 "an OSC 52 clipboard write passed the relay to the person's terminal"
	else
		row PASS relay-osc52 "no OSC 52 sequence passed the relay"
	fi
	if grep -aq 'kitty-cmd' "$W/inside.raw"; then
		row FAIL relay-kitty-rc "a kitty remote control command passed the relay to the person's terminal"
	else
		row PASS relay-kitty-rc "no kitty remote control sequence passed the relay"
	fi
	if grep -aq $'\e]5113;' "$W/inside.raw"; then
		row FAIL relay-osc5113 "an OSC 5113 file transfer passed the relay"
	else
		row PASS relay-osc5113 "no OSC 5113 sequence passed the relay"
	fi
	if grep -aq $'\e]0;cotty-lab-title' "$W/inside.raw"; then
		row PASS relay-title-kept "the window title (OSC 0) passed"
	else
		row FAIL relay-title-kept "the allowed title sequence did not come through"
	fi
fi
if grep -q 'cotty-agent-' "$W/scopes.log"; then
	row PASS own-scope "the agent ran in $(grep -o 'cotty-agent-[a-f0-9]*\.scope' "$W/scopes.log" | head -1)"
else
	row FAIL own-scope "no cotty-agent-*.scope seen while the agent ran"
fi
if ls "$P"/core* "$P"/tmpcore/core* >/dev/null 2>&1; then
	row FAIL core-files "core files in the project"
else
	row PASS core-files "no core file in the project"
fi
if [ -n "$VAR_SOCK" ]; then
	if [ -s "$W/var-sock.log" ]; then row FAIL var-socket-dir "a connection reached $VAR_SOCK"; else row PASS var-socket-dir "$VAR_SOCK unreachable"; fi
fi
if [ "$(sha256sum "$P/.git/modules/sub/config" | cut -d' ' -f1)" != "$SUB_SUM" ] || [ -e "$P/.git/commondir" ] || [ -e "$P/.git.old" ]; then
	row FAIL git-state-outside "the project's git directory was changed: $(ls -a "$P" "$P/.git" | tr '\n' ' ')"
else
	row PASS git-state-outside "no commondir, no renamed .git, submodule config unchanged"
fi
if [ -e "$P/.husky/_/pre-commit" ] || [ -e "$P/.husky/pre-commit" ] || [ -s "$P/lab.gitconfig" ] ||
	[ "$(cat "$P/.pre-commit-config.yaml" "$P/lefthook.yml")" != "$(printf 'repos: []\n{}')" ]; then
	row FAIL git-planted-outside "a hook or an included config was planted"
else
	row PASS git-planted-outside "no hook in .husky, the included config is empty, hook manager configuration unchanged"
fi

# The runs below start cotty agent with other commands: not under
# guard.sh, whose wrapper stands in for cotty agent with inside.sh only.
if [ -n "$(sed -n 's/^GUARD_MODE=//p' "$P/targets.env")" ]; then
	row SKIP layer2-extra-runs "under guard.sh: commondir, git init, socket roots and ABI 6 runs are in run.sh alone"
else
# A second run: creating .git/commondir (it would point the person's git
# at a config the agent wrote) stops the agent and is undone; a nested
# repository the agent creates is reported.
out=$("$COTTY" agent --profile generic --project "$P" "${EXTRA_FLAGS[@]}" -- sh -c \
	"cp -r .git/objects .git/refs .git/HEAD evil/ 2>/dev/null; mkdir -p evil && printf '[core]\n\tfsmonitor = \"touch $HOME/cotty-lab-escape; false\"\n' >evil/config; echo ../evil >.git/commondir; sleep 5; echo NOT-STOPPED" 2>&1 </dev/null)
rc=$?
if [ $rc -ne 0 ] && [ ! -e "$P/.git/commondir" ] && ! echo "$out" | grep -q NOT-STOPPED && echo "$out" | grep -q commondir; then
	row PASS git-commondir-tripwire "agent stopped (exit $rc), commondir removed"
else
	row FAIL git-commondir-tripwire "exit $rc, commondir $(test -e "$P/.git/commondir" && echo present || echo absent): $(echo "$out" | tr '\n' ' ' | cut -c1-160)"
fi
(cd "$P" && git status >/dev/null 2>&1)
if [ -e "$HOME/cotty-lab-escape" ]; then
	row FAIL git-commondir-effect "git status outside ran the planted fsmonitor"
	rm -f "$HOME/cotty-lab-escape"
else
	row PASS git-commondir-effect "git status outside ran nothing planted"
fi
rm -rf "$P/evil"
out=$("$COTTY" agent --profile generic --project "$P" "${EXTRA_FLAGS[@]}" -- sh -c 'mkdir -p n2 && cd n2 && git init -q && echo ok' 2>&1 </dev/null)
if echo "$out" | grep -q 'created git repositories'; then
	row PASS git-new-nested-reported "a repository created inside is reported at exit"
else
	row FAIL git-new-nested-reported "$(echo "$out" | tr '\n' ' ' | cut -c1-160)"
fi
rm -rf "$P/n2"

# A project without .git: the agent cannot `git init` there, and the
# empty .git cotty puts in place is gone afterwards.
NP=$W/nogit
mkdir -p "$NP"
out=$("$COTTY" agent --profile generic --project "$NP" "${EXTRA_FLAGS[@]}" -- sh -c 'git init -q 2>&1; test -f .git/HEAD && echo INIT-OK; ls -A .git' 2>&1 </dev/null)
if ! echo "$out" | grep -q INIT-OK && [ ! -e "$NP/.git" ]; then
	row PASS git-init-refused "git init failed inside, no .git left outside"
else
	row FAIL git-init-refused "$(echo "$out" | tr '\n' ' ' | cut -c1-120); outside: $(ls -A "$NP")"
fi

# Paths that hold sockets are refused as project, --ro, --rw, --agent-dir.
for args in "--project /tmp" "--project $RT" "--ro $RT" "--rw /run" "--ro /dev/shm" "--project /var" "--agent-dir $RT" "--project /tmp/.X11-unix"; do
	# shellcheck disable=SC2086
	if "$COTTY" agent --profile generic --project "$P" $args -- true >/dev/null 2>&1 </dev/null; then
		row FAIL socket-roots-refused "accepted: $args"
	else
		row PASS socket-roots-refused "refused: $args"
	fi
done
if [ "${LL_ABI:-0}" -lt 6 ]; then
	if out=$("$COTTY" agent --profile generic --project "$P" -- true 2>&1 </dev/null); then
		row FAIL abstract-socket-refusal "started on ABI $LL_ABI with an abstract X11 socket listening"
	elif echo "$out" | grep -q 'abstract'; then
		row PASS abstract-socket-refusal "refused on ABI $LL_ABI: abstract X11 socket listening"
	else
		row FAIL abstract-socket-refusal "$(echo "$out" | tail -1)"
	fi
fi
fi

if grep -q '^DONE ' "$W/inside.out"; then
	row PASS inside-completed "inside.sh ran to the end (cotty agent exit $RC)"
else
	row FAIL inside-completed "inside.sh did not finish (cotty agent exit $RC); see $W/inside.out"
fi

echo
echo "escape matrix, $(uname -r), $(. /etc/os-release && echo "$PRETTY_NAME"), landlock ABI $("$COTTY" doctor --json | sed -n 's/.*"value": "ABI \([0-9]*\)".*/\1/p' | head -1)"
printf '%-4s  %-26s %s\n' RES CHECK DETAIL
echo "$ROWS" | sed '/^$/d'
PASS=$(echo "$ROWS" | grep -c '^PASS')
FAIL=$(echo "$ROWS" | grep -c '^FAIL')
KNOWN=$(echo "$ROWS" | grep -c '^FAIL .*\[open: ')
GAP=$(echo "$ROWS" | grep -c '^GAP')
SKIP=$(echo "$ROWS" | grep -c '^SKIP')
echo
echo "summary: $PASS pass, $FAIL fail ($KNOWN of them open review items), $GAP gap (documented), $SKIP skip (work dir $W)"
[ "$FAIL" -eq 0 ]
