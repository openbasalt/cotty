#!/usr/bin/env bash
# Runs confined (started by tests/attacks/run.sh through `cotty agent`).
# Every "deny" row is an escape attempt that must fail; every "allow" row
# is ordinary agent work that must succeed. Rows print as
# PASS|FAIL|SKIP|GAP NAME DETAIL (GAP: open at this level and documented
# as such). Targets come from the file $1.
#
# Rows for a weakness the final review found and that is not fixed yet
# carry the review item: when such a row fails, its detail starts with
# "[open: ITEM]". They are expected to fail until that fix lands.
set -u
# shellcheck disable=SC1090
. "$1"
cd "$PROJECT" || exit 1
# The agent's own terminal, read before any redirection.
OWN_TTY=$(tty)

# OPEN: the review item of the next row, if it is a known open weakness.
OPEN=""
row() {
	local d=$3
	# Without layer 2 (guard.sh none and guard-only) every layer 2 row is
	# a baseline, not an open item.
	[ "$1" = FAIL ] && [ -n "$OPEN" ] && [ "${NO_LAYER2:-0}" != 1 ] && d="[open: $OPEN] $d"
	OPEN=""
	printf '%-4s  %-26s %s\n' "$1" "$2" "$d"
}
# known_open ITEM: mark the next row as a known open weakness (review ITEM).
known_open() { OPEN=$1; }

# deny NAME CMD...: the command must fail. probe exits 1 when denied,
# 0 when it got through, 2 when the attempt does not apply. Exit 127
# (command not found) proves nothing: SKIP.
deny() {
	local name=$1 out rc
	shift
	out=$(timeout 20 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-110)
	case $rc in
	0) row FAIL "$name" "ESCAPED: $out" ;;
	2) [ "$1" = "$PROBE" ] && row SKIP "$name" "$out" || row PASS "$name" "denied: $out" ;;
	127) row SKIP "$name" "command not found, nothing tried: $out" ;;
	*) row PASS "$name" "denied: $out" ;;
	esac
}

# deny_sock NAME SOCKET CMD...: as deny, for an attempt on a socket that
# must exist outside (run.sh lists the ones that do in OUTSIDE_SOCKS);
# a connect to a socket that does not exist proves nothing.
deny_sock() {
	local name=$1 sock=$2
	shift 2
	case " ${OUTSIDE_SOCKS:-} " in
	*" $sock "*) deny "$name" "$@" ;;
	*) OPEN=""; row SKIP "$name" "target $sock absent outside, nothing to reach" ;;
	esac
}

# allow NAME CMD...: the command must succeed.
allow() {
	local name=$1 out rc
	shift
	out=$(timeout 300 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tail -2 | tr '\n' ' ' | cut -c1-110)
	if [ $rc -eq 0 ]; then row PASS "$name" "ok $out"; else row FAIL "$name" "exit $rc: $out"; fi
}

skip_if_empty() { [ -n "$2" ] || { row SKIP "$1" "target not present on this host"; return 1; }; }

# gap NAME WHY CMD...: an escape the docs list as open on this kernel. It
# reads GAP when it gets through and PASS when it is denied anyway.
gap() {
	local name=$1 why=$2 out rc
	shift 2
	out=$(timeout 20 "$@" 2>&1 </dev/null)
	rc=$?
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-90)
	case $rc in
	0) row GAP "$name" "reachable ($why): $out" ;;
	2) row SKIP "$name" "$out" ;;
	*) row PASS "$name" "denied: $out" ;;
	esac
}

# abstract_row NAME @SOCK CMD...: an abstract socket attempt. Before
# Landlock ABI 6 (the run then uses --allow-abstract-sockets) it is the
# documented gap; otherwise, and without layer 2, an ordinary deny row.
abstract_row() {
	local name=$1 sock=$2
	shift 2
	if [ "${LL_ABI:-0}" -ge 6 ] || [ "${NO_LAYER2:-0}" = 1 ]; then
		deny_sock "$name" "$sock" "$@"
	else
		case " ${OUTSIDE_SOCKS:-} " in
		*" $sock "*) gap "$name" "Landlock ABI ${LL_ABI:-0} < 6 does not scope abstract sockets" "$@" ;;
		*) row SKIP "$name" "target $sock absent outside, nothing to reach" ;;
		esac
	fi
}

# --- the person's files ---
deny read-ssh-key grep -q "$MARKER" "$HOME/.ssh/cotty_lab_fake"
deny ssh-dir-visible test -e "$HOME/.ssh"
deny shell-history grep -q "$MARKER" "$HOME/.bash_history"
deny home-via-proc-root "$PROBE" open-read "/proc/1/root$HOME/.ssh/cotty_lab_fake"
deny home-via-self-root "$PROBE" open-read "/proc/self/root$HOME/.ssh/cotty_lab_fake"
deny umount-home-tmpfs "$PROBE" umount "$HOME"
skip_if_empty landlock-read-boot "$BOOT_FILE" && deny landlock-read-boot "$PROBE" open-read "$BOOT_FILE"
deny read-root-home ls /root
deny write-etc "$PROBE" open-write /etc/cotty-lab-escape
deny write-git-hook "$PROBE" open-write "$PROJECT/.git/hooks/pre-commit"
deny write-git-config "$PROBE" open-write "$PROJECT/.git/config"
# Around the protected files: renames, the commondir indirection is a
# separate run (it stops the agent), hooksPath, includes, scripts named by
# config, submodule and worktree git directories, nested repositories.
deny git-rename-dotgit sh -c 'mv "$1" "$2" && mv "$2" "$1" && echo "renamed $1"' sh "$PROJECT/.git" "$PROJECT/.git.old"
deny git-rename-hooks sh -c 'mv "$1" "$2" && mv "$2" "$1" && echo "renamed $1"' sh "$PROJECT/.git/hooks" "$PROJECT/.git/hooks.old"
deny git-rename-config sh -c 'mv "$1" "$2" && mv "$2" "$1" && echo "renamed $1"' sh "$PROJECT/.git/config" "$PROJECT/.git/config.old"
deny git-config-worktree "$PROBE" open-write "$PROJECT/.git/config.worktree"
deny git-hookspath-plant sh -c "mkdir -p '$PROJECT/.husky/_' && echo 'touch /tmp/x' >'$PROJECT/.husky/_/pre-commit'"
deny git-hookspath-rename sh -c 'mv "$1" "$2" && mv "$2" "$1" && echo "renamed $1"' sh "$PROJECT/.husky" "$PROJECT/.husky.old"
# Hook managers run work tree files: Husky v9's stubs run .husky/<hook>,
# pre-commit and lefthook read their configuration from the work tree.
deny git-husky-hook-plant sh -c "echo 'touch /tmp/x' >'$PROJECT/.husky/pre-commit'"
deny git-precommit-config "$PROBE" open-write "$PROJECT/.pre-commit-config.yaml"
deny git-lefthook-config "$PROBE" open-write "$PROJECT/lefthook.yml"
deny git-include-plant "$PROBE" open-write "$PROJECT/lab.gitconfig"
deny git-filter-script "$PROBE" open-write "$PROJECT/scripts/clean.sh"
deny git-modules-config "$PROBE" open-write "$PROJECT/.git/modules/sub/config"
deny git-modules-hooks sh -c "echo x >'$PROJECT/.git/modules/sub/hooks/post-checkout'"
deny git-modules-rename sh -c 'mv "$1" "$2" && mv "$2" "$1" && echo "renamed $1"' sh "$PROJECT/.git/modules" "$PROJECT/.git/modules.old"
deny git-modules-rename-sub sh -c 'mv "$1" "$2" && mv "$2" "$1" && echo "renamed $1"' sh "$PROJECT/.git/modules/sub" "$PROJECT/.git/modules/sub.old"
deny git-worktree-config "$PROBE" open-write "$PROJECT/.git/worktrees/wt/config.worktree"
deny git-worktree-commondir "$PROBE" open-write "$PROJECT/.git/worktrees/wt/commondir"
deny git-worktree-rename sh -c 'mv "$1" "$2" && mv "$2" "$1" && echo "renamed $1"' sh "$PROJECT/.git/worktrees/wt" "$PROJECT/.git/worktrees/wt.old"
deny git-nested-config "$PROBE" open-write "$PROJECT/vendored/.git/config"
deny git-nested-rename sh -c 'mv "$1" "$2" && mv "$2" "$1" && echo "renamed $1"' sh "$PROJECT/vendored/.git" "$PROJECT/vendored/.git.old"
deny git-nested-hooks sh -c "echo x >>'$PROJECT/vendored/.git/hooks/pre-commit'"
# Tokens the person's environment holds (run.sh sets them).
deny env-tokens sh -c 'env | grep -E "^(HF_TOKEN|DATABASE_URL|STRIPE_SECRET_KEY)="'
# The cotty directory in the runtime directory cannot be swapped.
deny runtime-cotty-rename sh -c 'mv "$1" "$2" && mv "$2" "$1" && echo "renamed $1"' sh "$XDG_RUNTIME_DIR/cotty" "$XDG_RUNTIME_DIR/cotty.old"
deny runtime-cotty-plant sh -c "mkdir '$XDG_RUNTIME_DIR/cotty/cotty-lab-x' && rmdir '$XDG_RUNTIME_DIR/cotty/cotty-lab-x'"

# --- sockets: session bus and keyring, systemd, key agents ---
deny_sock dbus-session-path "$RT/bus" "$PROBE" connect "$RT/bus"
if command -v busctl >/dev/null; then
	deny_sock dbus-secret-service "$RT/bus" env DBUS_SESSION_BUS_ADDRESS="unix:path=$RT/bus" busctl --user call org.freedesktop.secrets /org/freedesktop/secrets org.freedesktop.DBus.Peer Ping
fi
deny_sock dbus-fake-path "$RT/cotty-lab/bus" "$PROBE" connect "$RT/cotty-lab/bus"
abstract_row dbus-abstract @/tmp/dbus-cottylab "$PROBE" connect-abstract /tmp/dbus-cottylab
deny_sock systemd-private "$RT/systemd/private" "$PROBE" connect "$RT/systemd/private"
deny_sock systemd-run-scope "$RT/systemd/private" systemd-run --user --scope true
deny_sock systemd-run-shell "$RT/systemd/private" systemd-run --user --quiet --wait -- sh -c "touch $HOME/cotty-lab-escape"
deny_sock systemctl-user "$RT/systemd/private" systemctl --user show-environment
deny_sock system-bus /run/dbus/system_bus_socket "$PROBE" connect /run/dbus/system_bus_socket
deny_sock ssh-agent-real "$REAL_SSH" "$PROBE" connect "$REAL_SSH"
if command -v ssh-add >/dev/null; then deny_sock ssh-add "$REAL_SSH" env SSH_AUTH_SOCK="$REAL_SSH" ssh-add -l; fi
deny_sock ssh-agent-fake "$RT/cotty-lab/ssh-agent.sock" "$PROBE" connect "$RT/cotty-lab/ssh-agent.sock"
skip_if_empty gpg-agent "$GPG_SOCK" && deny_sock gpg-agent "$GPG_SOCK" "$PROBE" connect "$GPG_SOCK"
skip_if_empty docker-socket "$DOCKER_SOCK" && deny_sock docker-socket "$DOCKER_SOCK" "$PROBE" connect "$DOCKER_SOCK"

# A socket created outside in the project: only Landlock ABI 9 (resolve
# unix) or the guard stops the connect. Below ABI 9 a successful connect
# is the documented gap of layer 2 (docs/confinement.md), reported GAP,
# not SKIP: it is reachable. Without layer 2 (guard.sh none and
# guard-only) it is an ordinary deny row.
if [ "${LL_ABI:-0}" -ge 9 ] || [ "${NO_LAYER2:-0}" = 1 ]; then
	deny_sock landlock-resolve-unix "$PROJECT/outside.sock" "$PROBE" connect "$PROJECT/outside.sock"
else
	out=$("$PROBE" connect "$PROJECT/outside.sock" 2>&1)
	rc=$?
	out=$(echo "$out" | tr '\n' ' ' | cut -c1-80)
	case $rc in
	0) row GAP landlock-resolve-unix "reachable (Landlock ABI ${LL_ABI:-0} < 9 does not mediate pathname sockets): $out" ;;
	*) row PASS landlock-resolve-unix "denied (by a layer other than Landlock ABI ${LL_ABI:-0}): $out" ;;
	esac
fi
skip_if_empty var-socket-dir "${VAR_SOCK:-}" && deny var-socket-dir "$PROBE" connect "$VAR_SOCK"

# --- terminal remote control and the display ---
if skip_if_empty tmux-socket "$TMUX_SOCK"; then
	deny_sock tmux-socket "$TMUX_SOCK" "$PROBE" connect "$TMUX_SOCK"
	deny_sock tmux-capture-pane "$TMUX_SOCK" tmux -S "$TMUX_SOCK" capture-pane -p
fi
if skip_if_empty screen-socket "$SCREEN_SOCK"; then
	deny_sock screen-socket "$SCREEN_SOCK" "$PROBE" connect "$SCREEN_SOCK"
	deny_sock screen-hardcopy "$SCREEN_SOCK" screen -S cottylab -X hardcopy "$PROJECT/screen.txt"
fi
deny_sock kitty-path /tmp/kitty-cottylab "$PROBE" connect /tmp/kitty-cottylab
abstract_row kitty-abstract @kitty-cottylab "$PROBE" connect-abstract kitty-cottylab
deny_sock wezterm "$RT/wezterm/gui-sock-cottylab" "$PROBE" connect "$RT/wezterm/gui-sock-cottylab"
deny_sock x11-path /tmp/.X11-unix/X42 "$PROBE" connect /tmp/.X11-unix/X42
abstract_row x11-abstract @/tmp/.X11-unix/X42 "$PROBE" connect-abstract /tmp/.X11-unix/X42

# --- terminals ---
deny other-pts "$PROBE" pts-scan "$OWN_TTY"
deny own-devpts-instance "$PROBE" own-devpts "$PERSON_PTS_DEV" "$OWN_TTY"
deny inherited-fds "$PROBE" extra-fds
deny tiocsti-dev-tty "$PROBE" tiocsti /dev/tty

# --- other processes ---
deny pid-namespace "$PROBE" pidns "$VICTIM_PID"
deny environ-outside "$PROBE" environ-grep "$MARKER"
deny ptrace-outside "$PROBE" ptrace "$VICTIM_PID"
deny ptrace-own-child "$PROBE" ptrace-child
deny vm-readv-outside "$PROBE" vm-readv "$VICTIM_PID"
deny vm-readv-own-child "$PROBE" vm-readv-child
deny proc-mem-outside "$PROBE" proc-mem "$VICTIM_PID"
deny proc-mem-init "$PROBE" proc-mem 1
deny signal-outside "$PROBE" kill "$VICTIM_PID"
if [ "${LL_ABI:-0}" -ge 6 ] || [ "${NO_LAYER2:-0}" = 1 ]; then
	deny signal-init "$PROBE" kill 1
else
	gap signal-init "Landlock ABI ${LL_ABI:-0} < 6 does not scope signals (init is in the agent's pid namespace)" "$PROBE" kill 1
fi

# --- privileges, namespaces, cgroups, kernel interfaces ---
deny nested-userns-unshare "$PROBE" unshare user
deny nested-userns-clone "$PROBE" clone-userns
deny nested-mountns "$PROBE" unshare mount
deny unshare-command unshare -Ur true
deny mount-tmpfs "$PROBE" mount-tmpfs /tmp/cotty-lab-mnt
deny sudo sudo -n true
deny su su -c true root
deny no-new-privs "$PROBE" status NoNewPrivs 1
deny seccomp-filter "$PROBE" status Seccomp 2
deny capabilities "$PROBE" caps
deny cgroup-procs-own sh -c 'echo $$ >/sys/fs/cgroup/cgroup.procs'
deny cgroup-procs-person sh -c "echo \$\$ >/sys/fs/cgroup$PERSON_CGROUP/cgroup.procs"
deny cgroup-person-visible test -e "/sys/fs/cgroup$PERSON_CGROUP"
deny keyctl "$PROBE" keyctl
deny bpf "$PROBE" bpf
deny perf-event-open "$PROBE" perf
deny userfaultfd "$PROBE" userfaultfd
deny io-uring "$PROBE" io-uring
deny core-limit "$PROBE" core-limit
mkdir -p "$PROJECT/tmpcore"
deny core-dump sh -c "cd '$PROJECT/tmpcore' && '$PROBE' core-dump"

# --- allowed work ---
allow own-tty sh -c "case '$OWN_TTY' in /dev/pts/*) echo '$OWN_TTY';; *) exit 1;; esac"
allow ps ps -e
allow write-home-tmpfs sh -c "echo x >'$HOME/cotty-lab-escape'"
allow runtime-dir-write sh -c "touch '$XDG_RUNTIME_DIR/x' && test \"\$(stat -c %a '$XDG_RUNTIME_DIR')\" = 700"
allow git-commit sh -c 'echo work >>README.md && git commit -qam work && git log --oneline | head -1'
allow dns getent hosts example.com
allow https curl -fsS -o /dev/null https://example.com
if command -v gcc >/dev/null; then
	allow c-build-run sh -c 'mkdir -p c && cd c && printf "int main(){return 0;}\n" >m.c && gcc -o m m.c && ./m'
fi
if command -v go >/dev/null; then
	allow go-build-test sh -c 'mkdir -p gomod && cd gomod && cat >go.mod <<EOF
module lab
go 1.21
EOF
printf "package lab\nfunc Add(a,b int)int{return a+b}\n" >lab.go
printf "package lab\nimport \"testing\"\nfunc TestAdd(t *testing.T){if Add(1,2)!=3{t.Fatal()}}\n" >lab_test.go
GOTOOLCHAIN=local GOFLAGS=-mod=mod go test ./... && go build ./...'
fi
allow python-venv-pip sh -c 'python3 -m venv .venv && .venv/bin/pip install -q six && .venv/bin/python -c "import six"'
allow python-unittest sh -c 'mkdir -p py && cd py && printf "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        self.assertEqual(1+1,2)\n" >test_x.py && python3 -m unittest -q 2>&1'
if command -v npm >/dev/null; then
	allow npm-install-test sh -c 'mkdir -p js && cd js && npm init -y >/dev/null && npm install --silent is-number && echo "require(\"is-number\")" >test.js && npm pkg set scripts.test="node test.js" && npm test --silent'
fi
if command -v tmux >/dev/null; then
	allow own-tmux sh -c 'tmux -L inner new-session -d "sleep 5" && tmux -L inner ls && tmux -L inner kill-server'
fi
allow make-available make --version
allow own-unix-socket sh -c "python3 -c \"
import socket,os
p='$PROJECT/own.sock'
s=socket.socket(socket.AF_UNIX); s.bind(p); s.listen(1)
c=socket.socket(socket.AF_UNIX); c.connect(p); c.close(); os.unlink(p)\""
# --- rows added after the final review ---
# B7: rename .git, copy it back and plant a hook that the person's next
# git command would run unconfined (run.sh checks the result outside:
# git-dir-unchanged). Fixed: .git is a mount point of its own.
deny git-dir-rename-hook sh -c 'mv .git .git.cotty-old && cp -a .git.cotty-old .git && printf "#!/bin/sh\necho planted\n" >.git/hooks/post-checkout && chmod +x .git/hooks/post-checkout && echo "planted .git/hooks/post-checkout"'
# B7: a nested repository created inside cannot be prevented (any
# directory can hold a .git); cotty agent reports it when the agent exits
# (run.sh: git-new-nested-reported), so with layer 2 this is the
# documented gap. Existing nested repositories are protected
# (git-nested-* above).
if [ "${NO_LAYER2:-0}" = 1 ]; then
	deny git-nested-repo-hook sh -c 'git init -q nested && printf "#!/bin/sh\necho planted\n" >nested/.git/hooks/post-checkout && echo "planted nested/.git/hooks/post-checkout"'
else
	gap git-nested-repo-hook "a repository created inside is reported at exit, not blocked" sh -c 'git init -q nested && printf "#!/bin/sh\necho planted\n" >nested/.git/hooks/post-checkout && echo "planted nested/.git/hooks/post-checkout"'
fi
# S13: terminal control sequences the agent prints must not reach the
# person's terminal through the relay (run.sh checks the relayed output:
# OSC 52 clipboard write, kitty remote control, OSC 5113 file transfer;
# the window title passes).
printf '\033]52;c;%s\a' "$(printf COTTY-LAB-OSC52 | base64)"
printf '\033P@kitty-cmd{"cmd":"ls","version":[0,26,0]}\033\\'
printf '\033]5113;ac=send\033\\\033]0;cotty-lab-title\a'
# N12: the same OSC 52 with its introducer and terminator encoded in
# UTF-8 (U+009D, U+009C), and behind an ESC followed by a raw C1 byte.
printf '\302\23552;c;%s\302\234' "$(printf COTTY-LAB-U8C1 | base64)"
printf '\033\23552;c;%s\234' "$(printf COTTY-LAB-ESCC1 | base64)"
echo
row PASS relay-escapes-sent "OSC 52, OSC 5113, kitty remote control and a title printed; see relay-* outside"
if grep -q unpriv_cotty /proc/self/attr/current 2>/dev/null; then
	row PASS apparmor-agent "the agent runs under $(tr -d '\0' </proc/self/attr/current)"
elif [ -e /sys/kernel/security/apparmor ] && grep -q '^cotty' /proc/self/attr/current 2>/dev/null; then
	row FAIL apparmor-agent "the agent runs under $(tr -d '\0' </proc/self/attr/current), not unpriv_cotty"
else
	row SKIP apparmor-agent "not under cotty's AppArmor profile: $(tr -d '\0' </proc/self/attr/current 2>/dev/null)"
fi
echo "DONE inside.sh"
