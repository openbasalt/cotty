#!/usr/bin/env bash
# vm.sh: run the cotty mcp end to end tests in a Fedora 44 lab VM (WP-D),
# or Ubuntu 26.04 with DISTRO=ubuntu2604.
#
# Nothing here runs cotty on the host (PLAN section 9): the host only
# builds; sessions, sudo prompts and agent CLIs run inside the VM. The VM
# is made by tests/lab/vm-broker.sh (same image, users and test password),
# under its own name and port.
#
#   tests/e2e/vm.sh up            create (first time) and boot
#   tests/e2e/vm.sh test          build, install, run the deterministic e2e tests
#                                 (RUN=regexp selects tests, COUNT=n repeats)
#   tests/e2e/vm.sh real-claude   build, install, run tests/e2e/real-claude.sh in the VM
#                                 (needs the token file in the VM, see docs/mcp.md;
#                                 CONFINED=1 runs claude under `cotty agent`,
#                                 MODEL=haiku picks the model)
#   tests/e2e/vm.sh ssh [cmd]     ssh as the test user
#   tests/e2e/vm.sh stop          power off (keep the disk)
#   tests/e2e/vm.sh destroy       delete the VM
set -euo pipefail

export VMROOT=${VMROOT:-$HOME/work/cotty-vms}
export DISTRO=${DISTRO:-fedora44}
export NAME=${NAME:-cotty-d-$DISTRO}
export PORT=${PORT:-2251}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
LAB=$REPO/tests/lab/vm-broker.sh
DIR=$VMROOT/$NAME
case $DISTRO in ubuntu*) ADMIN=ubuntu ;; *) ADMIN=fedora ;; esac

ssh_opts=(-i "$DIR/id_ed25519" -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR -o ConnectTimeout=5)

# install builds cotty and the e2e test binary here and installs them in
# the VM: cotty root-owned in /usr/local/bin (as a package would), the
# test binary and real-claude.sh in the test user's home.
install() {
	"$LAB" up
	local out=$DIR/build
	mkdir -p "$out"
	(cd "$REPO" && CGO_ENABLED=0 go build -o "$out/cotty" ./cmd/cotty &&
		CGO_ENABLED=0 go test -c -tags vmtest -o "$out/cotty-e2e.test" ./tests/e2e)
	scp -q -P "$PORT" -i "$DIR/id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		"$out/cotty" "$out/cotty-e2e.test" "$REPO/tests/e2e/real-claude.sh" "$ADMIN"@127.0.0.1:/tmp/
	ssh "${ssh_opts[@]}" "$ADMIN"@127.0.0.1 'sudo install -o root -g root -m 0755 /tmp/cotty /usr/local/bin/cotty &&
		sudo install -o cottytest -g cottytest -m 0700 /tmp/cotty-e2e.test /home/cottytest/cotty-e2e.test &&
		sudo install -o cottytest -g cottytest -m 0700 /tmp/real-claude.sh /home/cottytest/real-claude.sh'
	# cotty's AppArmor profile where AppArmor runs (Ubuntu).
	ssh "${ssh_opts[@]}" "$ADMIN"@127.0.0.1 'if [ -d /sys/kernel/security/apparmor ] && command -v apparmor_parser >/dev/null; then
		sudo tee /etc/apparmor.d/cotty >/dev/null && sudo apparmor_parser -r /etc/apparmor.d/cotty; else cat >/dev/null; fi' <"$REPO/dist/apparmor/cotty"
	# The test password goes over stdin into a 0600 file in the test
	# user's home; it is a random string used only inside this VM.
	ssh "${ssh_opts[@]}" cottytest@127.0.0.1 'umask 077; cat > ~/.cotty-test-password' < "$DIR/test-password"
}

case "${1:-}" in
up | stop | destroy) "$LAB" "$1" ;;
ssh) shift; "$LAB" ssh "$@" ;;
test)
	install
	ssh "${ssh_opts[@]}" cottytest@127.0.0.1 \
		"rm -rf ~/.local/state/cotty; COTTY_BIN=/usr/local/bin/cotty COTTY_TEST_PASSWORD_FILE=\$HOME/.cotty-test-password ./cotty-e2e.test -test.v -test.timeout 20m ${RUN:+-test.run $(printf %q "$RUN")} ${COUNT:+-test.count $COUNT}"
	;;
real-claude)
	install
	ssh -t "${ssh_opts[@]}" cottytest@127.0.0.1 \
		"CLAUDE_TOKEN_FILE=\${CLAUDE_TOKEN_FILE:-\$HOME/.claude-token} COTTY_E2E_CONFINED=$(printf %q "${CONFINED:-}") COTTY_E2E_CLAUDE_MODEL=$(printf %q "${MODEL:-}") ./real-claude.sh"
	;;
*) sed -n '2,19p' "$0"; exit 2 ;;
esac
