#!/usr/bin/env bash
# vm-broker.sh: a Fedora 44 (or Ubuntu 26.04) VM for the broker
# integration tests (WP-A). DISTRO=ubuntu2604 selects Ubuntu, whose sudo
# is sudo-rs (password read in raw mode); name the VM accordingly
# (NAME=cotty-a-ubuntu2604) and give it its own PORT.
#
# Everything that runs cotty sessions runs inside this VM, never on the
# host (PLAN section 9). Plain qemu with KVM as the user, user networking,
# a qcow2 overlay on the shared cloud base image.
#
#   tests/lab/vm-broker.sh up        create (first time) and boot, wait for ssh
#   tests/lab/vm-broker.sh test      build, copy, run the integration tests
#                                    (RUN=regexp selects tests, COUNT=n repeats,
#                                    RACE=1 builds cotty with the race detector)
#   tests/lab/vm-broker.sh ssh [cmd] ssh as the test user
#   tests/lab/vm-broker.sh stop      power off (keep the disk)
#   tests/lab/vm-broker.sh destroy   delete the VM
#
# Layout under $VMROOT (default ~/work/cotty-vms):
#   base/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2   shared, read only
#   cotty-a-fedora44/{disk.qcow2,seed.iso,id_ed25519,test-password,pid,console.log}
# The lab key and the test user's password stay there (0600) and are never
# committed. The password is a random string used only inside this VM.
set -euo pipefail

VMROOT=${VMROOT:-$HOME/work/cotty-vms}
DISTRO=${DISTRO:-fedora44}
case $DISTRO in
fedora44)
	NAME=${NAME:-cotty-a-fedora44}
	BASE_FILE=Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2
	BASE_URL=https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/$BASE_FILE
	ADMIN=fedora ADMIN_GROUP=wheel
	PKGS="zsh, vim-enhanced, htop, less, python3, openssl, git, tmux, passwd" ;;
ubuntu2604)
	NAME=${NAME:-cotty-a-ubuntu2604}
	BASE_FILE=ubuntu-26.04-server-cloudimg-amd64.img
	BASE_URL=https://cloud-images.ubuntu.com/releases/26.04/release/$BASE_FILE
	ADMIN=ubuntu ADMIN_GROUP=sudo
	PKGS="zsh, vim, htop, less, python3, openssl, git, tmux, passwd, apparmor-utils" ;;
*) echo "vm-broker: unknown DISTRO $DISTRO (fedora44, ubuntu2604)" >&2; exit 1 ;;
esac
export ADMIN
PORT=${PORT:-2241}
MEM=${MEM:-4096}
CPUS=${CPUS:-4}
DIR=$VMROOT/$NAME
REPO=$(cd "$(dirname "$0")/../.." && pwd)

ssh_opts=(-i "$DIR/id_ed25519" -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR -o ConnectTimeout=5)

die() { echo "vm-broker: $*" >&2; exit 1; }

# install_apparmor loads cotty's AppArmor profile where AppArmor runs
# (Ubuntu restricts unprivileged user namespaces to profiled programs).
install_apparmor() {
	ssh "${ssh_opts[@]}" "$ADMIN"@127.0.0.1 'if [ -d /sys/kernel/security/apparmor ] && command -v apparmor_parser >/dev/null; then
		sudo tee /etc/apparmor.d/cotty >/dev/null && sudo apparmor_parser -r /etc/apparmor.d/cotty; else cat >/dev/null; fi' <"$REPO/dist/apparmor/cotty"
}

base() {
	mkdir -p "$VMROOT/base"
	local b=$VMROOT/base/$BASE_FILE
	if [ ! -f "$b" ]; then
		flock "$VMROOT/base/.dl.lock" sh -c "[ -f '$b' ] || (curl -sfL --retry 3 -o '$b.part' '$BASE_URL' && mv '$b.part' '$b')"
	fi
	echo "$b"
}

create() {
	mkdir -p "$DIR"
	chmod 700 "$DIR"
	local b
	b=$(base)
	[ -f "$DIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C "$NAME" -f "$DIR/id_ed25519"
	if [ ! -f "$DIR/test-password" ]; then
		(umask 077; head -c 18 /dev/urandom | base64 | tr -d '/+=' > "$DIR/test-password")
	fi
	local hash pub
	hash=$(openssl passwd -6 -stdin < "$DIR/test-password")
	pub=$(cat "$DIR/id_ed25519.pub")
	qemu-img create -q -f qcow2 -F qcow2 -b "$b" "$DIR/disk.qcow2" 20G
	cat > "$DIR/user-data" <<EOF
#cloud-config
hostname: $NAME
ssh_pwauth: true
users:
  - name: $ADMIN
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    groups: $ADMIN_GROUP
    ssh_authorized_keys: ["$pub"]
  - name: cottytest
    groups: $ADMIN_GROUP
    sudo: "ALL=(ALL) ALL"
    lock_passwd: false
    passwd: "$hash"
    shell: /bin/bash
    ssh_authorized_keys: ["$pub"]
packages: [$PKGS]
write_files:
  - path: /etc/sudoers.d/cotty-pwfeedback
    permissions: "0440"
    content: |
      Defaults!/usr/bin/id pwfeedback
runcmd:
  - loginctl enable-linger cottytest
  - touch /var/lib/cotty-lab-ready
EOF
	printf 'instance-id: %s\nlocal-hostname: %s\n' "$NAME" "$NAME" > "$DIR/meta-data"
	genisoimage -quiet -output "$DIR/seed.iso" -volid cidata -joliet -rock "$DIR/user-data" "$DIR/meta-data"
	rm -f "$DIR/user-data"
}

running() { [ -f "$DIR/pid" ] && kill -0 "$(cat "$DIR/pid")" 2>/dev/null; }

up() {
	[ -f "$DIR/disk.qcow2" ] || create
	if ! running; then
		qemu-system-x86_64 -name "$NAME" -enable-kvm -cpu host -m "$MEM" -smp "$CPUS" \
			-drive file="$DIR/disk.qcow2",if=virtio,cache=writeback,discard=unmap \
			-drive file="$DIR/seed.iso",if=virtio,media=cdrom,readonly=on \
			-netdev user,id=n0,hostfwd=tcp:127.0.0.1:"$PORT"-:22 -device virtio-net-pci,netdev=n0 \
			-display none -serial file:"$DIR/console.log" -daemonize -pidfile "$DIR/pid"
	fi
	for _ in $(seq 1 120); do
		if ssh "${ssh_opts[@]}" "$ADMIN"@127.0.0.1 test -f /var/lib/cotty-lab-ready 2>/dev/null; then
			echo "vm-broker: $NAME is up (ssh port $PORT)"
			return 0
		fi
		sleep 5
	done
	die "$NAME did not come up; see $DIR/console.log"
}

stop() {
	if running; then
		ssh "${ssh_opts[@]}" "$ADMIN"@127.0.0.1 sudo poweroff 2>/dev/null || true
		for _ in $(seq 1 30); do running || break; sleep 1; done
		running && kill "$(cat "$DIR/pid")"
	fi
	rm -f "$DIR/pid"
	echo "vm-broker: $NAME stopped"
}

destroy() {
	stop
	rm -rf "$DIR"
}

# test builds cotty and the integration test binary on the host (build
# only), installs cotty root-owned in the VM and runs the tests there as
# the unprivileged test user.
test_run() {
	up
	local out=$DIR/build
	mkdir -p "$out"
	local race=() cgo=0
	if [ -n "${RACE:-}" ]; then race=(-race); cgo=1; fi
	(cd "$REPO" && CGO_ENABLED=$cgo go build "${race[@]}" -o "$out/cotty" ./cmd/cotty &&
		CGO_ENABLED=0 go test -c -tags vmtest -o "$out/cotty-it.test" ./tests/integration)
	scp -q -P "$PORT" -i "$DIR/id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		"$out/cotty" "$out/cotty-it.test" "$ADMIN"@127.0.0.1:/tmp/
	ssh "${ssh_opts[@]}" "$ADMIN"@127.0.0.1 'sudo install -o root -g root -m 0755 /tmp/cotty /usr/local/bin/cotty &&
		sudo install -o cottytest -g cottytest -m 0700 /tmp/cotty-it.test /home/cottytest/cotty-it.test'
	install_apparmor
	# The password goes over stdin into a 0600 file in the test user's home.
	ssh "${ssh_opts[@]}" cottytest@127.0.0.1 'umask 077; cat > ~/.cotty-test-password' < "$DIR/test-password"
	ssh "${ssh_opts[@]}" cottytest@127.0.0.1 \
		"rm -rf ~/.local/state/cotty; COTTY_BIN=/usr/local/bin/cotty COTTY_TEST_PASSWORD_FILE=\$HOME/.cotty-test-password ./cotty-it.test -test.v -test.timeout 20m ${RUN:+-test.run $(printf %q "$RUN")} ${COUNT:+-test.count $COUNT}"
}

case "${1:-}" in
up) up ;;
stop) stop ;;
destroy) destroy ;;
test) test_run ;;
ssh) shift; ssh -t "${ssh_opts[@]}" cottytest@127.0.0.1 "$@" ;;
*) sed -n '2,20p' "$0"; exit 2 ;;
esac
