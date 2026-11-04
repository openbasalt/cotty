#!/usr/bin/env bash
# Throwaway VMs for testing cotty's confinement on real kernels, as an
# unprivileged user with KVM: plain qemu, cloud images, cloud-init, user
# networking (with internet), ssh with a lab key. Nothing here needs root
# on the host and nothing runs the confinement on the host itself.
#
#   tests/lab/vm.sh create NAME DISTRO   fedora44 | ubuntu2604 | ubuntu2404 |
#                                        debian13 | arch
#   tests/lab/vm.sh start NAME           boot and wait for cloud-init
#   tests/lab/vm.sh ssh NAME [CMD...]    shell or command as user "lab"
#   tests/lab/vm.sh push NAME            build cotty and the probe (host Go,
#                                        CGO_ENABLED=0) and copy them with
#                                        tests/ to ~/cotty in the VM
#   tests/lab/vm.sh matrix NAME          push, run the escape matrix, keep
#                                        the report in $LAB/NAME/
#   tests/lab/vm.sh broker-matrix NAME   push, run the escape matrix against
#                                        the broker (tests/attacks/broker.sh)
#   tests/lab/vm.sh claude-config NAME   push, run tests/attacks/claude-config.sh
#   tests/lab/vm.sh guard NAME [start|restart|stop]
#                                        install (from the last push) and run
#                                        cotty-guard in the VM, or stop it
#   tests/lab/vm.sh stop NAME            power off
#   tests/lab/vm.sh apparmor NAME        install and load dist/apparmor/cotty
#                                        in the VM (Ubuntu 24.04 and later)
#   tests/lab/vm.sh destroy NAME         stop and delete a VM this script made
#   tests/lab/vm.sh list                 VMs in the lab directory
#
# Layout: $COTTY_LAB (default ~/work/cotty-vms)/base holds one copy of each
# cloud image, shared by every VM (downloads of the same image are
# serialized with flock, one lock per image); each VM is a qcow2 overlay
# on it in $COTTY_LAB/NAME, so creating VMs writes little to disk. The lab
# ssh key lives in $COTTY_LAB/keys (0600); never commit it. Name VMs with your prefix (cotty-c-...).
set -euo pipefail

LAB=${COTTY_LAB:-$HOME/work/cotty-vms}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
KEY=$LAB/keys/lab_ed25519
SMP=${COTTY_LAB_SMP:-4}
MEM=${COTTY_LAB_MEM:-4096}

die() { echo "vm.sh: $*" >&2; exit 1; }

image_for() {
	case $1 in
	fedora44) echo "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2" ;;
	ubuntu2604) echo "https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img" ;;
	ubuntu2404) echo "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img" ;;
	debian13) echo "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2" ;;
	arch) echo "https://fastly.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2" ;;
	*) die "unknown distro $1 (fedora44, ubuntu2604, ubuntu2404, debian13, arch)" ;;
	esac
}

packages_for() {
	# Tools the matrix uses (attack targets and allowed work) and the
	# agent CLIs' runtimes.
	local common="git gcc make curl tmux screen gnupg2 sudo socat"
	case $1 in
	fedora*) echo "$common python3 python3-pip nodejs npm golang openssh-clients dbus-daemon" ;;
	ubuntu* | debian*) echo "$common python3 python3-venv python3-pip nodejs npm golang-go openssh-client dbus-user-session" ;;
	arch) echo "git gcc make curl tmux screen gnupg sudo socat python python-pip nodejs npm go openssh dbus" ;;
	esac
}

base_image() {
	local url file
	url=$(image_for "$1")
	file=$LAB/base/$(basename "$url")
	mkdir -p "$LAB/base"
	# An image already there needs no lock (another VM's download may hold
	# it for a long time).
	if [ -s "$file" ]; then
		echo "$file"
		return
	fi
	(
		flock 9
		if [ ! -s "$file" ]; then
			echo "vm.sh: downloading $url" >&2
			# The Fedora redirector sometimes picks an unreachable mirror;
			# the primary server is the fallback.
			if ! curl -fsSL --retry 3 --connect-timeout 20 -o "$file.part" "$url"; then
				url=${url/download.fedoraproject.org/dl.fedoraproject.org}
				echo "vm.sh: retrying from $url" >&2
				curl -fsSL --retry 3 --connect-timeout 20 -o "$file.part" "$url"
			fi
			mv "$file.part" "$file"
		fi
	) 9>"$file.lock"
	echo "$file"
}

vmdir() {
	[[ $1 =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "bad VM name $1"
	echo "$LAB/$1"
}

free_port() {
	local p
	for p in $(seq 22400 22499); do
		if ! ss -ltn "sport = :$p" | grep -q LISTEN && ! grep -qsx "$p" "$LAB"/*/port; then
			echo "$p"
			return
		fi
	done
	die "no free port in 22400-22499"
}

# reserve_port picks a free port and records it for the VM under one
# lock, so VMs created in parallel never get the same port.
reserve_port() {
	local dir=$1 p
	exec 8>"$LAB/.port.lock"
	flock 8
	p=$(free_port)
	echo "$p" >"$dir/port"
	exec 8>&-
	echo "$p"
}

cmd_create() {
	local name=$1 distro=$2 dir base port
	dir=$(vmdir "$name")
	[ -e "$dir" ] && die "$dir exists"
	base=$(base_image "$distro")
	mkdir -p "$LAB/keys" "$dir"
	if [ ! -f "$KEY" ]; then
		ssh-keygen -q -t ed25519 -N '' -C cotty-lab -f "$KEY"
		chmod 600 "$KEY"
	fi
	port=$(reserve_port "$dir")
	[ -n "$port" ] || die "no port for $name"
	echo "$distro" >"$dir/distro"
	touch "$dir/.cotty-lab"
	qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$dir/disk.qcow2" 30G
	cat >"$dir/user-data" <<EOF
#cloud-config
hostname: $name
users:
  - name: lab
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$KEY.pub")
package_update: true
packages: [$(packages_for "$distro" | sed 's/ /, /g')]
runcmd:
  - loginctl enable-linger lab
  - [sh, -c, "echo cotty-lab-ready > /var/lib/cotty-lab-ready"]
EOF
	printf 'instance-id: %s\nlocal-hostname: %s\n' "$name" "$name" >"$dir/meta-data"
	if command -v cloud-localds >/dev/null; then
		cloud-localds "$dir/seed.iso" "$dir/user-data" "$dir/meta-data"
	else
		genisoimage -quiet -output "$dir/seed.iso" -volid cidata -joliet -rock "$dir/user-data" "$dir/meta-data"
	fi
	echo "vm.sh: created $name ($distro), ssh port $port"
}

running() { [ -f "$1/qemu.pid" ] && kill -0 "$(cat "$1/qemu.pid")" 2>/dev/null; }

ssh_opts() {
	local dir=$1
	echo "-i $KEY -p $(cat "$dir/port") -o StrictHostKeyChecking=no -o UserKnownHostsFile=$dir/known_hosts -o LogLevel=ERROR -o ConnectTimeout=5"
}

cmd_start() {
	local name=$1 dir
	dir=$(vmdir "$name")
	[ -f "$dir/disk.qcow2" ] || die "no VM $name"
	if ! running "$dir"; then
		qemu-system-x86_64 -name "$name" -machine q35,accel=kvm -cpu host -smp "$SMP" -m "$MEM" \
			-drive file="$dir/disk.qcow2",if=virtio -drive file="$dir/seed.iso",media=cdrom,readonly=on \
			-nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:"$(cat "$dir/port")"-:22 \
			-display none -serial file:"$dir/serial.log" -daemonize -pidfile "$dir/qemu.pid"
	fi
	local i
	for i in $(seq 1 120); do
		# shellcheck disable=SC2046
		if ssh $(ssh_opts "$dir") lab@127.0.0.1 test -f /var/lib/cotty-lab-ready 2>/dev/null; then
			echo "vm.sh: $name is up (ssh port $(cat "$dir/port"))"
			return 0
		fi
		sleep 5
	done
	die "$name did not come up; see $dir/serial.log"
}

cmd_ssh() {
	local name=$1 dir
	shift
	dir=$(vmdir "$name")
	# shellcheck disable=SC2046
	exec ssh $(ssh_opts "$dir") lab@127.0.0.1 "$@"
}

cmd_push() {
	local name=$1 dir stage
	dir=$(vmdir "$name")
	stage=$dir/stage
	rm -rf "$stage"
	mkdir -p "$stage/bin"
	(cd "$REPO" && CGO_ENABLED=0 go build -o "$stage/bin/cotty" ./cmd/cotty && CGO_ENABLED=0 go build -o "$stage/bin/probe" ./tests/attacks/probe &&
		CGO_ENABLED=0 go build -o "$stage/bin/cotty-guard" ./cmd/cotty-guard && CGO_ENABLED=0 go build -o "$stage/bin/guardprobe" ./tests/attacks/guardprobe)
	cp -r "$REPO/tests" "$REPO/profiles" "$REPO/dist" "$stage/"
	# shellcheck disable=SC2046
	ssh $(ssh_opts "$dir") lab@127.0.0.1 'rm -rf ~/cotty && mkdir -p ~/cotty'
	# shellcheck disable=SC2046
	tar -C "$stage" -cf - . | ssh $(ssh_opts "$dir") lab@127.0.0.1 'tar -C ~/cotty -xf -'
	# Installed root-owned, as a package would: the broker trusts a person
	# attach only from a binary the user cannot replace, and where the
	# AppArmor profile is loaded (Ubuntu) only the installed path may
	# create user namespaces.
	# shellcheck disable=SC2046
	ssh $(ssh_opts "$dir") lab@127.0.0.1 'sudo install -o root -g root -m 0755 ~/cotty/bin/cotty /usr/local/bin/cotty'
	echo "vm.sh: pushed to $name:~/cotty"
}

cmd_matrix() {
	local name=$1 dir out
	dir=$(vmdir "$name")
	cmd_push "$name"
	out=$dir/matrix-$(date +%Y%m%d-%H%M%S).txt
	# shellcheck disable=SC2046
	ssh $(ssh_opts "$dir") lab@127.0.0.1 'C=~/cotty/bin/cotty; [ -x /usr/local/bin/cotty ] && C=/usr/local/bin/cotty; COTTY=$C PROBE=~/cotty/bin/probe bash ~/cotty/tests/attacks/run.sh' | tee "$out"
	echo "vm.sh: report in \$COTTY_LAB/${out#"$LAB"/}"
}

cmd_broker_matrix() {
	local name=$1 dir out
	dir=$(vmdir "$name")
	cmd_push "$name"
	out=$dir/broker-matrix-$(date +%Y%m%d-%H%M%S).txt
	# shellcheck disable=SC2046
	ssh $(ssh_opts "$dir") lab@127.0.0.1 'COTTY=/usr/local/bin/cotty PROBE=~/cotty/bin/probe bash ~/cotty/tests/attacks/broker.sh' | tee "$out"
	echo "vm.sh: report in \$COTTY_LAB/${out#"$LAB"/}"
}

cmd_claude_config() {
	local name=$1 dir out
	dir=$(vmdir "$name")
	cmd_push "$name"
	out=$dir/claude-config-$(date +%Y%m%d-%H%M%S).txt
	# shellcheck disable=SC2046
	ssh $(ssh_opts "$dir") lab@127.0.0.1 'COTTY=/usr/local/bin/cotty bash ~/cotty/tests/attacks/claude-config.sh' | tee "$out"
	echo "vm.sh: report in \$COTTY_LAB/${out#"$LAB"/}"
}

cmd_apparmor() {
	local name=$1 dir
	dir=$(vmdir "$name")
	# shellcheck disable=SC2046
	ssh $(ssh_opts "$dir") lab@127.0.0.1 'sudo tee /etc/apparmor.d/cotty >/dev/null && sudo apparmor_parser -r /etc/apparmor.d/cotty' <"$REPO/dist/apparmor/cotty"
	echo "vm.sh: AppArmor profile loaded in $name"
}

# cmd_guard installs cotty-guard and its unit in the VM (from the last
# push) and starts, stops or restarts it; layer 3 runs only in VMs.
cmd_guard() {
	local name=$1 action=${2:-start} dir
	dir=$(vmdir "$name")
	case $action in
	start | restart)
		# shellcheck disable=SC2046
		ssh $(ssh_opts "$dir") lab@127.0.0.1 'sudo install -m 0755 ~/cotty/bin/cotty-guard /usr/bin/cotty-guard &&
			sudo install -m 0644 ~/cotty/dist/systemd/cotty-guard.service /etc/systemd/system/cotty-guard.service &&
			sudo systemctl daemon-reload && sudo systemctl restart cotty-guard && sleep 1 && systemctl is-active cotty-guard && cotty-guard status'
		;;
	stop)
		# shellcheck disable=SC2046
		ssh $(ssh_opts "$dir") lab@127.0.0.1 'sudo systemctl stop cotty-guard; systemctl is-active cotty-guard || true'
		;;
	*) die "usage: vm.sh guard NAME [start|restart|stop]" ;;
	esac
}

cmd_stop() {
	local name=$1 dir i
	dir=$(vmdir "$name")
	running "$dir" || { echo "vm.sh: $name is not running"; return 0; }
	# shellcheck disable=SC2046
	ssh $(ssh_opts "$dir") lab@127.0.0.1 'sudo systemctl poweroff' >/dev/null 2>&1 || true
	for i in $(seq 1 30); do
		running "$dir" || { echo "vm.sh: $name stopped"; return 0; }
		sleep 2
	done
	kill "$(cat "$dir/qemu.pid")"
	echo "vm.sh: $name killed"
}

cmd_destroy() {
	local name=$1 dir
	dir=$(vmdir "$name")
	[ -f "$dir/.cotty-lab" ] || die "$dir was not made by this script; not deleting"
	cmd_stop "$name"
	rm -rf "$dir"
	echo "vm.sh: $name deleted"
}

cmd_list() {
	local d
	for d in "$LAB"/*/; do
		[ -f "$d/disk.qcow2" ] || continue
		printf '%-24s %-12s %s\n' "$(basename "$d")" "$(cat "$d/distro" 2>/dev/null || echo '?')" "$(running "$d" && echo running || echo stopped)"
	done
}

[ $# -ge 1 ] || die "usage: vm.sh create|start|ssh|push|matrix|broker-matrix|claude-config|guard|apparmor|stop|destroy|list ..."
c=$1
shift
case $c in
create) [ $# -eq 2 ] || die "usage: vm.sh create NAME DISTRO"; cmd_create "$@" ;;
start | push | matrix | apparmor | stop | destroy) [ $# -eq 1 ] || die "usage: vm.sh $c NAME"; "cmd_$c" "$1" ;;
broker-matrix | claude-config) [ $# -eq 1 ] || die "usage: vm.sh $c NAME"; "cmd_${c//-/_}" "$1" ;;
ssh) [ $# -ge 1 ] || die "usage: vm.sh ssh NAME [CMD...]"; cmd_ssh "$@" ;;
guard) [ $# -ge 1 ] || die "usage: vm.sh guard NAME [start|restart|stop]"; cmd_guard "$@" ;;
list) cmd_list ;;
*) die "unknown command $c" ;;
esac
