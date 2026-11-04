#!/usr/bin/env bash
# Rough overhead of cotty-guard: a clean `go build ./...` of the cotty
# repository inside `cotty agent`, and a loop of 300000 open/close calls
# (the file_open hook's worst case), with the guard stopped and running,
# alternating, RUNS times each. Run it in a throwaway VM as a user with
# sudo (it starts and stops cotty-guard.service).
#
#   guard-bench.sh SRC [RUNS]   SRC: a checkout of the cotty repository
set -u
SRC=${1:?usage: guard-bench.sh SRC [RUNS]}
RUNS=${2:-3}
HERE=$(cd "$(dirname "$0")" && pwd)
COTTY=${COTTY:-$HERE/../../bin/cotty}
P=$HOME/cotty-bench/project
[ -d "$HOME/cotty-bench" ] && chmod -R u+w "$HOME/cotty-bench"
rm -rf "$HOME/cotty-bench" && mkdir -p "$P"
tar -C "$SRC" --exclude=.git -cf - . | tar -C "$P" -xf -
export GOTOOLCHAIN=local GOFLAGS=-mod=mod GOMODCACHE=$P/.gomod GOPATH=$P/.gopath
(cd "$P" && go mod download) || { echo "go mod download failed" >&2; exit 2; }

build() {
	rm -rf "$P/.gocache"
	local t0 t1
	t0=$(date +%s.%N)
	"$COTTY" agent --quiet --profile generic --project "$P" -- \
		sh -c "cd '$P' && GOCACHE='$P/.gocache' GOMODCACHE='$P/.gomod' GOPATH='$P/.gopath' GOFLAGS=-mod=mod GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 go build ./..." \
		</dev/null >/dev/null 2>"$HOME/cotty-bench/err.txt" || { echo "build failed:" >&2; cat "$HOME/cotty-bench/err.txt" >&2; exit 1; }
	t1=$(date +%s.%N)
	awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }'
}

# opens prints the seconds of 300000 open/close pairs inside the agent.
opens() {
	"$COTTY" agent --quiet --profile generic --project "$P" -- python3 -c '
import os, time
t = time.monotonic()
for _ in range(300000):
    os.close(os.open("/etc/hostname", os.O_RDONLY))
print("%.2f" % (time.monotonic() - t))' </dev/null 2>/dev/null
}

off=()
on=()
ooff=()
oon=()
for i in $(seq "$RUNS"); do
	sudo systemctl stop cotty-guard
	off+=("$(build)")
	ooff+=("$(opens)")
	sudo systemctl start cotty-guard
	sleep 1
	on+=("$(build)")
	oon+=("$(opens)")
done
median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
mo=$(median "${off[@]}")
mn=$(median "${on[@]}")
echo "kernel $(uname -r), $(. /etc/os-release && echo "$PRETTY_NAME"), $(nproc) cpus"
echo "clean go build ./... of cotty inside cotty agent, $RUNS runs each (seconds)"
echo "guard stopped: ${off[*]} (median $mo)"
echo "guard running: ${on[*]} (median $mn)"
awk -v o="$mo" -v n="$mn" 'BEGIN { printf "overhead: %.1f%%\n", (n - o) * 100 / o }'
oo=$(median "${ooff[@]}")
on2=$(median "${oon[@]}")
echo "300000 open/close of /etc/hostname inside cotty agent (seconds)"
echo "guard stopped: ${ooff[*]} (median $oo)"
echo "guard running: ${oon[*]} (median $on2)"
awk -v o="$oo" -v n="$on2" 'BEGIN { printf "overhead: %.1f%%, %.2f microseconds per open\n", (n - o) * 100 / o, (n - o) * 1e6 / 300000 }'
