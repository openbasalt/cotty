# cotty build, checks and lab targets.
#
# Every build is static and without cgo (CGO_ENABLED=0): the confinement
# drops capabilities on all threads with syscall.AllThreadsSyscall, which
# Go refuses in cgo binaries, and the binary must run on any distribution.
# cmd/cotty/nocgo.go makes a cgo build of cotty fail at compile time
# (race detector builds excepted).
#
# The host only builds and runs unit tests. Everything that runs cotty
# (sessions, confinement, escape matrix, agent CLIs) runs in lab VMs
# (vm-* targets; see tests/lab/vm.sh, tests/lab/vm-broker.sh,
# tests/e2e/vm.sh).

GO ?= go
export CGO_ENABLED := 0
BIN ?= bin
VM ?= cotty-e-fedora44
LDFLAGS ?= -s -w

.PHONY: all build bpf test vet fmt-check check clean vm-integration vm-e2e vm-matrix vm-broker-matrix vm-claude-config

all: check build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/cotty ./cmd/cotty
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/cotty-guard ./cmd/cotty-guard
	$(GO) build -trimpath -o $(BIN)/probe ./tests/attacks/probe
	$(GO) build -trimpath -o $(BIN)/guardprobe ./tests/attacks/guardprobe

# Regenerate the guard's BPF object and Go bindings
# (internal/guard/daemon/guardbpf_bpfel.{go,o}) from bpf/guard.bpf.c and
# commit both. Needs clang (BPF target) and llvm-strip, for example in a
# lab VM (dnf install clang llvm). The Go side of bpf2go needs no cgo.
bpf:
	cd internal/guard/daemon && $(GO) generate ./...

# Pure unit tests: no PTY, no shell, no namespaces (safe on any host).
test:
	$(GO) test ./internal/... ./cmd/...

vet:
	$(GO) vet ./...
	$(GO) vet -tags vmtest ./tests/...

fmt-check:
	@out=$$(gofmt -l cmd internal tests profiles); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

check: fmt-check vet test

clean:
	rm -rf $(BIN)

# Lab VMs on a lab host (tests/lab), never on a workstation you care about.
vm-integration:
	tests/lab/vm-broker.sh test

vm-e2e:
	tests/e2e/vm.sh test

vm-matrix:
	tests/lab/vm.sh matrix $(VM)

vm-broker-matrix:
	tests/lab/vm.sh broker-matrix $(VM)

vm-claude-config:
	tests/lab/vm.sh claude-config $(VM)
