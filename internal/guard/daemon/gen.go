// Package daemon is the root side of cotty-guard: it loads and attaches
// the BPF LSM programs of bpf/guard.bpf.c, pins their maps and links under
// /sys/fs/bpf/cotty, serves the unprivileged socket of package guard and
// writes denials to the audit log. Only cmd/cotty-guard imports it, so the
// cotty binary itself never links cilium/ebpf.
package daemon

// The BPF object and its Go bindings (guardbpf_bpfel.go and .o) are
// generated from bpf/guard.bpf.c and committed, so `go build` needs no
// clang. Regenerate with `make bpf` (clang and llvm-strip required; see
// docs/guard.md).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel -type event -type tag -type file_key -type pts_owner -type broker_name -type broker_reg -type exe_key -type exe_val -type exc_use guardbpf ../../../bpf/guard.bpf.c -- -I../../../bpf/headers
