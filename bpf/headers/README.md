# BPF headers

- `bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_tracing.h`, `bpf_core_read.h`:
  vendored unchanged from libbpf 1.6 (https://github.com/libbpf/libbpf,
  `src/`). libbpf licenses them LGPL-2.1 OR BSD-2-Clause; cotty uses them
  under BSD-2-Clause, whose text and notice are in LICENSE.BSD-2-Clause
  (copied from libbpf). `bpf_helper_defs.h` is generated upstream and has
  no SPDX line there either.
- `cotty_vmlinux.h`: written for cotty, the few kernel types the guard
  reads, declared by hand for CO-RE (Apache-2.0 OR GPL-2.0-only, like
  `../guard.bpf.c`).

`make bpf` regenerates the guard's object and Go bindings from these
headers and `../guard.bpf.c` (docs/guard.md, Building).
