# cotty: a terminal shared by a person and an AI agent

Status: design document, written 2026-11-03 and kept current. The name
`cotty` stands for co-TTY. Repo: `openbasalt/cotty`. Language: Go.
License: Apache-2.0.

## 1. Goal

One real terminal session that a person and an AI coding agent use at the
same time:

- the agent reads the screen and types, through MCP, so any agent that
  speaks MCP works (Claude Code, Codex CLI, Gemini CLI, Cursor CLI, Aider,
  opencode, IDE agents);
- the person sees everything the agent types, can type at any moment and
  can always take the keyboard back;
- secret input (password prompts) never reaches the agent: the agent learns
  that a secret prompt started and ended, and then follows the result;
- a list of known secrets is masked in everything the agent reads;
- the agent process cannot go around cotty to get what cotty hides: same
  isolation principle for every agent, enforced by the kernel where it can
  be.

Works on any modern Linux (Fedora, Ubuntu, Debian, Arch). Basalt OS ships it
and adds its SELinux domains, but nothing depends on Basalt.

## 2. Threat model

Assets: what the person types while a secret prompt is active; secrets that
appear on screen; the person's view of the session (it must be honest);
the person's credentials outside the session.

Adversary: the agent process tree, assumed prompt-injected or buggy, running
as the person's uid. It may run any program it is allowed to, read and write
its project, open sockets, and type into the shared session through MCP.

In scope:

1. The agent reads secret input: through MCP, through the person's attach
   client, by opening the session's /dev/pts slave and reading competing
   input, by ptrace or /proc/PID/mem of the broker or the attach client, by
   X11 keylogging of the terminal emulator, by TIOCSTI or TIOCLINUX.
2. The agent reads unmasked output: by attaching as a person, by reading the
   broker's memory, its scrollback log or its secret list.
3. The agent forges the person's view or authority: fake password prompts,
   writing to the session's pts, confirming its own commands, taking the
   person role on the socket.
4. The agent escapes its confinement: moving out of its cgroup, dropping the
   Landlock domain, gaining privileges (setuid, sudo).

Out of scope, stated plainly in the docs:

- Commands the agent types into the shared shell run with the person's
  rights. That is the purpose of the tool. The defences there are
  visibility (every agent keystroke is shown and marked), an optional
  approve-before-run policy, and masking of known secrets. A command such as
  `cat ~/.config/x/token` shows a secret the masking list does not know.
- A secret typed with echo on (for example `export TOKEN=...`) is visible
  unless the person used private mode (5.4) or the value is on the list.
- A malicious kernel or root.

## 3. Architecture

```
person's terminal ── cotty attach ──┐                       ┌── shell (bash/zsh/fish)
                                    ├── broker (per session)├── PTY master/slave
agent ── stdio ── cotty mcp ────────┘   vt screen, roles,   └── commands
 (confined by cotty agent)              masking, audit
                                        │
                                optional: cotty-guard (root, BPF LSM)
```

- broker: one process per session (`cotty new`). Owns the PTY master, a vt
  emulator (screen grid plus scrollback), input arbitration, secret-input
  detection, masking, audit. Unix socket in `$XDG_RUNTIME_DIR/cotty/`.
  Non-dumpable (PR_SET_DUMPABLE 0), secret list in mlocked memory.
- attach client (`cotty attach`): raw passthrough of the real screen plus a
  status line drawn by cotty (who has the keyboard, lock indicator, agent
  activity). Only a connection the broker classifies as person gets the
  unmasked stream and may confirm anything.
- MCP server (`cotty mcp`): stdio JSON-RPC, started by the agent as its MCP
  server, so it inherits the agent's confinement. Always classified as
  agent.
- launcher (`cotty agent -- CMD`): starts any agent CLI confined (layer 2).
- guard (`cotty-guard.service`, optional, root): BPF LSM programs that make
  the confinement and the peer tags unforgeable (layer 3).

### Peer classification (the core rule)

The broker decides a connection's role from what the kernel says about the
peer, never from what the client claims (same rule as basalt-shell's
`internal/shell/peer.go`). Default is agent. Person requires all of:

- SO_PEERCRED uid equals the broker's uid;
- the peer is in the broker's own user and pid namespaces (an agent runs in
  its own, section 4), is not in an agent cgroup, is not tagged by the guard
  (layer 3), and is not a descendant of the session's shell (commands typed
  in the session cannot attach as the person);
- the peer has a controlling terminal that is not a cotty session pts;
- the peer's executable is the installed cotty binary (root-owned, not
  writable by the user);
- on SELinux systems with the Basalt policy: SO_PEERSEC is not an agent
  domain.

Only the first person attach of a session (the creator, `cotty new`) is
automatic. Any later person attach proves the reattach code (shown at
detach), and while a person is attached it must also be approved with a
hotkey in that person's client, which shows the new client's pid,
program, terminal and first two parents. This closes the case where something
outside the agent's reach (for example a process the systemd user manager
started on someone's request) passes every kernel check above. The code
is proven, never sent, and the broker proves it back, so the client also
knows it reached the session's broker (docs/protocol.md section 7).

The resulting assurance is reported, like basalt-shell's modes: `strong`
(guard loaded, the session's pts protection confirmed by the guard, and
the agent tagged by it and under layer 2), `confined` (layer 2 active, no
guard; or the guard without layer 2), `weak` (agent not started through
`cotty agent`; the docs say what that means), `insecure` (development
only).

## 4. Enforcement layers

Layer 1, userland: broker, roles, masking. Always on.

Layer 2, unprivileged confinement (`cotty agent`), works on any kernel with
Landlock; degrades with a clear `cotty doctor` report:

Landlock alone cannot mediate connect() to pathname Unix sockets on the
kernels we target (it covers files, device opens, ioctl on devices from
ABI 5, abstract socket and signal scoping from ABI 6; check during WP-C
whether ABI 8 or 9 added a right for pathname Unix sockets). So the
well-known sockets (D-Bus session bus and with it the keyring, the systemd
user manager, ssh-agent, gpg-agent, terminal remote control, tmux and
screen, X11 and Wayland) are removed from the agent's view with namespaces,
not with environment variables. The launcher works like bubblewrap:

- cgroup first: the launcher, still outside, creates the agent's scope
  (`systemd-run --user --scope` or a delegated cgroup), then unshares;
- user, mount, pid and ipc namespaces (uid mapped to itself): a private
  `/proc` (the agent sees only its own processes), a private devpts instance
  (the agent's terminal comes from it, so no cotty session pts and no
  person terminal is visible), a tmpfs over `$XDG_RUNTIME_DIR` with only the
  cotty agent socket bound in, tmpfs over `/tmp/.X11-unix`, the rest of
  `$HOME` hidden except the project and the profile's own dirs;
- the agent never reaches the systemd user manager or D-Bus, so it cannot
  ask them to start anything outside its confinement (the `systemd-run
  --user` escape);
- Landlock on top, as defence in depth: system dirs read and execute;
  read-write only the project, the profile's home and a private tmp; ABI 6
  scoping of abstract Unix sockets (X11's `@/tmp/.X11-unix/X0`, abstract
  D-Bus addresses) and signals;
- seccomp, installed last: deny ptrace, process_vm_readv/writev, bpf,
  perf_event_open, userfaultfd, io_uring setup, mount, unshare and clone
  with any new namespace flag (no nested user namespaces), TIOCSTI and
  TIOCLINUX ioctls, kernel keyring syscalls; no_new_privs (so sudo and
  setuid fail inside the agent; the agent asks the person to run privileged
  commands in the shared session, where the person types the password
  safely);
- file descriptors: everything except stdio closed before exec;
  RLIMIT_CORE 0;
- environment scrub as hygiene: SSH_AUTH_SOCK, GPG_AGENT_INFO,
  DBUS_SESSION_BUS_ADDRESS, DISPLAY, WAYLAND_DISPLAY, KITTY_LISTEN_ON,
  WEZTERM_UNIX_SOCKET, TMUX, STY, KONSOLE_DBUS_*, cloud credential variables;
- Yama ptrace_scope >= 1 checked;
- Ubuntu 24.04 and later restrict unprivileged user namespaces through
  AppArmor; the deb ships an AppArmor profile for the launcher, as
  bubblewrap does, and `cotty doctor` explains the state;
- the shared session's shell keeps HISTFILE and any shell integration state
  outside every agent project, and session children get RLIMIT_CORE 0.
- profiles per agent, same INI format as basalt-agent: claude, codex,
  gemini, cursor-agent, aider, opencode, generic. GUI IDE agents (Cursor,
  VS Code, Windsurf) are phase 4 with an explicitly weaker profile on X11.
- Network filtering is not in cotty v1 (basalt-agent does it on Basalt);
  optional Landlock TCP connect rules by port where ABI 4 exists.

Layer 3, kernel enforcement (`cotty-guard`, root, optional): BPF LSM via
cilium/ebpf. No out-of-tree kernel module: no DKMS, no per-distro builds, no
Secure Boot signing, and the verifier rules out crashing the kernel. A
module is reconsidered only if a required rule cannot be written as BPF LSM.

- tags: the agent's cgroup id is registered with the guard (`agent:<id>`),
  and every task in that cgroup or below it is an agent, whatever spawned
  it; task storage additionally carries the tag, copied explicitly in
  `task_alloc` (task storage is not inherited by itself) and set in
  `bprm_creds_for_exec`. Tagging only restricts, so any process may ask to
  tag itself or its own cgroup; the guard's socket rejects untagging and
  tagging another pid;
- hooks and rules for agent tasks: `ptrace_access_check` (deny any target
  outside the agent), `file_open` (deny `/proc/PID/{mem,environ,fd,maps}`
  of other tasks, cotty session pts, `/dev/input`, `/dev/uinput`, writes to
  `cgroup.procs`, which is how cgroup migration is blocked),
  `unix_stream_connect` and `socket_connect` (deny every Unix socket except
  the cotty agent socket and an allowlist from the profile; this is the
  mediation Landlock lacks), `bprm_creds_for_exec` (deny setuid and file
  capability exec), `bpf` (deny);
- the broker asks the guard for a peer's tag (by pid via a pinned map), so
  classification no longer depends on cgroups the user owns;
- broker registry: a broker registers with the guard under its session
  name before it binds its sockets (the installed root-owned binary only,
  not traced, never with `--dev-insecure`); the first live registrant
  keeps the name, only registered brokers may change the runtime
  directories, and a socket a broker claimed is its own while it runs;
- the broker protects the session pts while the new pty is still locked,
  before anything can open it, and only a registered broker holding the
  master may protect a pts;
- `verify-broker`: the attach client asks the guard, as root, whether the
  listener is the registered broker of that session, and refuses to run
  when the guard is installed but its daemon does not answer;
- enforcement kept across a stop and a restart: maps and links stay
  pinned, an upgrade migrates maps that only grew and refuses one whose
  layout changed (the old programs keep enforcing); only `cotty-guard
  uninstall` ends it;
- every denial goes to the audit log.

Checked when the plan was written: Fedora with kernels 6.19, 7.0 and
7.1 (Landlock ABI 7 to 9) has `bpf` and `landlock` in the active LSM
list, ptrace_scope 1 and legacy TIOCSTI off. Whether other distros put
`bpf` in the active `lsm=` list by default (and ship BTF) is unverified;
WP-F checks Ubuntu, Debian and Arch in VMs. The guard reads
`/sys/kernel/security/lsm`, reports and exits cleanly where it is missing.

On Basalt, `basalt-agent` sessions (SELinux `basalt_agent_t` or
`container_t`) are recognized as agents through SO_PEERSEC, and a
`basalt_cotty` policy module is a later phase.

## 5. Behaviour

### 5.1 Input arbitration

- The person's keystrokes always go through immediately.
- Agent input is refused while the person typed in the last 1.5 s or holds
  the keyboard (hotkey to take/give it), and always while secret input is
  active.
- Agent keystrokes are shown in the status line as they are sent and kept
  in the audit log with the author.
- Policy `confirm` (per session): agent text is typed but the Enter the
  agent sends is held; the person sees "agent wants to run: LINE" and
  accepts with a hotkey. Only a person connection can accept.

### 5.2 Secret input detection

A secret prompt is detected on the PTY's termios: ECHO off with ICANON on
(getpass, sudo, ssh, passwd, `read -s` all do this). Raw mode programs
(shell line editors, vim, less) turn ICANON off too, so they are not
mistaken for secret prompts. Known secret programs that use raw mode
(pinentry-curses and similar, matched by executable path) are added from an
extensible list. A setuid-root process in raw mode that has started no
child yet is a password prompt too (sudo-rs and `sudo` with `pwfeedback`
read in raw mode and print asterisks; once sudo runs its command it has a
child and is not). Known false negative, documented: a raw mode program
that is not setuid root and draws its own password field; for it the person uses
private mode (5.4), and the lock stays off, which is the signal. The kernel
sends no notification of termios changes (packet mode reports flow control
only), so the broker polls tcgetattr on the master before forwarding each
batch of person input and on every output chunk. After any transition the
broker holds person input for a short grace window (50 ms) and re-reads
termios, so the first keystrokes after a prompt appears are classified with
the new state. After an Enter at the shell prompt (the person's, the
agent's, or an agent line the person accepted) person input is held for
up to 150 ms or until a secret prompt is detected, so a password typed
ahead of a prompt is not echoed before the program turns echo off.

While secret input is active:

- person bytes go to the PTY and nowhere else: not to the vt model's input
  log, not to the audit log (only "secret input, N keystrokes", count
  optional and off by default), not to MCP;
- agent input is refused with a typed error;
- MCP reports `secret_input: active` with the foreground program, then
  `ended` (Enter seen, or termios restored), so `term_wait` can return;
  agents get one state change at the start and one at the end, none per
  keystroke.

Lock indicator: drawn by cotty in the person's status line (never by
anything the session prints), judging every process of the PTY's
foreground process group (tcgetpgrp, then `/proc/PID/exe` of each), named
after the executable judged (with the name it was started under when
that differs: `head (as sudo)`):

- green: every member is a root-owned system binary not writable by the
  user and not an interpreter (sudo, ssh, passwd);
- amber: anything else (a shell builtin such as `read -s`, a script, a user
  binary, an interpreter anywhere in a pipeline), and a note when the
  foreground job was started by an agent line.

The rule taught to people: type a password only when the lock is lit, and
look at the program it names. A fake prompt printed with echo on never
lights the lock.

### 5.3 What the agent reads

- `screen`: the rendered grid as text, cursor position, with masking.
- `since`: lines committed to scrollback since a cursor, with masking.
- state: who has the keyboard, secret input, foreground program, last
  command and exit code when shell integration (OSC 133) is present. OSC
  133 marks are hints only (a program can print them).

Masking runs on rendered text, after the vt model, so escape sequences and
chunk boundaries cannot split a secret past the filter. Rows that change
while private mode is on stay masked in the agent's view until every
column of them is rewritten or erased after it ends, wherever they move,
and lines that scroll away with them stay masked for good; rows are
marked by cell, never matched by text (docs/vt.md).

### 5.4 Private mode

A person hotkey toggles private mode: the agent's view freezes and reports
`private: true`; rows written during it stay masked as above. The agent
cannot turn it on or off. Private mode hides rows, not what programs keep:
shell history, a redraw or a pager can print the text again after it ends
(docs/security.md, Known limits).

### 5.5 Masking list

- literal values from secret sources, referenced by name: a 0600 file
  (`~/.config/cotty/secrets.env`), the Secret Service (libsecret), `pass`,
  or an external command (`cotty secrets add NAME --command '...'`, used
  for a vault or password manager CLI). The agent may ask to mask a secret by name
  (`term_mask`), never to read one;
- common encodings of each value (base64, URL encoding, hex);
- rules for well-known token formats (cloud keys, GitHub tokens, private
  key blocks, JWTs); a high-entropy heuristic stays off by default;
- replacement text `[masked:NAME]`.

### 5.6 MCP tools

`term_sessions`, `term_read` (screen or since cursor, plus state),
`term_type` (text, optional Enter), `term_keys` (named keys such as C-c,
Up), `term_run` (type, Enter, wait for prompt or idle, return the masked
output and exit code), `term_wait` (idle, prompt, regex on masked text,
secret input ended; timeout), `term_mask` (add a secret by name),
`term_request_keyboard`. A session is visible to agents only when the
person created it with `--ai` or ran `cotty share SESSION`.

### 5.7 Audit

Hash-chained JSON lines (basalt-agent format and code): session start and
end, attaches with role and assurance, agent lines typed, confirmations,
secret input start and end (never content), masking hits by name, guard
denials. On Basalt it also forwards to basalt-ledger.

## 6. Reuse of our code

The pieces live in `internal/` packages, so they are copied with a
provenance line (same license, Apache-2.0); a shared module comes later
if a third user appears.

- basalt-agent (basalt-os/basalt-os, packages/basalt-agent): profile INI
  parser and profiles, audit hash chain, secrets store reader, session id
  format, ledger forwarder, `tests/attacks.sh` and `credattacks.sh` escape
  matrix ideas.
- basalt-shell: `internal/mcp` (stdio JSON-RPC MCP server), peer
  classification pattern (`internal/shell/peer.go`), `internal/harden`.
- tui-kit: theme colours for the status line, if it stays dependency-light.

## 7. Layout

```
cmd/cotty/            subcommands: new, attach, ls, share, agent, mcp, secrets, doctor
cmd/cotty-guard/      layer 3 daemon
internal/broker/      PTY, vt model, arbitration, secret detection, sessions
internal/proto/       socket protocol (docs/protocol.md is the contract)
internal/peer/        classification and assurance
internal/mask/        masking engine and rules
internal/secretsrc/   secret sources
internal/confine/     Landlock, seccomp, cgroup, env scrub, profiles
internal/mcp/         MCP server and tools
internal/audit/       hash-chained log
bpf/                  BPF LSM programs (C, built with bpf2go)
profiles/             agent profiles
tests/attacks/        escape matrix, run as a confined agent
docs/                 PLAN, protocol, threat model, agents (one page per agent CLI)
```

Dependencies kept small: creack/pty, a vt emulator (charmbracelet/x/vt,
fallback hinshun/vt10x; the first work package checks which renders
correctly), landlock-lsm/go-landlock, a pure Go seccomp builder
(elastic/go-seccomp-bpf), cilium/ebpf.

## 8. Work packages

Phase 0: this plan and `docs/protocol.md`, reviewed before any code.

Phase 1, in parallel:

- WP-A broker: PTY, vt model, sessions, socket protocol, attach client with
  status line, arbitration, secret detection, private mode, audit. Tests:
  sudo, ssh, `read -s`, passwd prompts and raw mode programs; fuzzed output.
- WP-B masking and secret sources: pure library with fuzz tests (secrets
  split across chunks, inside escape sequences, wrapped across rows,
  encodings).
- WP-C confinement: `cotty agent`, `cotty doctor`, profiles, Landlock,
  seccomp, cgroup, env scrub; escape matrix run inside a confined shell.

Phase 2, after WP-A:

- WP-D MCP server and agent integration: tools, `cotty mcp`, docs and
  config snippets for Claude Code, Codex, Gemini CLI, Cursor CLI, opencode;
  end to end test where a real Claude Code (`claude -p`) drives a session in
  a lab VM and a scripted person types a sudo password; the transcript
  and MCP log are checked for the password and the masked values.
- WP-E integration of A, B, C: peer classification with assurance levels;
  the escape matrix now also targets the broker (attach as person, open
  the session pts, read broker memory).

Phase 3:

- WP-F guard: BPF LSM programs, tags, rules, map lookup for the broker,
  audit; tested in lab VMs: Fedora 44, Ubuntu 26.04, Debian 13, Arch. Nothing loads BPF on the host.

Phase 4: packages (RPM and deb in the OpenBasalt package repository),
Basalt policy module, GUI IDE profile, docs site page; an independent
security review of the whole result before the first release.

## 9. Where work runs

- Developer machines only build and run pure unit tests.
- Everything that runs cotty (sessions, confinement, escape matrix, agent
  CLIs, the guard, fuzzing) runs inside throwaway VMs on a lab host:
  user-mode qemu with KVM, qcow2 overlays on shared cloud base images
  (`tests/lab/vm.sh`, lab directory `$COTTY_LAB`, VM names prefixed
  `cotty-`). Never on a machine anyone cares about.

## 10. Acceptance

- The escape matrix (section 2 items 1 to 4) is denied at the assurance
  level the docs claim, on Fedora and on Ubuntu, and the report lists any
  item a level does not cover. Required cases include: `systemd-run --user`
  to start `cotty attach` or a shell outside the agent; D-Bus session bus
  and Secret Service reached by path with the environment scrubbed;
  ssh-agent and gpg-agent sockets; kitty, wezterm, tmux and screen remote
  control used to read the real screen; reading the session pts through an
  inherited fd or by path; a nested user namespace; a core dump of a
  session child holding a secret; ptrace and /proc/PID/mem of the broker
  and the attach client; a second person attach without approval.
- sudo with pwfeedback and sudo-rs are detected (setuid root, raw mode,
  no child yet); their asterisks are hidden from agents.
- In the end to end run, no password typed at a secret prompt and no listed
  secret value appears in anything the agent received (MCP log, agent
  transcript, audit log).
- Raw mode programs (vim, less, htop, zsh line editing) never trigger
  secret mode; the five common secret prompts always do.
- The person can interrupt the agent and take the keyboard at any time.

## 11. Design changes

- 2026-11-03, after the design review: Landlock does
  not mediate pathname Unix socket connects, so layer 2 now uses user,
  mount, pid and ipc namespaces to hide D-Bus, the systemd user manager and
  agent sockets; the `systemd-run --user` escape is closed by that and by
  approval of any second person attach; guard tags by cgroup with explicit
  task storage copy and mediates Unix socket connects; termios polling with
  a grace window replaces the packet mode claim; pwfeedback and raw mode
  password fields are documented false negatives; inherited fds, nested
  user namespaces, core dumps, history files and terminal remote control
  sockets added to layer 2 and to the acceptance matrix.
