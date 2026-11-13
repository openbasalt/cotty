# Agent confinement (layer 2): `cotty agent` and `cotty doctor`

`cotty agent` starts an AI coding agent CLI so that it cannot go around
cotty to get what cotty hides: your keys and keyring, your other
terminals, your session bus and systemd user manager, other processes and
their memory, and privileges. It needs no root and no setuid helper, and
works on any kernel with unprivileged user namespaces. It is layer 2 of
the plan (docs/PLAN.md, section 4); layer 3 (`cotty-guard`, BPF LSM) is
optional, see [guard.md](guard.md).

```
cotty agent [--profile P] [--project DIR] [--ro PATH] [--rw PATH] [--agent-dir DIR] [--no-mcp]
            [--allow-git-init] [--allow-git-links] [--allow-abstract-sockets] [--quiet] [--] CMD [ARGS...]
cotty agent --profile claude              # runs the profile's own command
cotty agent --list-profiles
cotty agent --dry-run -- claude -p hi     # print the computed plan as JSON
cotty doctor [--json]                     # what this system offers, in plain words
```

Without `--profile` the profile is guessed from the command's name
(`claude`, `codex`, `gemini`, `cursor-agent`, `aider`, `opencode`), else
`generic`. Without `--project` the current directory is the project.
`cotty agent` refuses a project (and a `--ro` or `--rw` path) that is `/`,
your home directory or one of its parents, a credential store (`~/.ssh`,
`~/.gnupg` and similar), cotty's own configuration (`~/.config/cotty`, the
masking list and its values) or state (`~/.local/state/cotty`, the audit
log and session history), or a directory that contains one of them (such
as `~/.local` or `~/.config`). `$XDG_CONFIG_HOME/cotty` and
`$XDG_STATE_HOME/cotty` count too when those variables are set. It also
refuses the places where sockets live, which a bind would put back in
view: `/tmp`, `/var/tmp`, `/dev/shm`, `/run` (and `/var/run`),
`$XDG_RUNTIME_DIR`, anything below `/run`, `/dev/shm` and
`$XDG_RUNTIME_DIR`, a parent of any of them (`/var`, `/run/user`), and
socket directories directly in `/tmp` or `/var/tmp` (`.X11-unix`,
`tmux-UID`, `ssh-*`, `systemd-private-*`, any dot directory and similar);
an ordinary directory such as `/tmp/build` is fine. A `--ro` or `--rw`
path in one of the socket directories cotty hides under `/var`, `/nix`
and `/opt` (`/var/lib/incus`, `/var/lib/mysql` and the others listed
below) is refused; a parent of one (`--ro /var/lib`) is accepted, and the
socket directories below it stay covered. `--agent-dir` must be
cotty's own agent endpoint directory (or one shaped like it: a directory
named `agent` in a `cotty` runtime directory, yours, mode 0700).

## What the agent sees

| Resource | Inside the confinement |
| --- | --- |
| `$HOME` | an empty tmpfs; the project, the profile's own directories and `~/.gitconfig` (read-only) are put back on top. Anything else the agent writes to `~` is lost when it exits. |
| project | read-write, except what git runs with your rights the next time you use git there: see "What git runs" below |
| `/tmp`, `/var/tmp`, `/dev/shm` | private, empty tmpfs |
| `$XDG_RUNTIME_DIR` | a private directory (mode 0700) holding only `cotty/`, a small read-only tmpfs with the cotty agent endpoint directory (`$XDG_RUNTIME_DIR/cotty/agent/`, read-only, one socket per session shared with agents) and the cotty binary (`$XDG_RUNTIME_DIR/cotty/bin/cotty`, first in `PATH`); `cotty/` itself cannot be renamed or added to |
| `/run` | an empty tmpfs; only DNS resolver files, the journal socket, nscd and NixOS system paths are put back |
| `/dev` | a private tmpfs with `null`, `zero`, `full`, `random`, `urandom`, `tty`, a new devpts instance (only the agent's own pty exists in it) and its own `/dev/shm` and `/dev/mqueue` |
| `/proc` | of the agent's own pid namespace: only its own processes |
| `/sys/fs/cgroup` | read-only, seen from the agent's cgroup namespace: its own scope is the root |
| system directories | read and execute (`/usr`, `/etc`, `/opt`, `/var` and the rest); not readable: other homes, `/root`, `/boot`, `/mnt`, `/media`, `/srv`. Covered with an empty tmpfs: known socket directories under `/var`, `/nix` and `/opt` (incus, LXD, libvirt, MySQL, PostgreSQL, docker, containerd, podman, tailscale, postfix, cups, the nix daemon and others, `internal/confine/plan.go`), the journal (`/var/log/journal`) and the mail spool |
| network | open, as for any program of yours (out of scope in v1) |

Environment: built from an allowlist (`internal/confine/env.go`), because
a token in the environment needs no socket to be useful and the network is
open. What passes: user and terminal basics (`USER`, `SHELL`, `TERM`,
`COLORTERM`, `TERM_PROGRAM`, `LANG`, `LC_*`, `TZ`, `EDITOR`, `PAGER`,
colour switches), the XDG base directories, proxies and certificate
bundles (`HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE` and similar; a proxy URL can
carry a password and passes all the same), and toolchain locations and
build flags (`GOPATH`, `GOFLAGS`, `CARGO_HOME`, `JAVA_HOME`, `NVM_DIR`,
`VIRTUAL_ENV`, `CC`, `CFLAGS` and similar). Everything else is removed: key agent
and session bus addresses, display and compositor sockets, terminal and
multiplexer remote control, cloud, forge, database and payment
credentials, whatever their names. A profile lets more through with
`[scrub] keep = NAME` or `PREFIX*` (each built-in profile keeps the model
provider variables its CLI reads, such as `ANTHROPIC_*` for Claude Code;
nothing else gets them) and removes allowed ones with `drop`. The agent
gets `COTTY_AGENT=<profile>`, `COTTY_AGENT_DIR` and `COTTY_ASSURANCE`;
other `COTTY_*` variables never pass.

### The agent endpoint

Every session shared with agents has a socket in
`$XDG_RUNTIME_DIR/cotty/agent/`, served by its broker (docs/protocol.md
section 1); connections there only get the agent role. `cotty agent`
creates that directory when it is missing and binds the directory, not a
socket, read-only into the confinement. So:

- an agent started before any session exists, or before you share one,
  sees the session as soon as you share it;
- a session restarted (same or other name) shows up again without
  restarting the agent;
- hiding a session (`cotty share --off`) removes its socket from the
  agent's view at once;
- the agent cannot plant a socket there that another agent would take for
  a session (read-only mount), and connecting needs no write access;
- the main session sockets, metadata and broker logs, in
  `$XDG_RUNTIME_DIR/cotty/` itself, are not visible.

On Landlock ABI 9 and later the directory is also on the list of pathname
sockets the agent may connect to.

### What git runs

The person later runs git in the project, outside the confinement, and
git runs programs the repository names. Inside, for the project's git
directory and every git directory that hangs off it (submodule git
directories in `.git/modules/`, linked worktree directories in
`.git/worktrees/`, nested repositories found down to six levels below
the project root, submodule checkouts `.gitmodules` names at any depth,
the real git directory of a `.git` gitfile when it lies in the project):

- `config`, `config.worktree`, `hooks/`, `commondir` and `gitdir` are
  read-only; `config.worktree` and `hooks/` are created empty first when
  they are missing, so the agent cannot plant them;
- the git directory itself, and every directory between the project
  root and a read-only path, is a mount point of its own (a read-write
  bind onto itself): renaming `.git`, `.git/modules` or a worktree
  directory and putting a new one in its place fails with EBUSY;
- `core.hooksPath`, read from the repository's config and from
  `/etc/gitconfig`, `~/.gitconfig` and `~/.config/git/config` (includes
  followed), is read-only when it points into the project, and created
  empty first when missing;
- files named by `include.path` and `includeIf.*.path` that lie in the
  project are read-only (created empty first when missing);
- scripts named by any config value (a word with a `/`, such as
  `filter.x.clean = ./scripts/clean.sh` or an alias `!sh tools/a.sh`)
  that exist in the project are read-only; the program of a command
  setting (`core.fsmonitor`, `core.sshCommand`, `alias.*`, `filter.*`,
  `diff.*.textconv` and similar) written as a path (`./x`, `~/x`) that
  does not exist yet is created empty first, so the agent cannot create
  it;
- hook managers: their shims in the hooks directory run files from the
  work tree. Read-only when they exist: the whole `.husky/` directory
  (Husky v9's stubs in `.husky/_` run `.husky/<hook>`),
  `.pre-commit-config.yaml`, and lefthook's `lefthook.yml`,
  `.lefthook.yml`, `lefthook-local.yml`, `.lefthook-local.yml` (also as
  `.yaml`; the main file also as `.json` and `.toml`), `.lefthook/` and
  `.lefthook-local/`. When a shim of one of them is installed (a hook
  file that names Husky, pre-commit or lefthook) and its configuration is
  missing, it is created first: an empty `.husky/`, a
  `.pre-commit-config.yaml` holding `repos: []`, a `lefthook.yml` and a
  `lefthook-local.yml` holding `{}`. Scripts those files name by path
  (a pre-commit `entry: ./scripts/check.sh`, a lefthook `run:`, a line of
  a Husky hook) that exist are read-only too. An agent that edits these
  files as part of its work gets a permission error;
- a protected git file that is a symbolic link (`.git` itself,
  `.git/config`, `.git/hooks`, `config.worktree`, `commondir`, `gitdir`,
  the `core.hooksPath` directory) in a writable place makes `cotty agent`
  refuse to start: the link cannot be made read-only, and the agent could
  replace it with a file or directory of its own. `--allow-git-links`
  starts anyway, protects what the link points to and prints a note;
- a git directory without a `commondir` file is watched by the launcher
  (inotify, outside): such a file would point git at a config and hooks
  of the agent's choosing, and it cannot be created in advance (git
  would refuse to work), so when the agent creates one, cotty removes it
  and stops the agent;
- a project without `.git` gets an empty read-only `.git` directory for
  the run (removed afterwards when no other agent uses it), so `git init`
  inside fails; `--allow-git-init` turns this off;
- repositories the agent creates (a new `.git` anywhere down to six
  levels) are listed when it exits: their hooks and config would run with
  your rights when you use git there, and `git status` in the project
  enters submodules registered in the index.

The search for nested repositories skips installed dependencies and
caches (`node_modules`, `bower_components`, `.venv`, `__pycache__`,
`.tox`, `.gradle`, `.terraform`, `.next` and similar) and stops after
50000 entries; directories deeper than six levels are not searched. When
the search stops early or leaves deep directories out, `cotty agent`
says so in a note: a repository there is neither protected nor reported.
Paths `.gitmodules` names are protected wherever they are.

The files cotty creates first (empty `hooks/` and `config.worktree`,
hook manager configuration, include files, scripts) stay in the project
after the run, so a later run finds them in place; remove them yourself
if you do not want them. Only the empty `.git` of a project without one
is removed.

Planted configuration is used as soon as anything runs git in that
repository, also while the agent still runs: a shell prompt that shows
the git status (starship, powerlevel10k, oh-my-zsh themes) or an editor
or IDE that runs `git status` when you open or `cd` into the project.
What cotty protects cannot be planted; what it only reports (a new
repository, an in-progress rebase, below) can, and those tools run it.

### The terminal

With a terminal, the agent's output reaches your terminal emulator
through the launcher's relay, which filters escape sequences
(`internal/confine/termfilter.go`). Text, C0 controls, CSI sequences
(colours, cursor, modes) and two-byte ESC sequences pass; of the OSC
commands only 0, 1 and 2 (titles), 7 (current directory), 8 (hyperlinks)
and 133 (prompt marks) pass, re-emitted only once complete and free of
control characters. Every other OSC (52 clipboard, 5113 kitty file
transfer, 1337 iTerm2 file transfer, colour queries), every DCS (kitty
remote control `@kitty-cmd`, tmux passthrough, sixel, terminal queries),
APC (kitty graphics), PM and SOS string, and stray 8-bit C1 bytes are
dropped. The filter keeps its state across reads. What this costs inside:
no inline images, no clipboard writes, no terminal capability queries.

## How it is built

`cotty agent` runs in three stages, like bubblewrap but in Go, so nothing
else needs to be installed:

1. Outside. It computes the plan, then creates the agent's cgroup while
   still outside: it re-executes itself under `systemd-run --user --scope`
   (unit `cotty-agent-<id>.scope`). Without a systemd user manager it
   creates a child of its current cgroup when that cgroup is delegated to
   you. It then starts the init stage with new user, mount, pid, ipc and
   cgroup namespaces, your uid and gid mapped to themselves. With a
   terminal it puts your terminal in raw mode and relays it to a pty that
   the init stage allocated in the agent's devpts instance; your terminal
   never enters the namespaces, so the agent cannot read or inject into
   it, and no cotty session pts is visible.
2. Init, pid 1 of the new pid namespace, not dumpable. It makes `/` a
   slave mount (nothing propagates back out), takes detached copies
   (`open_tree`) of everything that stays visible, marks the read-only
   ones (`mount_setattr`), covers `$HOME`, `/tmp`, `/var/tmp`, `/run` and
   the known socket directories with tmpfs, builds the private `/dev`,
   mounts `/proc` and the cgroup view, puts the copies back
   (`move_mount`), covers again the socket directories that a copy of a
   parent brought back (`--ro /var/lib` holds `/var/lib/incus`, copied
   before it was covered), changes its own directory to `/`, allocates the pty,
   drops every capability (bounding, ambient, permitted, effective) on all
   threads, starts the exec stage, reaps and forwards signals.
3. Exec, the agent's own process. It refuses to continue if it holds any
   capability, sets `RLIMIT_CORE` to 0 (soft and hard), asks AppArmor for
   the agent's own profile when cotty runs under its AppArmor profile
   (below), sets `no_new_privs`, applies Landlock with the best ABI the
   kernel has (refusing an ABI below 6 unless the launcher accepted it),
   installs the seccomp filter last, marks every descriptor above stdio
   close-on-exec and executes the agent.

The plan travels between stages on a pipe, never in the environment or on
the command line.

### Landlock

Rules: system directories read and execute; project, `$HOME` (the tmpfs),
private tmp and runtime directories read-write (write includes create,
remove, rename across directories, truncate); `/dev` read, write and
device ioctl. Read-only binds below a read-write rule stay read-only
through the mount flag. Scopes (ABI 6): abstract Unix sockets and signals
to processes outside the agent's domain are denied, which keeps the agent
away from X11's `@/tmp/.X11-unix/X0`, abstract D-Bus addresses and the
init stage. On ABI 9 and later, connecting to a pathname Unix socket is
denied too, except the cotty agent endpoint directory, the resolver, journal, userdb
and nscd sockets, and sockets the profile allows (`[sockets] allow`).

What each recent ABI adds, checked against the kernel headers of Fedora
44's kernels 6.19 (ABI 7), 7.0 (ABI 8), 7.1 (ABI 9) and 7.2 (ABI 10):

| ABI | Kernel | Adds | Used by cotty |
| --- | --- | --- | --- |
| 6 | 6.12 | scoping of abstract Unix sockets and signals | yes |
| 7 | 6.15 | audit logging flags for `landlock_restrict_self` (`LOG_SAME_EXEC_OFF`, `LOG_NEW_EXEC_ON`, `LOG_SUBDOMAINS_OFF`) | default logging kept |
| 8 | 7.0 | `LANDLOCK_RESTRICT_SELF_TSYNC`: one call restricts every thread of a process | yes, through go-landlock |
| 9 | 7.1 | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`: `connect()` and `sendmsg()` to pathname Unix sockets created outside the domain need the right | yes, as a second wall behind the mount view |
| 10 | 7.2 | UDP bind and connect/send rights; `LANDLOCK_ADD_RULE_QUIET` to keep chosen denials out of the audit log | no (network open in v1) |

Before ABI 9 Landlock cannot stop a connect to a pathname socket that is
visible. The mount view hides the places sockets live (`/run`, `/tmp`,
`$XDG_RUNTIME_DIR`, the known socket directories under `/var`, `/nix` and
`/opt`), but a socket in a directory that stays visible (the project, a
`--ro` or `--rw` path, a system directory cotty does not know about) can
be connected to. The escape matrix has one row that isolates this layer: a
socket created outside in the project directory (visible by design) is
refused on ABI 9 and later and reachable before (a GAP row).

Before ABI 6 nothing scopes abstract sockets. `cotty agent` then reads
`/proc/net/unix` and refuses to start while an abstract socket that
matters listens (X11 displays, D-Bus buses, ICE, input methods, terminal
remote control, PipeWire and PulseAudio), naming them. It also refuses
when the environment names a display or bus that can use one, even if
nothing listens yet (Xwayland and a bus can start while the agent runs):
a local `DISPLAY` (`:0`), any `WAYLAND_DISPLAY`, and a
`DBUS_SESSION_BUS_ADDRESS` with `unix:abstract=` or `unix:tmpdir=`. X11
over TCP (`DISPLAY=host:10`, SSH forwarding) and a bus at a
`unix:path=` address (a pathname socket the mount view hides) do not
count. `--allow-abstract-sockets` accepts the risk. The exec stage refuses a kernel below ABI 6 unless the
launcher made that decision, so Landlock's best-effort mode never drops
the scoping silently.

### Seccomp

A classic BPF filter written in Go (`internal/confine/seccomp_linux.go`),
for x86_64 and aarch64; other architectures run without it and `cotty
doctor` says so. It kills the process on a foreign architecture or x32
entry and returns EPERM for: `ptrace`, `process_vm_readv`,
`process_vm_writev`, `bpf`, `perf_event_open`, `userfaultfd`,
`io_uring_setup`, `mount`, `umount2`, `pivot_root`, `chroot`, the new mount
API (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`,
`mount_setattr`), `setns`, `keyctl`, `add_key`, `request_key`, kexec and
module syscalls, `open_by_handle_at`, `pidfd_getfd`, `process_madvise`,
`acct`, `swapon`, `swapoff`, and on x86_64 `ioperm`, `iopl`, `uselib`;
`clone` and `unshare` with any namespace flag; `kcmp`, `open_tree_attr`;
`ioctl` `TIOCSTI`, `TIOCLINUX` and `TIOCSETD` (the low 32 bits of the
request, as the kernel reads it); `socket` with `AF_ALG` or `AF_VSOCK`
(EAFNOSUPPORT).
`clone3` returns ENOSYS so the C library falls back to `clone`, whose flags
the filter can see (Docker and Flatpak do the same). Consequences: no
debugger or `strace` inside the agent, no containers or nested sandboxes
inside it (including Claude Code's own bubblewrap sandbox), no io_uring
(libuv and others fall back).

## Profiles

Same INI format as basalt-agent. Built in (`profiles/*.conf`), overridable
by a file of the same name in `~/.config/cotty/profiles/` or
`/etc/cotty/profiles/`.

```
[agent]   name, description, command, args, match = NAME...
[home]    rw = REL[/]   ro = REL   protect = REL   hide = REL/   seed = SRC DST   (relative to $HOME)
[paths]   ro = /ABS   rw = /ABS   dev = NAME          (outside $HOME, /dev nodes)
[sockets] allow = /ABS                                (pathname sockets)
[env]     KEY = value                                 (a leading ~/ is your $HOME)
[scrub]   keep = NAME|PREFIX*   drop = NAME|PREFIX*
[mcp]     style = claude | codex | opencode | manual | none
```

`rw` entries ending in `/` are created when missing, so a first login
persists. `protect` means always read-only: a file or directory (ending in
`/`) under an `rw` entry whose content runs with your rights when you
start the CLI yourself (hooks, MCP servers, plugins, commands, rules). A
protected path that is missing is created first, outside and empty (`{}`
for a `.json` file, an empty file or directory otherwise), then bound
read-only, so the agent cannot create it with content of its own; the
placeholder stays afterwards. The directories between the `rw` entry and
a protected path become mount points, so they cannot be renamed away
with the protected path inside. Scripts a protected settings file names
(any quoted string with a path to an existing file in a writable profile
directory: hook commands, status line, key helpers) are read-only too.
Links in `$HOME` (`~/.local/bin/claude`) are recreated as links when their
target is visible, else the target is bound at the link's place. Where a
home entry leads through a link, the target gets the checks a `--ro` or
`--rw` path gets (credential stores, cotty's own files, socket
directories): a link the agent left in a writable directory on an
earlier run (`~/.claude/local -> ~/.ssh`) never gets its target bound. A
`protect` entry that is such a link refuses the start (remove the link);
other entries are left out with a note, and nothing below an `rw` entry
left out that way is created or bound (no placeholder or hidden
directory is made through the link). A `protect` file that is a link to
a place the agent may see (a dotfiles layout: GNU stow, chezmoi's
symlink mode, `~/.claude/settings.json -> ~/dotfiles/claude/settings.json`)
stays read-only: the real file is mounted read-only over the link itself,
so the agent can neither write through the link nor replace it, and at
its own path when the agent could write it there (the dotfiles
repository as the project). A `protect` directory that is a link in a
writable directory refuses the start, since a directory cannot be
mounted over a link: replace the link with the directory (GNU stow:
`--no-folding`). Links inside a protected directory cannot be replaced,
and their targets are read-only too when they lie in a directory the
agent may write. When an `rw` entry is itself a link whose target is
visible (`~/.claude -> ~/dotfiles/claude` with the dotfiles repository
as the project), the protected and hidden paths below it are put in
place at the target. `hide` covers a directory under an `rw` entry with
an empty tmpfs inside, so what is there outside is neither readable nor
writable by the agent; it is created empty outside when missing, a link
or file there refuses the start, the start fails if the directory
cannot be covered (a link on its way inside), and `cotty agent
--show-hidden` leaves it visible. `seed`
copies `~/SRC` to `~/DST` (0600), outside and before the launch, when
`DST` does not exist yet (the claude profile seeds the settings file it
keeps in `~/.claude`); a JSON file is copied without MCP server
definitions and without any key whose name says it holds a credential
(API keys, tokens, secrets, passwords). A profile can never name
`~/.ssh`, `~/.gnupg`, `~/.password-store`, `~/.pki`, `~/.mozilla`,
`~/.aws`, `~/.kube`, `~/.docker`, `~/.config/gh`, `~/.netrc`,
`~/.git-credentials`, `~/.config/gcloud`, `~/.azure`, `~/.npmrc`,
`~/.pypirc`, `~/.cargo/credentials(.toml)`, `~/.vault-token`,
`~/.config/rclone`, the keyring, `~/.config/cotty` or
`~/.local/state/cotty`, nor a directory that contains one of them.
`[scrub] keep = *` (or a prefix shorter than three characters) is
refused: it would pass your whole environment, tokens included.
One page per agent CLI is in `docs/agents/`.

`cotty agent` points the agent at `cotty mcp` without touching its
settings (the endpoint directory always exists, so no broker needs to run
when the agent starts): Claude Code
gets `--mcp-config` (only for a session, not for subcommands such as
`claude mcp`), Codex gets `-c mcp_servers.cotty.*` overrides, opencode
gets `OPENCODE_CONFIG_CONTENT`. Gemini CLI and Cursor CLI need a one-time
entry in their settings, made outside (their settings are read-only
inside). `--no-mcp` turns this off.

## Assurance and `cotty doctor`

`cotty doctor` checks the kernel, the Landlock ABI, the active LSMs, Yama,
`legacy_tiocsti`, unprivileged user namespaces (with a real probe that
makes the same mounts as `cotty agent`, and Debian's and Ubuntu's switches),
seccomp, cgroup delegation and the display server, and explains each in a
sentence. It ends with the assurance level `cotty agent` would report and the gaps
that remain (`cotty agent` prints the gaps at every start, `--quiet`
included):

- `confined`: namespaces, Landlock ABI 6 or later, seccomp and a cgroup of
  its own;
- `partial`: namespaces work, something else is missing; the gaps are
  listed (for example Landlock older than ABI 6 leaves X11's abstract
  socket reachable);
- at every level the gaps also name what stays open by design: below
  Landlock ABI 9, pathname sockets in visible directories; always, the
  shared network namespace;
- `unavailable`: no unprivileged user namespaces; `cotty agent` refuses to
  start.

`cotty agent` prints the level when it starts and passes it to the agent
as `COTTY_ASSURANCE`. The broker's own assurance levels (`strong`,
`confined`, `weak`, `insecure`, PLAN section 3) build on this: the broker
does not read `COTTY_ASSURANCE` (the agent could change it) but checks
that pid 1 of the agent's pid namespace is the trusted cotty binary
running the init stage (docs/security.md, Assurance levels).

`cotty doctor` then names the level a session created now can reach:
`strong available for new sessions (cotty-guard running)`, `confined
(cotty-guard not running)`, `weak` when the cotty binary can be replaced
by your user, or `unavailable`. A session keeps the level it got when it
started: one created before cotty-guard started stays `confined`, so start
a new session after starting the guard. In `--json` these are the
`sessions` and `sessions_note` fields.

Ubuntu 24.04 and later allow unprivileged user namespaces only to programs
with an AppArmor profile (`kernel.apparmor_restrict_unprivileged_userns =
1`). cotty ships two in `dist/apparmor/cotty`, after Ubuntu's
`bwrap-userns-restrict`: `cotty`, for `/usr/bin/cotty` and
`/usr/local/bin/cotty`, allows user namespaces and is otherwise
unconfined; `unpriv_cotty` is the agent's profile, entered by the exec
stage right before it executes the agent (a change on exec, so the shells
of your cotty sessions keep their rights), and denies every capability to
the agent and everything it runs. An agent that executes cotty, bwrap or
`unshare` again gets no capability in a new user namespace; this matters
most where cotty has no seccomp filter. When cotty runs under the `cotty`
profile and `unpriv_cotty` is not loaded, `cotty agent` refuses to start.
The package installs the file; by hand:

```
sudo install -m 0644 dist/apparmor/cotty /etc/apparmor.d/cotty
sudo apparmor_parser -r /etc/apparmor.d/cotty
```

Debian kernels before 6.x may have `kernel.unprivileged_userns_clone = 0`;
`cotty doctor` names that too.

## What layer 2 does not cover

- Commands typed into the shared session run with your rights; that is the
  point of cotty (PLAN section 2).
- The network is open. The agent can reach any TCP or UDP service you can,
  including services on localhost (a dev server, a database, a browser's
  remote debugging port). basalt-agent filters egress on Basalt; Landlock
  TCP rules by port are a later option.
- Before Landlock ABI 9, a pathname socket that is visible inside (one in
  the project, one a profile exposes, one in a system directory cotty does
  not know to hide) can be connected to.
- Before Landlock ABI 6, abstract Unix sockets (X11, abstract D-Bus) are
  reachable; `cotty agent` refuses to start while one that matters
  listens or a display or bus is configured, and with
  `--allow-abstract-sockets` reports `partial`.
- Files the agent writes in the project are later used by you: build
  scripts, `package.json` scripts, `Makefile`, editor, direnv and
  `.vscode/tasks.json` files, and the agent CLIs' own project files
  (`.claude/settings.local.json`, `.mcp.json`, `.cursor/`, `.gemini/`,
  `opencode.json`, `.aider.conf.yml`, `AGENTS.md`, `CLAUDE.md`; see each
  page in `docs/agents/`). cotty protects the git files listed above and
  the hook manager files it knows; nothing else in the project is
  protected.
- Warning: git hooks and build commands can still run files the agent
  wrote. A protected hook or hook manager configuration often starts
  other programs from the work tree: `npx lint-staged` or `npm test`
  (`package.json` scripts and the packages in `node_modules`), `make`
  (the `Makefile`), a pre-commit `repo: local` entry such as `python
  -m tools.check` or `bash -c ...` that names no path, a script one of
  those calls in turn, an older Husky that reads `package.json`, or a
  hook manager configuration spelled in a way cotty does not know. After
  an agent session, review the changes in the work tree (`git status`,
  `git diff`, new untracked files) before you run git hooks (`git
  commit`, `git push`, `git checkout`) or build and test commands there.
- Git: a rebase, cherry-pick or merge left in progress by the agent runs
  what it left when you continue it: `exec` lines in
  `.git/rebase-merge/git-rebase-todo`, and the strategy programs named by
  `.git/sequencer/opts` and `.git/rebase-merge/strategy` (a
  `git-merge-NAME` found in `PATH`). A repository the agent creates in
  the project is reported, not blocked. A `.git` that is a symbolic link
  is refused unless you pass `--allow-git-links`; with it, the link can
  be replaced (a note says so at start).
- Browsers inside: Chrome, Chromium and Playwright's browsers cannot
  start their own sandbox (it needs new namespaces, which the seccomp
  filter denies); run them with `--no-sandbox` (Playwright:
  `chromiumSandbox: false`). cotty is then their only sandbox.
- The profile's own directories are read-write by design (login state,
  history, transcripts, memory). The files and directories the profile
  lists as `protect` are read-only, also when they do not exist yet;
  anything else there that a CLI loads later is not (see each page in
  `docs/agents/`).
- Executable placed in a writable place: if the cotty binary itself lies
  in the project or another read-write path, `cotty agent` warns: the
  agent could replace it.
- An agent CLI installed in `$HOME` outside the profile's paths needs
  `--ro DIR`; that directory is then readable (and executable) by the
  agent.
- Layer 2 cannot stop a second, unconfined program of yours from doing
  anything; the broker's peer classification, person-attach approval and
  `--require-confined` address the cotty side of that, and the guard
  (layer 3) the rest. docs/security.md lists, case by case, what each
  assurance level covers.

## Escape matrix and lab

`tests/attacks/run.sh` runs `tests/attacks/inside.sh` confined and checks
the outside effects; `tests/attacks/probe` is the Go helper that makes the
raw attempts (connect, ptrace, process_vm_readv, unshare, ioctl, ...).
`tests/attacks/agents.sh` starts every installed agent CLI under its
profile. Run them only in throwaway VMs: `tests/lab/vm.sh` makes those
with plain qemu and KVM as an unprivileged user (cloud images, cloud-init,
qcow2 overlays on one shared base image):

```
tests/lab/vm.sh create cotty-c-fedora44 fedora44
tests/lab/vm.sh start cotty-c-fedora44
tests/lab/vm.sh matrix cotty-c-fedora44
tests/lab/vm.sh apparmor cotty-c-ubuntu2604    # Ubuntu: load the AppArmor profile first
tests/lab/vm.sh broker-matrix cotty-c-fedora44   # attacks on the session broker (docs/security.md)
tests/lab/vm.sh claude-config cotty-c-fedora44   # Claude Code's settings file layout, fake writer
tests/lab/vm.sh stop cotty-c-fedora44
```

Rows report PASS, FAIL, GAP or SKIP. GAP is an attempt that got
through where this page lists it as open (a pathname socket below
Landlock ABI 9). SKIP means nothing was tried: the target does not exist
outside, or the command is not installed (exit 127 is never counted as
a denial). A FAIL whose detail starts with `[open: ITEM]` is a weakness
from the final review that is not fixed yet (docs/security.md, "Rows
added after the final review"). A few rows check plain permissions
rather than the confinement (`su`, `read-root-home`, `write-etc`) or
repeat another row's view (`home-via-proc-root`, `home-via-self-root`
with `ssh-dir-visible`); they are kept as sanity checks.

Results with the corrected harness, 2026-11-04, before the layer 2 fixes
below (escape attempts must be denied, allowed work must succeed):

| VM | Kernel | Landlock | Pass | Fail (open items) | Gap | Skip |
| --- | --- | --- | --- | --- | --- | --- |
| Fedora 44 Cloud | 7.2.15 | ABI 10 | 89 | 5 (B7 three rows, S13 two rows) | 0 | 2 |
| Ubuntu 26.04 LTS, AppArmor profile loaded, `lsm=...,bpf` | 7.0.0 | ABI 8 | 89 | 5 (as Fedora) | 1 | 1 |

The Ubuntu gap is `landlock-resolve-unix`: a socket created outside in
the project is reachable below ABI 9. Skips: the Docker socket (no
Docker in the VMs) and, on Fedora, gpg-agent (no agent socket). Earlier
results (2026-11-03: 88 / 0 / 2 on kernels 6.19 and 7.0, 89 / 0 / 1 on
7.2) predate the rows added after the review, and reported the
`landlock-resolve-unix` row as SKIP although its connect succeeded.
Full reports are in `tests/attacks/results/`.

Runs of 2026-11-04 on a kernel 7.1 host, with the fixes for the
layer 2 review findings (git and profile protection, socket roots,
environment allowlist, terminal filter, ABI 6 refusal, AppArmor agent
profile). GAP marks an escape the docs list as open on that kernel:

| VM | Kernel | Landlock | Pass | Fail | Gap | Skip |
| --- | --- | --- | --- | --- | --- | --- |
| Fedora 44 Cloud | 6.19.10 | ABI 7 | 131 | 0 | 2 | 3 |
| Ubuntu 26.04 LTS, AppArmor profiles loaded | 7.0.0 | ABI 8 | 133 | 0 | 2 | 1 |
| Ubuntu 24.04 LTS, AppArmor profiles loaded, `--allow-abstract-sockets` | 6.8.0 | ABI 4 | 129 | 0 | 7 | 1 |

On Ubuntu 24.04 the run first checks that `cotty agent` refuses to start
while the fake X11 abstract socket listens, then runs the matrix with
`--allow-abstract-sockets`: the abstract socket rows, the outside
listener check and `signal-init` read GAP there. On every kernel
`landlock-resolve-unix` (below ABI 9) and `git-nested-repo-hook` (a
repository the agent creates is reported at exit, not blocked) read GAP;
the open-item rows added after the review (B7, S13) pass. Skips: Docker
socket, and on Fedora gpg-agent and the AppArmor row.
`tests/attacks/claude-config.sh` passed its 30 checks on all three, and
`tests/attacks/agents.sh` started Claude Code 2.1.318, Codex CLI 0.166.0,
Gemini CLI 0.66.0, opencode 1.19.5 and Cursor CLI 2026.10.22 under the
new profiles on Fedora 44 (each up to its login or API check). Reports:
`tests/attacks/results/2026-11-04-*-layer2fix.txt`. Full reports are in
`tests/attacks/results/`. On Ubuntu 26.04 without the AppArmor profile,
`cotty doctor` reports `unavailable` and `cotty agent` refuses to start,
as expected.
