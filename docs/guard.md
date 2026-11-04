# Kernel enforcement (layer 3): `cotty-guard`

`cotty-guard` is an optional root service. It loads BPF LSM programs that
enforce the agent rules in the kernel, for every process of an agent,
whatever started it. Layer 2 (`cotty agent`, docs/confinement.md) hides
what the agent must not reach with namespaces, Landlock and seccomp; the
guard makes the same rules hold by identity instead of by view, so they
also hold for a process that leaves the view, and it gives the broker an
answer about a peer that nothing the user owns can fake. It is layer 3 of
the plan (docs/PLAN.md, section 4).

No kernel module: no DKMS, no per-distribution build, no Secure Boot
signing; the BPF verifier rules out crashing the kernel. One CO-RE object
runs on every kernel with BTF and the `bpf` LSM.

```
systemctl enable --now cotty-guard        # the daemon (root)
cotty guard status                        # its state, as any user
cotty guard facts                         # what this kernel offers
cotty-guard hooks                         # each hook's signature on this kernel, checked
cotty doctor                              # includes a "guard" line
```

## Who is an agent

- Every task in a cgroup registered with the guard, or in a cgroup below
  it, at any depth. `cotty agent` registers its own scope
  (`cotty-agent-<id>.scope`) before anything of the agent runs. The
  programs look up the task's cgroup v2 ancestors (`cgroup->ancestors[]`)
  at the levels where some cgroup is registered, in a map only the daemon
  writes.
- Every task carrying a tag in its task storage, or whose thread group
  leader carries one. Task storage is not inherited by itself: the
  `task_alloc` program copies the tag to every new task of an agent, and
  `bprm_creds_for_exec` sets it on a task found by cgroup. So the tag
  survives if something outside moves an agent process to another cgroup.
  An agent itself cannot start a child in another cgroup:
  `clone3(CLONE_INTO_CGROUP)` is refused to it. When the kernel cannot
  allocate the tag, the new task is not created (`ENOMEM`): an untagged
  child of an agent would be outside every rule.
- The tag is the agent id: the registered cgroup's id, or a random id the
  daemon chose for a process that tagged itself. The broker sees it as
  `agent:<id>`.

Nothing removes a tag or a registration. They end with the agent's
processes and cgroup; the daemon forgets a cgroup once it is gone. The
maps and programs stay pinned when the daemon stops or restarts, so a
restart keeps them; only `cotty-guard uninstall` removes them (see
below). An upgrade keeps them too: a pinned map whose layout changed only
in size is copied into a map of the new size, and one whose key or value
changed refuses the start, leaving the programs already loaded enforcing
(see "The daemon and its socket").

## Rules for agent tasks

| Hook | Denied for an agent |
| --- | --- |
| `ptrace_access_check` | any ptrace-style access to a task of another agent or of the person: `ptrace`, `process_vm_readv`/`writev`, `pidfd_getfd`, `kcmp`, and every access the kernel itself guards with a ptrace check, whatever the file is called (for `/proc/PID`: `mem`, `environ`, `fd/N` links, `root`, `cwd`, `exe`, `maps`, `stack` and others). Checks marked "no audit" (`ps` reading `/proc/PID/stat`) are denied silently. |
| `file_open` | `/proc/PID/{mem,environ,fd,fdinfo,maps,smaps,smaps_rollup,pagemap,auxv}` of a task outside the agent (task found through the proc inode, so it holds in any pid namespace; matched by name); input devices (`/dev/input/*`, major 13), `/dev/uinput`, `/dev/uhid`, `/dev/vcs*` (console screen contents); any cgroup v2 file opened for writing: `cgroup.procs` and `cgroup.threads` (moving out of the agent's cgroup), `cgroup.kill`, `cgroup.freeze`, `memory.max`, `pids.max` and the rest (killing, freezing or starving the broker without a signal); `/dev/tty` when the agent's controlling terminal is a protected session pts (an agent CLI started inside the session) |
| `unix_stream_connect`, `unix_may_send` | a Unix socket (stream, seqpacket or datagram, connect or sendto) unless the agent created it, or it is on the agent's allowlist, or on the global one; abstract sockets only when the agent created them |
| `socket_post_create` | nothing: it marks Unix sockets created by an agent with the agent id (socket storage), which is what makes the agent's own sockets reachable |
| `inode_mknod`, `inode_create`, `inode_mkdir`, `inode_symlink`, `inode_link`, `inode_unlink`, `inode_rmdir`, `inode_rename` | any change in a guarded directory (see the allowlists below): binding a socket there (`bind()` creates its inode through `mknod`), creating, linking, symlinking, moving in or out, removing; and renaming or removing a guarded directory itself. This keeps the agent from moving the session bus into the allowed agent endpoint directory, and from planting a fake session socket (or a link to one) where `cotty attach` looks. For every process, agent or not: in a cotty runtime directory (`$XDG_RUNTIME_DIR/cotty` and its `agent/` directory, registered by the brokers) only registered brokers and root may bind, link, symlink, rename or remove, while the daemon runs; and a session socket a broker claimed may be removed, renamed or replaced by no other process but root (other brokers included) while that broker runs, daemon or not (see the broker registry below). |
| `bprm_creds_from_file` | an exec that gains privileges: a different effective uid or gid, or permitted capabilities the task did not have (setuid, setgid, file capabilities) |
| `bpf` | the `bpf()` syscall, every command |
| `task_alloc` | `clone3(CLONE_INTO_CGROUP)`: a child started directly in another cgroup |
| `task_kill` | a signal to a task of another agent or of the person |
| `task_setrlimit`, `task_setnice`, `task_setioprio`, `task_setscheduler` | changing the resource limits (`prlimit`, for example `RLIMIT_CPU`), nice value, I/O priority or scheduler of a task of another agent or of the person |
| `file_fcntl` | `F_SETOWN` (other than clearing it) and `F_SETOWN_EX`: the kernel would send `SIGIO`, or any signal chosen with `F_SETSIG`, to the owner without `task_kill`; `F_SETSIG` (other than back to `SIGIO`) and `O_ASYNC` through `F_SETFL`: a terminal with `O_ASYNC` sends `SIGIO` to its foreground process group by itself, which on the person's terminal is the attach client |
| `file_ioctl`, `file_ioctl_compat` | `TIOCSTI` and `TIOCLINUX` (input injection into a terminal), `FIOSETOWN`, `SIOCSPGRP` and `FIOASYNC` (the `SIGIO` owner and `O_ASYNC` again). `file_ioctl_compat` (32-bit ioctls on a 64-bit kernel, Linux 6.8 and later) is attached where the kernel has it. |

Rules for every process, agent or not, protect a cotty session's pts.
The broker protects it (by device and inode) before the shell starts, and
from then on:

- `file_open` lets it open only for that broker and for the processes
  whose controlling terminal it is (the session's own commands, compared
  by the kernel's `tty_struct`), never for an agent. This closes the two
  rows that layer 2 cannot close for an agent started without `cotty
  agent` (assurance `weak`): opening the pts by its path, and opening it
  through `/proc/<shell pid>/fd/0` (the magic link ends in the same
  `file_open` on the pts);
- `file_receive` applies the same rule to a descriptor of the pts that
  arrives over `SCM_RIGHTS` (a command in the session handing its terminal
  out) or through `pidfd_getfd`. `O_PATH` descriptors, which cannot read
  or write the terminal, pass;
- `ptrace_access_check`: a process outside the session that is not its
  broker and not root cannot ptrace-attach to the session's processes
  (`ptrace`, `pidfd_getfd`, `process_vm_readv`/`writev`,
  `/proc/PID/mem`). On distributions with Yama's `ptrace_scope` 0
  (Fedora) a process of the same user could otherwise attach to the
  session shell and take the pts from it.

The protection belongs to the broker process (its pid and start time),
not to a connection: it lasts as long as the broker runs, whatever
happens to the daemon; the programs ignore an entry whose broker is gone
and the daemon removes it. Only a registered broker may protect a pts,
and only one whose master it holds (it sends the master with the request
and the daemon checks, through `TIOCGPTPEER`, that it is that pts's), so
no other process can protect a session's pts first and keep the session
from starting, or protect the person's other terminals. Nobody can take a
protection over: a request to protect a pts that another live process
protects is refused.

The broker protects the pts before anybody can open it: a new pty starts
locked (opening its slave fails with `EIO`), the broker reaches the slave
through the master (`TIOCGPTPEER`), first as an `O_PATH` descriptor that
opens no terminal, protects it, and only then unlocks the pty and opens
the slave for the shell. A process that watches `/dev/pts` and retries
the open finds the pty locked first and protected after (row
`u-pts-race-open`).

The cost: a program outside the session that opens the terminal by name,
such as a `pinentry-curses` started by `gpg-agent` with `GPG_TTY`
pointing at the session's pts, is refused. Use GPG's loopback pinentry
(docs/security.md, GPG), or list the program on the pts exception list
(below). A debugger outside the session cannot attach to a process in it
(`gdb -p` from another terminal); run it inside the session, or as root.

### The pts exception list

`/etc/cotty/guard-exceptions.conf` (`--exceptions FILE` for another
path) lists executables that may open a protected session pts without it
being their controlling terminal, one absolute path per line, `#`
comments:

```
# pinentry for gpg-agent with GPG_TTY
/usr/bin/pinentry-curses
```

- Absent or empty: no exception (the default).
- The file and every directory above it must be owned by root and not
  writable by group or others; otherwise the daemon refuses the whole
  list and logs why (`refusing /etc/cotty/guard-exceptions.conf: mode
  0664 is writable by group or others ...`).
- Each listed path is resolved when the list is loaded: symbolic links
  are followed, and the file they end at must be a root-owned executable
  closed to group and others, in directories closed the same way. The
  kernel then matches the file a process runs (`mm->exe_file`, by device
  and inode), not its name or arguments. A copy at another path is
  another file and is refused; a symbolic link or a hard link to the
  listed file runs that very file and passes.
- The list is read at start, on `systemctl reload cotty-guard` (SIGHUP)
  and every 30 seconds, so a package upgrade that replaces the listed
  file is picked up.
- Agents never get an exception: the agent check comes first, so an
  agent, and every process it starts, is refused whatever it runs. A
  traced process is refused too. The exception covers opening the pts,
  not receiving it over SCM_RIGHTS or `pidfd_getfd`.
- Each use is logged (`exception used: pid N (pinentry-curses) running
  /usr/bin/pinentry-curses opened the session pts ...`) and written to
  the audit log as `guard.exception`. The broker asks the guard for the
  latest use of its pts (`pts-exception`) whenever echo is off, before
  every batch of person input and after output, and lights the lock for
  that process while it runs and echo is off, named with its parent, the
  process that receives what it reads: `LOCK pinentry-curses (exception,
  for gpg-agent)`. A parent you did not expect (`for python3`) means
  someone else is asking for the keys: do not type.
- The list lives with the daemon. Only a running daemon can tell the
  broker about an exception use, so a clean stop (`systemctl stop
  cotty-guard`) empties the list in the kernel at once, and after a crash
  the programs stop honouring it once the daemon's heartbeat is older
  than 90 seconds; the pts is then refused to the listed program as to
  any other. The next start loads the list again.

The kernel's view of the file is the superblock's device (as
`/proc/self/mountinfo` shows it, which on btrfs differs from what `stat`
shows), the inode number and the inode generation (`FS_IOC_GETVERSION`):
btrfs subvolumes share one superblock and each numbers its inodes from
the start, so without the generation a file a user creates in another
subvolume could take the listed file's place. A file on btrfs or
bcachefs whose generation cannot be read is not accepted.

What an exception costs: the guard identifies the file, not the code
that runs, and not who started it. A process of yours that is not an
agent needs no trick to read the session's keys through a listed
pinentry: it runs `/usr/bin/pinentry-curses --ttyname /dev/pts/N` (the
session pts), sends `SETDESC`, `SETPROMPT` and `GETPIN` on its standard
input, and receives on its standard output what the person types at the
dialog, while the lock is lit and names the program the person expects
from gpg. The lock's `for PARENT` is the one signal against that: a
pinentry started by gpg-agent reads `for gpg-agent`. It can also start
the listed program with `LD_PRELOAD` or a changed library path, or trace
it: the process that starts a program can always trace it (Yama
`ptrace_scope` 1 allows tracing one's own descendants; only 2 and 3
stop it), and any other debugger can where Yama allows. The guard's
refusal of a traced task is a speed bump, not a guarantee: a tracer can
change the program at exec and detach before it opens the pts. Agents
started with `cotty agent` (tagged) can do none of this; an agent CLI
started without it (`weak`) can. Keep the list to pinentry programs.

Do not allow an agent to reach gpg-agent: `--allow-socket` on a
gpg-agent socket (or on `/run/user/UID/gnupg`, or a profile's `[sockets]
allow` entry for it) lets a tagged agent run `gpg` with `GPG_TTY` set to
the session pts. gpg-agent, which is not tagged, then starts the listed
pinentry on the person's terminal, and the lock reads `LOCK
pinentry-curses (exception, for gpg-agent)`, not the agent's name. The
passphrase goes to gpg-agent, not to the agent, but the agent gets the
signature or the decryption it asked for, and the agent's passphrase
cache.

The broker asks the guard in its own pid namespace's terms: the daemon
answers pids of its namespace, so a broker in another pid namespace (a
container) never lights the lock for an exception use. It logs that once
(`... runs in another pid namespace and cannot light the lock for it`).
A broker newer than the daemon (protocol 5 against 4) gets an unknown
operation for `pts-exception`, logs it once and watches the pts itself
(docs/broker.md, A reader outside the session).

Allowlists, by inode of the socket or of the directory holding it:

- global, kept by the daemon (rescanned every 30 seconds, so a restarted
  service keeps working): the resolver, journal, userdb, nscd and SSSD
  sockets, the same list `cotty agent` keeps visible, plus
  `--allow-socket PATH` on the daemon's command line;
- per agent, sent by `cotty agent` at registration: the cotty agent socket
  (or its directory) and the profile's `[sockets] allow` entries. A
  world-writable directory is refused.

An allowed directory allows the sockets directly in it, looked up at
connect time through the socket's parent directory. So every allowed
directory of an agent is also guarded for it (the `inode_*` rules above):
nothing can be moved, linked or bound into it by the agent. `cotty
agent` also sends guarded directories that are not allowed: the cotty
runtime directory (`$XDG_RUNTIME_DIR/cotty`), where the person's session
sockets live, so an agent cannot plant a fake session there, unlink a
real one or rename the directory away. A process that is not an agent
(a command typed into the session) is not bound by these rules.

Every denial goes to the audit log (`/var/log/cotty/guard.audit.jsonl`,
the hash-chained format of `internal/audit`, event `guard.denial`, with
the agent tag, hook, reason, program, the first 32 bytes of the file
name, target pid). The programs send at most 32 denial events per
process and second; repeats of the same denial within two seconds are
counted, not logged again. Both counts show as `dropped` in `cotty-guard
status`. The budget is per agent (all processes of one agent share it),
and per process for a process that is not an agent.

### What the guard does not do

- It does not hide files. Reading `~/.ssh` or the shell history is a
  matter of the agent's view (layer 2: tmpfs over `$HOME`, Landlock).
  BPF LSM could deny opens by path, but a path list in the kernel would
  duplicate the profile and get it wrong; the view is the better tool.
- It does not take away descriptors the agent already holds. A terminal
  or socket passed to the agent at start stays usable; `cotty agent`
  closes everything but stdio (layer 2).
- It does not create namespaces, drop capabilities, set `no_new_privs`,
  limit core dumps or filter syscalls in general; layer 2 does.
- It does not stop a nested user namespace. Inside one the agent holds
  capabilities over its own namespace only; every rule above still
  applies to it (the tag and the cgroup do not change). Layer 2 forbids
  nested namespaces with seccomp.
- Pathname sockets are identified by inode when the agent connects. A
  socket that is removed and created again gets a new inode: the global
  list is rescanned every 30 seconds, an allowed directory covers new
  sockets in it, and a single allowed socket must be registered again.
- It does not filter the network: TCP and UDP stay open, including
  services on localhost (an sshd, a Docker API on TCP, a browser's
  remote debugging port) that would start processes outside the agent's
  tag.
- It needs cgroup v2 (the unified hierarchy). On a hybrid or v1-only host
  the daemon refuses a registration and `cotty agent` does not start the
  agent.
- Device numbers it names are the common ones: `/dev/hidraw*` (dynamic
  major) is not covered, and `TIOCSTI` is matched by its value on x86 and
  arm (other architectures number it differently).

Rules from the plan that are expressed differently:

- "deny setuid and file capability exec" is enforced in
  `bprm_creds_from_file`, not `bprm_creds_for_exec`: the new credentials
  are only computed (by the capability LSM, which runs first) after
  `bprm_creds_for_exec`. Checking the result instead of the file's mode
  bits covers file capabilities and leaves alone a setuid file on a
  `nosuid` mount or under `no_new_privs`, where the exec gains nothing.
  `bprm_creds_for_exec` sets the tag.
- "`socket_connect` for AF_UNIX": the decision is taken in
  `unix_stream_connect` and `unix_may_send`, which see the socket the
  kernel resolved, instead of `socket_connect`, which sees only the path
  string the agent passed (a link or a rename could swap what it names).
  Together they cover `connect()` and `sendto()` for stream, seqpacket and
  datagram sockets.

## The daemon and its socket

`cotty-guard run` (the systemd unit `dist/systemd/cotty-guard.service`):

- reads `/sys/kernel/security/lsm` and `/sys/kernel/btf/vmlinux`; without
  the `bpf` LSM or BTF it says why and exits with status 0 (the guard is
  optional);
- loads the programs, reusing maps pinned in `/sys/fs/bpf/cotty`, so tags,
  registrations and pts protections survive a restart; attaches the
  programs and pins the links there too. A stop, a restart, an upgrade or
  a crash leave the enforcement in place: while no daemon runs, the rules
  still hold, nothing new can be registered, and brokers stop reporting
  `strong` (they cannot confirm their protection) until it answers again;
- on an upgrade whose pinned maps have another layout: a hash or array
  map that only changed its number of entries is copied into a map of
  the new size, which replaces the pin in one rename; the rate limit and
  the event queue are replaced empty; any other change (a key or value
  layout, task or socket storage, which cannot be copied) refuses the
  start with a message, and the programs already loaded keep enforcing on
  the old maps. Then stop the sessions and agents, run `cotty-guard
  uninstall` and start the guard again;
- creates `/run/cotty-guard/enforcing` (the unit keeps that directory
  across a stop); only `cotty-guard uninstall` removes it. While it exists
  and the daemon does not answer, `cotty attach`, `new`, `share` and
  `kill` refuse to run: they cannot have the session's broker verified,
  and they fail closed instead of skipping the check;
- a stop leaves the last heartbeat in place, so the broker directory
  rule (below) stays on for up to 90 seconds: a restart or an upgrade
  never opens a window, and a guard stopped for good does not keep new
  sessions from starting for longer than that;
- at start removes protections whose broker is gone (sessions that ended
  while it was stopped), and every 30 seconds after;
- serves `/run/cotty-guard/guard.sock` (seqpacket, mode 0666 in a 0755
  root directory) and writes denials from a ring buffer to the audit log.
  At most 64 open connections per user (root is not limited); a request
  must arrive within 60 seconds and its answer be taken within 5; an
  accept that fails (out of descriptors or memory) is retried with a
  back-off, never ends the service. Clients give the daemon 3 seconds per
  request, so a daemon that stops answering cannot hang a broker;
- accepts as brokers only the cotty binary at `/usr/bin/cotty` or
  `/usr/local/bin/cotty` (`--cotty PATH`, repeatable, names others). It
  records the executable (device and inode) each broker ran when it
  registered, in `/run/cotty-guard/broker-exes.json` (root-owned, kept
  across restarts of the daemon): after a package upgrade replaces the
  installed file, a running broker that still runs the recorded inode is
  vouched for, so running sessions stay attachable;
- loads the pts exception list (`/etc/cotty/guard-exceptions.conf`,
  below) at start, on SIGHUP and every 30 seconds.

Requests (JSON messages, descriptors as SCM_RIGHTS). The caller is known
from `SO_PEERCRED` and `SO_PEERPIDFD` (Linux 6.5), never from the message:

| Request | Who | What |
| --- | --- | --- |
| `register` (+ socket and directory fds) | a process that is not an agent, in a cgroup whose name starts with `cotty-agent` and which it owns (at most 1024 per user) | its own cgroup becomes an agent cgroup; the sockets go on that agent's allowlist; the directories are guarded, the last `guard` of them without connect rights |
| `tag-self` | anyone | the caller is tagged (it only restricts) |
| `protect-pts` (+ terminal fd, `O_PATH` is enough, and its master) | a registered broker that holds the terminal's master, when no other live process protects it (at most 1024 per user) | while the caller runs, the terminal opens only for the caller and for the processes whose controlling terminal it is, never for an agent |
| `check-pts`, `release-pts` (+ terminal fd) | the process that protected it | whether the protection is in place for the caller; end it |
| `register-broker` (+ session name, the runtime directory and its agent directory) | a broker: the installed cotty binary (root-owned, at a configured path, in root-owned directories, none writable by group or others) running `__broker` without `-dev-insecure`, not dumpable, not traced, not an agent; a session name no other live broker of the user holds (at most 256 per user) | the caller becomes the registered broker of that session name (by pid and start time, until it exits; the first registrant keeps the name); the directories (its user's, mode 0700) become cotty runtime directories |
| `claim-socket` (+ session name, one socket fd) | the registered broker of that name | the socket can no longer be removed, renamed or replaced by any other process but root while the caller runs |
| `pts-exception` (+ terminal fd) | the process that protected it | the running process that last opened the terminal through the exception list (pid, start time, listed path), if any |
| `verify-broker` (+ session name, connected socket fd) | anyone | whether the process listening on the other end of the caller's connection runs as the caller's uid, is the registered broker of that session name and runs the installed cotty binary as `__broker`; its pid |
| `tag-of` (+ pidfd) | anyone | the tag of that process |
| `status` | anyone | loaded programs, agents, denials |
| `untag`, `unregister` | nobody | always refused |

Agents cannot reach the socket at all: the guard denies them the connect,
like any other socket not on their list.

### For the broker and the launcher

- `guard.ForAgent(cgroup, sockets)` is what `cotty agent` calls once it
  runs in its scope and before it starts the agent
  (`internal/confine/launch_linux.go`). Without a guard it does nothing;
  if a running guard refuses, the launch stops. Where the launcher has no
  cgroup of its own to register (no systemd user manager), it tags itself
  instead: the agent is tagged and every rule applies, but there is no
  socket allowlist, so the agent cannot reach its own cotty socket
  either; `cotty agent` says so when it happens.
- `guard.New()` returns a `peer.Guard` for the broker: `Loaded()` asks the
  daemon (cached for two seconds), `Tag(pid)` sends a pidfd and gets the
  tag the kernel's maps hold. The broker checks that the socket is served
  by root. Nothing in that answer comes from files or cgroups the user or
  the agent can write.
- `guard.NewSession()` is the broker's per-session guard: its `Protect`
  (`broker.Config.ProtectPTS`) protects the pts while the new pty is still
  locked, before anybody can open it and before the shell starts (when a
  running guard refuses, the session does not start), and it is the
  broker's `peer.Guard`. Its requests to the daemon never run under the
  lock `Loaded()` takes, so the broker never waits on the daemon. It
  asks the daemon every two seconds whether the protection is still in
  place, over a connection it keeps (and opens again after a restart),
  and `Loaded()` is true only while the last answer said yes. So the
  session reports `strong` only while the guard confirms its protection:
  `confined` while the daemon does not answer, and for good once the
  protection lapsed (the session started before the guard, or `cotty-guard
  uninstall` removed it), since anything may have opened the pts in the
  meantime and such a descriptor stays usable.

- The broker registry closes the guard side of B3 and N1 (a process of
  the user replacing the session socket a person attaches to, or a second
  broker taking a session over). `cotty __broker` calls
  `Session.RegisterBroker` with its session name, `$XDG_RUNTIME_DIR/cotty`
  and its `agent/` directory before it binds a socket; with a running
  guard that refuses, the session does not start (with the guard loaded,
  cotty must be installed root-owned, which `strong` needs anyway). The
  name belongs to the first broker that registered it for as long as that
  broker runs: a second `cotty __broker` with the same name (any process
  of the user can start the installed binary) is refused, and so is a
  broker started with `-dev-insecure` or under a tracer. From then on only
  registered brokers and root may bind, link, symlink, rename or remove in
  those directories; creating plain files and directories stays open
  (logs, metadata), except for agents. After it binds, the broker claims
  its sockets (`claim-socket`): no other process but root, other brokers
  included, can remove, rename or replace them while it runs, with or
  without the daemon. `cotty ls` therefore cannot remove a dead broker's
  leftover socket while the guard runs; the next broker of that name
  replaces it. The directory rule holds while the daemon's heartbeat
  (every 30 seconds) is younger than 90 seconds: with no daemon, brokers
  could not register and new sessions could not start. The session
  registers its broker and claims its sockets again after a daemon
  restart. Registrations, names and claims of gone brokers, and runtime
  directories no live broker registered, are removed every 30 seconds.
- `guard.BrokerVerifier` is the attach client's `attach.BrokerVerifier`:
  `cotty attach`, `new`, `share` and `kill` use it when the guard is
  loaded (`guard.ClientVerifier`). It sends the client's connected socket
  and the session name to the daemon (`verify-broker`), which looks at the
  listener as root and must answer with the pid the client's
  `SO_PEERCRED` gives; any other answer, or no answer, refuses the
  connection before anything is sent. With the guard installed (its
  marker present) and no daemon answering, those commands refuse to run.
- Not covered: a process that starts the real cotty under
  `PTRACE_TRACEME` (allowed with Yama `ptrace_scope` 0 and 1), changes its
  memory before it registers and detaches; with `ptrace_scope` 0 a
  process can also follow `cotty new` with `PTRACE_O_TRACEFORK`. The
  guard refuses only a broker that is being traced when it registers. A process
  of the user can also rewrite `NAME.json` or pre-create files named like
  a session's in the runtime directory: that keeps a session from being
  attached (the client's checks fail) or started, never lets anything in.
- Also not covered: a session process that calls `setsid` and keeps the
  pts open without making it its controlling terminal falls outside the
  ptrace rule (the rule finds session processes by controlling terminal);
  on 32-bit kernels before 7.0, `task_alloc` sees only the low 32 bits of
  the clone flags, so the `CLONE_INTO_CGROUP` refusal does not apply
  there.

`cotty-guard uninstall` (root, daemon stopped) detaches the programs and
removes the maps: the enforcement ends and every tag, registration and
protection is forgotten. A package's removal script should run it;
nothing else does.

## Distributions

The guard needs `bpf` in the active LSM list and kernel BTF. Checked in
VMs on 2026-11-03 (stock cloud images, no kernel parameter changed):

| Image | Kernel | `CONFIG_LSM` | Active LSMs at boot | `bpf` active | BTF |
| --- | --- | --- | --- | --- | --- |
| Fedora 44 Cloud (updated) | 7.2.15 | (Fedora default) | lockdown, capability, yama, selinux, bpf, landlock, ipe, ima, evm | yes | yes |
| Fedora 44 Cloud (as released) | 6.19.10 | (Fedora default) | same list | yes | yes |
| Ubuntu 26.04 LTS | 7.0.0-38 | landlock, lockdown, yama, integrity, apparmor | lockdown, capability, landlock, yama, apparmor, ima, evm | no | yes |
| Debian 13 (genericcloud) | 6.12.115 | landlock, lockdown, yama, loadpin, safesetid, integrity, apparmor, selinux, smack, tomoyo, bpf, ipe | lockdown, capability, landlock, yama, apparmor, tomoyo, bpf, ipe, ima, evm | yes | yes |
| Arch Linux (cloudimg) | 7.2.11-arch1 | landlock, lockdown, yama, integrity, bpf | capability, landlock, lockdown, yama, bpf | yes | yes |

All four build the bpf LSM in (`CONFIG_BPF_LSM=y`); only Ubuntu leaves it
out of the default list. On Ubuntu 26.04 `cotty-guard` logs why and exits
with status 0, and `cotty doctor` says "not possible on this kernel". With
`lsm=lockdown,landlock,yama,apparmor,ima,evm,bpf` on the kernel command
line (a file in `/etc/default/grub.d/`, then `update-grub`) the guard runs
there like everywhere else; the Ubuntu results below were taken that way.

The hook signatures, checked with `cotty-guard hooks` on each kernel, all
match what the programs read. Two differ between kernels without
affecting the programs: `task_alloc`'s `clone_flags` is `unsigned long`
on 6.12 and `u64` on 7.x, and `bpf` gained a fourth argument (`bool
kernel`) after 6.12.

Where `bpf` is missing from the active list, add it to the kernel command
line, keeping the LSMs already active (`cotty guard facts` prints the
exact value), for example on Fedora with GRUB:

```
sudo grubby --update-kernel=ALL --args="lsm=lockdown,yama,selinux,bpf,landlock"
```

or in `/etc/default/grub` (`GRUB_CMDLINE_LINUX`) and `update-grub` on
Debian and Ubuntu.

## Escape matrix with the guard

`tests/attacks/guard.sh MODE` runs the escape matrix of
`tests/attacks/run.sh` plus `tests/attacks/guard-inside.sh` (guard socket
abuse, the protected person pts, a file capability exec, every visible
`environ`) in four modes:

- `none`: the agent runs as a plain process in a `cotty-agent-*` scope,
  with the guard stopped (the baseline). Until 2026-11-04 this mode ran
  with the guard loaded, and its `guard-register-again` row registered
  the scope, so every later row ran under the guard and the baseline was
  not one; the guard must now be stopped, and register-again runs last;
- `guard-only`: the same, registered with the guard, without layer 2
  (`tests/attacks/guardprobe run-registered`, with the agent endpoint
  directory allowed and the cotty runtime directory guarded, as `cotty
  agent` registers): what the guard alone blocks;
- `layer2`: `cotty agent`, guard stopped;
- `both`: `cotty agent` with the guard running; the launcher registers
  the agent.

`tests/attacks/guard-exceptions.sh` (guard loaded, passwordless sudo)
tries the pts exception list with a root-owned stand-in for
pinentry-curses: listed and started outside the session it opens the pts
and the lock names it; unlisted, a copy, started by an agent (registered
cgroup, a descendant, a self-tagged launcher) or traced it is refused; a
list writable by group, owned by the user, empty or absent allows
nothing; with the daemon stopped the listed program is refused, after a
crash once the heartbeat is 90 s old, and a restart allows it again
(`exc-daemon-*`). `tests/attacks/gpg.sh` signs with a real key, through
loopback and through pinentry-curses, with the guard (exception) and
without it (the broker's own scan; docs/security.md, GPG).

```
tests/lab/vm.sh create cotty-f-fedora44 fedora44
tests/lab/vm.sh start cotty-f-fedora44
tests/lab/vm.sh push cotty-f-fedora44
tests/lab/vm.sh guard cotty-f-fedora44 start
tests/lab/vm.sh ssh cotty-f-fedora44 'COTTY=~/cotty/bin/cotty PROBE=~/cotty/bin/probe GUARDPROBE=~/cotty/bin/guardprobe bash ~/cotty/tests/attacks/guard.sh guard-only'
tests/lab/vm.sh guard cotty-f-fedora44 stop
```

Results with every review fix in (layer 2 and the guard), 2026-11-04
(pass / fail / gap / skip; a fail in `none` and `guard-only` is an
escape that layer 2 is there to stop, none of them an open review item):

| VM | Kernel | Landlock | none | guard-only | layer2 | both |
| --- | --- | --- | --- | --- | --- | --- |
| Fedora 44 Cloud | 7.2.15 | ABI 10 | 39 / 94 / 0 / 12 | 88 / 48 / 0 / 9 | 133 / 0 / 1 / 7 | 135 / 0 / 1 / 5 |
| Ubuntu 26.04, `lsm=...,bpf`, AppArmor profile | 7.0.0 | ABI 8 | 43 / 91 / 0 / 11 | 90 / 47 / 0 / 8 | 134 / 0 / 2 / 5 | 137 / 0 / 1 / 3 |

The gap in `layer2` and `both` is `git-nested-repo-hook` (a repository
the agent creates inside the project is reported when it exits, not
blocked; docs/confinement.md); the second Ubuntu gap in `layer2` is
`landlock-resolve-unix` below ABI 9, which the guard closes in `both`.
The rows added for the review's guard items (S19 to S23 and the B3 guard
rule) pass in `guard-only`. Reports:
`tests/attacks/results/2026-11-04-guard-*-fixguard-*.txt`.

Before the fixes, with the same harness: `guard-only` 72 / 33 (6 open:
S19, S20, S21) on Fedora and 74 / 32 (6) on Ubuntu
(`tests/attacks/results/2026-11-04-guard-*.txt` without `fixguard`).
Earlier results (2026-11-03) had `none` at 43 / 52 / 2 on Fedora 44 and
similar elsewhere: wrong, because that mode ran with the guard loaded
and its `guard-register-again` row registered the agent's scope, so
every later row ran under the guard (24 `file_open` denials in a run
that was meant to have none). Debian 13 and Arch have not been run with
the corrected harness yet; their earlier `layer2` and `both` counts
(94 / 0 / 3 and 96 / 0 / 1) predate the new rows.

`tests/attacks/guard-lifetime.sh` checks the guard's own lifetime
(review B4 and B5) on a real session: 660 s idle, a restart, a stop, a
start, an `uninstall`, taking over the protection with an `O_PATH`
descriptor, and the protection gone once the broker exits. 21 of 21 on
both VMs (`2026-11-04-guard-lifetime-idle660-fixguard-*.txt`).

What the guard alone turns from escaped into denied (`none` against
`guard-only`, on both VMs unless noted): every Unix socket of the person
(session bus by path, fake bus by path and abstract, systemd private
socket, `systemd-run --user` and `systemctl --user`, system bus,
ssh-agent real and fake, gpg-agent where it ran (Ubuntu), tmux and
screen sockets and their `capture-pane`/`hardcopy`, kitty path and
abstract, wezterm, X11 path and abstract, a socket created outside in
the project), no fake listener outside reached; reading another
process's `environ`; `ptrace` and `process_vm_readv` of an outside
process (Fedora; on Ubuntu Yama already refused them in `none`);
`pidfd_getfd` of the person's pts from its holder (Fedora; refused by
Yama on Ubuntu); signals to outside processes; `sudo` (setuid exec);
`bpf()`; and the guard's own rows: the protected pts, `cgroup.procs` of
the agent's scope, a file capability exec (`newuidmap`), every outside
`environ`, and the rows for the review's items: a socket renamed into the
allowed directory (S19), `clone3(CLONE_INTO_CGROUP)` (S20),
`cgroup.freeze`, `cgroup.kill`, `prlimit`, nice and SIGIO on processes
of the person (S21), `pidfd_getfd` of the pts (S22), and binding,
linking, symlinking or renaming in the cotty runtime directories.

What stays open with the guard alone: by design (layer 2's job) files
(`~/.ssh`, history, `/boot`, `.git/hooks`, writes to the real home),
other terminals that are not cotty sessions, descriptors inherited at
start, the pid namespace view, nested user namespaces, `no_new_privs`,
seccomp, capabilities in the bounding set, `keyctl`, `perf_event_open`,
`io_uring`, core limits, and the visible cgroup tree.

The guard rows prove little in `both` mode: layer 2 alone already
refuses each of them (the person's pts is not in the agent's devpts
instance, the victims are outside its pid and cgroup namespaces, the
runtime directory is a private tmpfs), so a pass there says nothing
about the guard. Only `guard-only` shows the guard's own effect; the
denial counts by hook after each run show which rules fired.

With layer 2 present the guard adds no new passing row on these kernels
(layer 2 already passes all of them), but it is the first to refuse some
of them: on Fedora and Arch the bpf LSM sits before Landlock in the LSM
order and denies abstract socket connects first, and on Debian (Landlock
ABI 6) it denies the connect to a socket created outside in the project,
which Landlock before ABI 9 lets through. The broker matrix with the
guard is in [security.md](security.md): the two gaps of the `weak` level
close. Full reports: `tests/attacks/results/2026-11-03-guard-*.txt` and
`2026-11-03-broker-guard-*.txt`.

## Overhead

`tests/attacks/guard-bench.sh SRC [RUNS]` measures, inside `cotty
agent`, a clean `go build ./...` of this repository and 300000 open and
close calls (the worst case for the `file_open` program), with the guard
stopped and running alternately, three runs each, medians (VMs with 4
vCPUs on one lab host, 2026-11-03):

| VM | go build, stopped | go build, running | change | 300000 opens, stopped | running | per open |
| --- | --- | --- | --- | --- | --- | --- |
| Fedora 44, 7.2.15 | 14.95 s | 14.94 s | -0.1% | 0.98 s | 1.03 s | +0.17 us (+5%) |
| Ubuntu 26.04, 7.0.0 | 14.95 s | 14.91 s | -0.3% | 1.00 s | 1.10 s | +0.33 us (+10%) |
| Arch Linux, 7.2.11 | 13.10 s | 13.17 s | +0.5% | 0.82 s | 0.98 s | +0.53 us (+20%) |

With the review's additions (26 programs, among them the `inode_*`
hooks that run on every file creation and removal), 2026-11-04:

| VM | go build, stopped | go build, running | change | 300000 opens, stopped | running | per open |
| --- | --- | --- | --- | --- | --- | --- |
| Fedora 44, 7.2.15 | 15.16 s | 15.30 s | +0.9% | 1.00 s | 1.05 s | +0.17 us (+5%) |
| Ubuntu 26.04, 7.0.0 | 15.23 s | 15.31 s | +0.5% | 1.15 s | 1.18 s | +0.10 us (+3%) |

A build does not notice the guard (the differences are noise). The
open loop shows the price of one `file_open` call: two task storage
lookups (the task and its thread group leader) and, while at least one
agent cgroup is registered, one map lookup per cgroup level at which an
agent cgroup is registered, about half a microsecond at most. Every process pays it, agent
or not, since the programs must find out which one it is; opening a pts
adds one map lookup.

## Building

`go build ./...` needs nothing but Go: the BPF object and its bindings
(`internal/guard/daemon/guardbpf_bpfel.{go,o}`) are generated by
cilium/ebpf's bpf2go and committed. After changing `bpf/guard.bpf.c`,
run `make bpf` (needs clang and llvm-strip) and commit both files. The
kernel types the programs read are declared by hand in
`bpf/headers/cotty_vmlinux.h` with `preserve_access_index` (CO-RE), so no
`vmlinux.h` is generated or committed; the libbpf headers next to it are
vendored from libbpf 1.6 (LGPL-2.1 OR BSD-2-Clause). The programs are
licensed Apache-2.0 OR GPL-2.0-only: the kernel requires a GPL-compatible
license for BPF LSM programs and the helpers they call.

Load the guard only in throwaway VMs while developing
(`tests/lab/vm.sh guard NAME`); never on a machine you care about.
