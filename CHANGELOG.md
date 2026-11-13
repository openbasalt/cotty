# Changelog

## Unreleased

- `cotty agent` refuses a kernel without Landlock (ABI 0) unless given
  `--allow-no-landlock`; it used to start the agent without Landlock and
  the session still reported it `confined`. Sessions now report every
  agent `weak` on such a kernel, and `cotty doctor` says so.
- Assurance: an agent is `confined` only when the broker sees that the
  trusted cotty binary built its confinement (pid 1 of its pid namespace
  runs cotty agent's init stage, and the agent is in that namespace's
  user namespace and mount view with no_new_privs and seccomp). Its own
  user namespace (`unshare -U`), a `cotty-agent*` cgroup or a guard tag
  no longer raise the level, so they no longer pass `--require-confined`
  or hide the red warning. Agents under the guard without layer 2, peers
  whose pid the broker cannot see, and every agent while the cotty binary
  is writable by the user now read `weak`.
- Confirm policy: agents may no longer press Tab or BTab (completion ran
  project files such as `./configure --help` and Makefile `$(shell ...)`
  in your shell before any approval), Up, Down, PgUp or PgDn (they
  recalled commands typed in private mode), nor type tabs, history
  expansion (`!`, `^`) or, outside a UTF-8 locale, bytes above 0x7f
  (Meta keys for readline). Left: text, held Enter, Backspace, Delete,
  Space, Left, Right, Home, End and C-c (docs/broker.md, Confirm policy).
- Docs: private mode does not keep a command out of the shell's history;
  README and docs/broker.md say so where private mode is described.
- The pts exception list lapses with cotty-guard's daemon: a clean stop
  empties it in the kernel, and the programs stop honouring it once the
  daemon's heartbeat is 90 s old, so a listed pinentry is refused while
  no daemon can tell the broker to light the lock.
- The exception lock names the program's parent: `LOCK pinentry-curses
  (exception, for gpg-agent)`; a parent that is a job the agent started
  marks it `(started by agent)`.
- Without the guard (or while its daemon cannot answer), the broker
  looks for a process outside the session that holds the session pts
  while a job reads with echo off, and lights the lock for it (`outside
  the session, for PARENT`, never green), holding agent input.
- A broker in another pid namespace than the guard, and a broker newer
  than its daemon (unknown `pts-exception`), log that once.
- Docs: the plain pinentry-protocol path (any process of the user that
  is not an agent can run the listed pinentry against the session pts
  and read the PIN), the Yama `ptrace_scope` sentence, and the
  `--allow-socket` on gpg-agent caveat.
- GPG: loopback pinentry (`pinentry-mode loopback`) is documented and
  tested; the lock lights for it, `git commit -S` included.
- cotty-guard reads a pts exception list (`/etc/cotty/guard-exceptions.conf`,
  root-owned, absent means none): a listed executable such as
  `pinentry-curses`, started outside the session and outside any agent,
  may open the session pts; the use is logged and audited, and the lock
  reads `LOCK pinentry-curses (exception)`. The guard's map layout gains
  two maps (replaced, not migrated, on upgrade); protocol version 5.
- Upgrade note: the first upgrade to a guard that keeps the record of
  each broker's executable locks out sessions whose broker started
  under the previous guard, once: their clients fail closed after the
  package replaces the installed cotty.
  End those sessions before upgrading; later upgrades keep running
  sessions reachable (docs/security.md, Known limits, The guard).
- A `protect` file that is a symbolic link (GNU stow, chezmoi's symlink
  mode) stays read-only inside, at the link and at its target; a
  `protect` directory that is a link refuses the start.
- `home.hide` directories are covered after the home links are made and
  fail closed; nothing is created through an `rw` entry that is skipped.
- The raw-mode re-check of the foreground group no longer walks `/proc`
  at every poll of an idle shell prompt.
- The reattach code is never handed out between its use and its
  replacement.
