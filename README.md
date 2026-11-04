# cotty

A terminal shared by a person and an AI coding agent.

You and an agent work in one real terminal session at the same time. The
agent reads the screen and types through MCP, so any agent CLI that speaks
MCP works (Claude Code, Codex CLI, Gemini CLI, Cursor CLI, opencode). You
see everything it types, you can type at any moment, and you can take the
keyboard back. What you type at a password prompt never reaches the agent,
and values you put on a masking list are hidden in everything it reads.
`cotty agent` starts the agent CLI itself confined, so it cannot go around
cotty to read what cotty hides.

## Status

Testing. cotty is early and not yet reviewed by anyone outside the
project, so do not rely on it to protect anything that matters yet. Four
internal review rounds found weaknesses that were fixed; what is still
open is listed under Known limits in docs/security.md. Interfaces, file
locations and the protocol may change without notice before the first
release. Linux only.

Test packages for Fedora (basalt-testing) and Debian or Ubuntu (the
OpenBasalt apt testing suite) are published at https://obpkg.org. Both
channels are opt-in.

## What cotty is not

- Not a sandbox for the commands the agent types into the shared session.
  Those run with your rights, in your shell: that is the purpose of the
  tool. cotty shows every agent keystroke, can ask you to approve each
  command, and masks known secrets, but a command such as
  `cat ~/.config/x/token` prints a secret cotty does not know about.
- Not a guard for secrets typed with echo on. `export TOKEN=...` is visible
  to the agent unless you turned on private mode first or the value is on
  the masking list.
- Not a defence against a malicious kernel or root.
- Not a network filter. A confined agent can reach any TCP or UDP service
  you can, including services on localhost.
- Masking is not a boundary. It hides values the list knows from what the
  agent reads; it does not stop an agent from obtaining them another way.

The threat model is in docs/PLAN.md, section 2.

## How it works

Three layers, each optional above the first:

1. The session broker owns the terminal. It decides who may type, detects
   secret prompts from the terminal's own settings, keeps the agent's view
   masked, and shows you a status line with a lock while a secret prompt
   is active.
2. `cotty agent` runs the agent CLI in its own namespaces with Landlock,
   seccomp and its own cgroup. Your keys, sockets, other terminals and
   other processes are out of its view.
3. `cotty-guard` (optional, needs root and the BPF LSM) enforces the agent
   rules in the kernel and protects the session's terminal device from
   every other process.

The broker reports one assurance level per agent connection and shows the
weakest one in the status line:

| Level | Meaning |
| --- | --- |
| `strong` | the guard is loaded and confirms the session pts protection, and the agent runs under `cotty agent` and is tagged by the guard |
| `confined` | the agent runs under `cotty agent`, no guard (or the guard without `cotty agent`) |
| `weak` | no confinement evidence: an agent CLI started without `cotty agent`, or any other program of yours |
| `insecure` | broker started with `--dev-insecure` (development only) |

What each level stops, case by case, is in docs/security.md.

## Requirements

- Linux with user namespaces and Landlock (kernel 6.12 or later
  recommended; `cotty doctor` says what your system offers and what is
  missing).
- Go 1.26 or later to build. No cgo.
- For the guard: the BPF LSM active (`bpf` in `/sys/kernel/security/lsm`)
  and BTF. docs/guard.md explains how to enable it.
- On Ubuntu 24.04 and later, the AppArmor profile in `dist/apparmor/cotty`
  so that the installed binary may create user namespaces.

## Build and install

```
make
sudo install -o root -g root -m 0755 bin/cotty /usr/local/bin/cotty
cotty doctor
```

Install cotty root-owned, as a package would: the broker trusts a person
attach only from a binary you cannot replace. With the guard loaded this
is required: the guard registers only brokers that run the root-owned
binary at `/usr/bin/cotty` or `/usr/local/bin/cotty` (`cotty-guard
--cotty PATH` for another place), and sessions do not start otherwise.
`make check` runs gofmt, vet and the unit tests. Every build is static
and without cgo.

The guard (optional):

```
sudo install -o root -g root -m 0755 bin/cotty-guard /usr/bin/cotty-guard
sudo install -m 0644 dist/systemd/cotty-guard.service /etc/systemd/system/
sudo systemctl enable --now cotty-guard
```

Stopping it keeps every rule in force, and while it is installed but
stopped `cotty attach` and `cotty new` refuse to run (they cannot have
the session's broker verified). To remove it: `sudo systemctl disable
--now cotty-guard`, then `sudo cotty-guard uninstall`, which detaches the
programs and forgets every tag, registration and protection.

## Quick start

```
cotty new --ai --name work          # a shared session, you are attached
cotty agent -- claude               # in another terminal: the agent, confined
```

Inside the agent, the `cotty` MCP tools (`term_read`, `term_run`,
`term_type`, `term_wait` and others) act on the shared session. Press
`Ctrl-]` then `?` in the session for the hotkeys: take the keyboard,
private mode, approve an agent command, show the reattach code, detach.
`cotty secrets add NAME` puts a value on the masking list by reference;
the value is never printed.

Reattaching (`cotty attach work`) asks for the reattach code, printed at
detach and shown with `Ctrl-]` then `c`. The code is proven to the
session, never sent, and the session proves it back, so a program that
took the session socket's place learns nothing and is refused; while you
are attached elsewhere, that client also approves the new one. With
several sessions, `cotty attach`, `share` and `kill` need the session
name.

`cotty agent` refuses some setups unless told otherwise:
`--allow-git-init` lets the agent create a repository in a project
without `.git` (its hooks and config are then the agent's),
`--allow-git-links` accepts a project whose `.git`, git config or hooks
are symbolic links, and `--allow-abstract-sockets` starts on kernels
below Landlock ABI 6 even though a display or session bus is reachable
through abstract sockets there. `--show-hidden` leaves a profile's
hidden directories visible (for Claude Code, `~/.claude/ide`, whose lock
files hold your IDE's auth token).

The lock does not light for a password prompt inside a program that
relays the terminal in raw mode (`sudo -i`, `ssh`, `tmux`, `screen`):
turn private mode on before typing a secret there. docs/security.md,
Known limits, lists what is not covered yet.

Per agent CLI setup is in docs/agents/.

### GPG signing in a session

gpg's `pinentry-curses`, started by gpg-agent with `GPG_TTY`, reads
outside the session, where the lock cannot see it. On servers use
loopback (`pinentry-mode loopback` in `~/.gnupg/gpg.conf`,
`allow-loopback-pinentry` in `gpg-agent.conf`): gpg then asks in the
session and the lock lights, `git commit -S` included. With the guard,
`/usr/bin/pinentry-curses` can go on the guard's exception list instead
(`/etc/cotty/guard-exceptions.conf`); without the guard the broker lights
the lock for a pinentry outside the session it finds holding the
terminal. See docs/security.md, GPG.

## Documentation

- docs/PLAN.md: goals, threat model and design
- docs/security.md: what each assurance level covers, where secrets
  live in memory, and the known limits
- docs/broker.md: sessions, status line, hotkeys, the lock, admission,
  audit
- docs/protocol.md: the broker socket protocol
- docs/mcp.md: `cotty mcp`, the tools agents use, end to end tests
- docs/confinement.md: `cotty agent`, `cotty doctor`, profiles, the escape
  matrix
- docs/guard.md: `cotty-guard`, the BPF LSM layer
- docs/vt.md: the terminal emulator library and why
- docs/agents/: one page per agent CLI

## Testing

The host only builds and runs unit tests. Everything that runs sessions,
the confinement or the guard runs in throwaway lab VMs made by
`tests/lab/vm.sh` (plain qemu and KVM as an unprivileged user):
`make vm-matrix`, `make vm-broker-matrix`, `make vm-integration`,
`make vm-e2e`. Never run the escape matrix or the guard on a machine you
care about.

## Reporting a vulnerability

Please report security problems privately, through GitHub's private
vulnerability reporting on this repository. See SECURITY.md.

## License

Apache-2.0, see LICENSE. The BPF programs in `bpf/` are dual licensed
Apache-2.0 OR GPL-2.0-only, because the kernel requires a GPL compatible
license for BPF LSM programs. The libbpf headers vendored in
`bpf/headers/` are LGPL-2.1 OR BSD-2-Clause; cotty uses them under
BSD-2-Clause (bpf/headers/LICENSE.BSD-2-Clause).

## Credits

cotty is part of OpenBasalt (https://openbasalt.org) and was created by
Edimar Cardoso (https://edimar-cardoso.me/en).
