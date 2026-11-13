# What cotty protects, at which assurance level

The threat model is in [PLAN.md](PLAN.md) section 2: the adversary is the
agent's process tree, running as your uid, possibly prompt-injected. This
page says, case by case, which attacks on the session each assurance level
stops, and where secrets live in memory. The confinement itself
(`cotty agent`, layer 2) is [confinement.md](confinement.md); the broker
and the lock are [broker.md](broker.md).

## Assurance levels

The broker reports one level per agent connection (and the weakest of them
for the session, in the status line and in `term_read`'s state):

| Level | Meaning |
| --- | --- |
| `strong` | the guard (`cotty-guard`, BPF LSM, layer 3) is loaded, the agent is tagged, and the guard confirms that the session's pts protection is in place (the broker asks every two seconds; while the guard does not answer the session is `confined`, and after a lapse of the protection it never returns to `strong`) |
| `confined` | the agent runs under `cotty agent` (its own namespaces, Landlock, seccomp, own cgroup), no guard |
| `weak` | no confinement evidence: an agent CLI started without `cotty agent`, or any other program of yours that speaks the protocol. It can do everything you can do as a program, outside cotty's view |
| `insecure` | broker started with `--dev-insecure` (development only) |

A session that must never serve a `weak` agent is started (or shared) with
`--require-confined`. Without it, a weak agent works and the person's
status line shows it in red.

## Escape matrix against the broker

`tests/attacks/broker.sh` (lab VM only: `tests/lab/vm.sh broker-matrix
NAME`) starts a shared session with a scripted person attached, puts a
secret through a `read -rs` prompt, and attacks the broker as an ordinary
process of the same user (weak) and from inside `cotty agent` (confined).
Results below. GAP marks what the docs list as open at that level and
only the guard (layer 3, [guard.md](guard.md)) closes. With the guard
loaded the script expects the confined agent to be reported `strong`.

Runs with the corrected harness and the rows added after the final
review, 2026-11-04, cotty installed root-owned in /usr/local/bin. Every
fail is an open review item (detail `[open: ITEM]`, see below):

| VM | Kernel | Landlock | Guard | Pass | Fail (open items) | Gap |
| --- | --- | --- | --- | --- | --- | --- |
| Fedora 44 Cloud | 7.2.15 | ABI 10 | no | 53 | 5 (B1, B2, B3, B6, S4) | 4 |
| Fedora 44 Cloud | 7.2.15 | ABI 10 | loaded, restarted mid-run | 55 | 9 (B1, B2, B3 twice, B5 twice, B6, S4, S22) | 0 |
| Fedora 44 Cloud | 7.2.15 | ABI 10 | loaded, 620 s idle | see below | B4 | |
| Ubuntu 26.04, AppArmor profile, `lsm=...,bpf` | 7.0 | ABI 8 | no | 54 | 5 (B1, B2, B3, B6, S4) | 3 |
| Ubuntu 26.04, AppArmor profile, `lsm=...,bpf` | 7.0 | ABI 8 | loaded, restarted mid-run | 56 | 8 (as Fedora but S22) | 0 |
| Ubuntu 26.04, AppArmor profile, `lsm=...,bpf` | 7.0 | ABI 8 | loaded, 620 s idle | see below | B4 | |

With every review fix in (the broker, attach and masking fixes, layer 2
and the guard), same date, the guard runs with an idle wait of 620 s and
a guard restart mid-session (`COTTY_MATRIX_IDLE_SECS=620
COTTY_MATRIX_GUARD_RESTART=1`):

| VM | Kernel | Landlock | Guard | Pass | Fail | Gap | Skip |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Fedora 44 Cloud | 7.2.15 | ABI 10 | no | 56 | 0 | 5 | 4 |
| Fedora 44 Cloud | 7.2.15 | ABI 10 | loaded, 620 s idle, restarted mid-run | 67 | 0 | 0 | 0 |
| Ubuntu 26.04, AppArmor profile, `lsm=...,bpf` | 7.0 | ABI 8 | no | 60 | 0 | 4 | 1 |
| Ubuntu 26.04, AppArmor profile, `lsm=...,bpf` | 7.0 | ABI 8 | loaded, 620 s idle, restarted mid-run | 67 | 0 | 0 | 0 |

Without the guard the gap rows are the pts by path, through
`/proc/SHELL/fd/0`, ptrace and `pidfd_getfd` of the shell (Fedora: its
Yama ptrace_scope is 0, Ubuntu's 1 refuses them), a session command
passing its terminal out over SCM_RIGHTS (Ubuntu; on Fedora that row was
a skip in this run, the command was not typed in time), and the renamed
session socket. With the guard every one of them is denied, after the
idle wait and after the restart too, and the confined agent is told
`strong` again once the restarted guard confirms the protection.
`tests/attacks/guard-lifetime.sh` (a session idle for 660 s, then a guard
restart, stop, start and `uninstall`) passes 21 of 21 rows on both VMs.
Reports: `tests/attacks/results/2026-11-04-broker-*fixguard*.txt` and
`2026-11-04-guard-lifetime-*`.

With the second-round broker fixes (cell taint, the lock's executable
name, the typeahead hold after an agent Enter) and their rows, same
date, fresh VMs, guard runs with a restart mid-session
(`COTTY_MATRIX_GUARD_RESTART=1`):

| VM | Kernel | Landlock | Guard | Pass | Fail | Gap | Skip |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Fedora 44 Cloud | 6.19.10 | ABI 7 | no | 62 | 0 | 6 | 1 |
| Fedora 44 Cloud | 6.19.10 | ABI 7 | loaded, restarted mid-run | 70 | 0 | 0 | 0 |
| Ubuntu 26.04, AppArmor profile, `lsm=...,bpf` | 7.0 | ABI 8 | no | 64 | 0 | 4 | 1 |
| Ubuntu 26.04, AppArmor profile, `lsm=...,bpf` | 7.0 | ABI 8 | loaded, restarted mid-run | 70 | 0 | 0 | 0 |

With sudo-rs detection (the next change), same VMs: Fedora 63 pass, 0
fail, 6 gap, 1 skip without the guard and 71 pass with it; Ubuntu 65
pass, 0 fail, 4 gap, 1 skip without and 71 pass with it (row
`u-sudo-command-not-secret` added). The integration tests (17) and the
e2e tests (7, the real Claude run skipped) pass on both, the sudo tests
included: `tests/lab/vm-broker.sh` and `tests/e2e/vm.sh` take
`DISTRO=ubuntu2604`. Reports: `2026-11-04-broker-*sudors*.txt`.

These runs also fixed the harness: its ptrace probe detached before the
tracee's attach stop, which left the session shell stopped wherever the
attach succeeded (Fedora without the guard), so the rows after it that
type into the session (B2, B6 and the new ones) were void there; the
earlier Fedora skips of `u-state-events-during-secret`,
`u-fake-lock-pipeline` and `u-pts-scm-rights` came from that. Reports:
`tests/attacks/results/2026-11-04-broker-*r2broker*.txt`.

Before those fixes (with fix-broker's client side only, guard not
loaded) Fedora had 58 / 0 / 4 and Ubuntu 59 / 0 / 3
(`2026-11-04-broker-fixbroker-*.txt`). The runs of the table further up
are the harness against the code before the fixes: there the idle runs
(`COTTY_MATRIX_IDLE_SECS=620`) found the pts open again after more than
ten idle minutes on both VMs (B4), and the restart runs found it open
after `systemctl restart cotty-guard` while a confined agent was still
told `strong` (B5). Reports: `tests/attacks/results/2026-11-04-broker-*.txt`.

Earlier runs, before the final review:

| VM | Kernel | Landlock | Guard | Pass | Fail | Gap |
| --- | --- | --- | --- | --- | --- | --- |
| Fedora 44 Cloud | 6.19 | ABI 7 | no | 52 | 0 | 2 |
| Ubuntu 26.04, AppArmor profile loaded | 7.0 | ABI 8 | no | 52 | 0 | 2 |
| Fedora 44 Cloud | 7.2.15 | ABI 10 | no | 52 | 0 | 2 |
| Fedora 44 Cloud | 7.2.15 | ABI 10 | loaded | 54 | 0 | 0 |
| Ubuntu 26.04, AppArmor profile, `lsm=...,bpf` | 7.0 | ABI 8 | no | 52 | 0 | 2 |
| Ubuntu 26.04, AppArmor profile, `lsm=...,bpf` | 7.0 | ABI 8 | loaded | 54 | 0 | 0 |
| Arch Linux | 7.2.11 | ABI 10 | no | 52 | 0 | 2 |
| Arch Linux | 7.2.11 | ABI 10 | loaded | 54 | 0 | 0 |
| Debian 13 | 6.12 | ABI 6 | no | 51 | 1 | 2 |
| Debian 13 | 6.12 | ABI 6 | loaded | 53 | 1 | 0 |

These counts are from the harness as it was before the final review:
it did not yet have the rows added after it (below), and it reported a
reachable GAP row as GAP even with the guard loaded. The first two rows
are WP-E's runs; the others are from 2026-11-03 too
(WP-F). With the guard loaded both gap rows read PASS (denied) and both
confined agent endpoint rows report `assurance strong`. The Debian
failure is the same with and without the guard and is not about the
guard: `u-systemd-run-needed-approval` (the `systemd-run --user --pty
cotty attach` attempt was refused, but not through the person's approval
prompt, so the denial counter did not move). Reports:
`tests/attacks/results/2026-11-03-broker-*.txt` (without the guard) and
`tests/attacks/results/2026-11-03-broker-guard-*.txt`. Debian and Arch
have not been run with the corrected harness yet.

| Attack | weak (unconfined process of the user) | confined (`cotty agent`) | strong (guard) |
| --- | --- | --- | --- |
| take the person or control role on the session socket | refused: not classified as a person (no controlling terminal, not the cotty binary) | the socket is not in the agent's view | as confined; the guard tag also marks the peer |
| person or control role on the agent endpoint | refused (the endpoint serves only agents) | refused | refused |
| `cotty share --off` or `cotty kill` without a terminal | refused (no controlling terminal) | no session visible | as confined |
| `cotty attach` from a fresh terminal | asks for the reattach code; with a person attached, a right code then waits for that person's approval (`^] a`), shown with pid, program, terminal and the names of the requester's first two parents. Without the code no attach request is even raised (row `u-attach-needs-code`) | no session visible | as confined |
| `systemd-run --user --pty cotty attach` | as from a fresh terminal: the code first (row `u-systemd-run-needs-code`) | the systemd user manager is unreachable | as confined |
| `systemd-run --user cotty share --off` | refused (no controlling terminal) | unreachable | as confined |
| guess the reattach code (only while no person is attached) | 3 guesses per 30 s per controlling terminal and kernel session over a 50 bit code, then `rate_limited` for that terminal; the code is proven, never sent (protocol.md section 7), so nothing on the socket can be tested offline faster than PBKDF2 with 600000 iterations allows | no admission endpoint in view | as confined |
| read the secret typed at a `read -rs` prompt through the agent role | absent from screen, scrollback and state | absent | absent |
| open the session pts by path (read the person's keys, write fake output) | GAP: the pts belongs to the user and opens | not in the agent's devpts instance | denied for every other process, tagged or not, by the guard's `file_open` rule on the protected pts. The protection lasts as long as the broker runs: idle time, a lost connection and a guard restart or stop do not end it; a session whose protection lapsed (`cotty-guard uninstall`, or no guard at session start) is not reported `strong` |
| open the pts through `/proc/SHELL/fd/0` | GAP: the shell is an ordinary dumpable process | the shell is outside the agent's pid namespace | denied the same way |
| take a copy of the pts without opening it: `pidfd_getfd` on the shell, ptrace of the shell (Yama ptrace_scope 0, the Fedora default), a descriptor passed over a socket | GAP | the shell is outside the pid namespace; `pidfd_getfd` and `ptrace` are denied by seccomp | denied: a process outside the session that is not its broker and not root cannot ptrace-attach to the session's processes (`ptrace`, `pidfd_getfd`, `process_vm_*`, `/proc/PID/mem`), and a descriptor of the pts that arrives over SCM_RIGHTS or `pidfd_getfd` is refused by `file_receive` unless the receiver could open it; rows `u-pts-pidfd-getfd`, `u-ptrace-shell`, `u-pts-scm-rights` |
| list `/proc/BROKER/fd`, read its environ | denied (the broker is not dumpable, its /proc files belong to root) | not visible | as confined |
| ptrace, `/proc/PID/mem`, `process_vm_readv` of the broker | denied (not dumpable; Yama ptrace_scope 1) | denied (other pid namespace, seccomp) | denied, and for a tagged agent also by guard `ptrace_access_check` |
| the same against the attach client | denied (not dumpable once attached) | denied | as confined |
| find the secret in the audit log, broker logs or history | files readable, the secret is not in them | files not visible | as confined |
| connect as an agent to a `--require-confined` session | refused (`confinement_required`), counted in the status line | accepted as confined | accepted |
| replace the session socket the person attaches to (`$XDG_RUNTIME_DIR/cotty/NAME.sock`), or start a second broker with the session's name | a second `cotty __broker` with the same name is refused: each broker holds a lock on `NAME.lock` for its lifetime and never removes a socket that still answers (rows `u-second-broker-same-name`, `u-second-broker-insecure`). GAP: a process of the user can still rename the socket and listen there. Every admission proves a secret, the creator token or the reattach code, with a challenge bound to both pids, and the client requires the broker's proof back: a listener that admits without proving it (as if an attached person had approved, or as a `--dev-insecure` broker) is refused, whatever metadata, name and argv it forged (rows `u-attach-forged-approval`, `u-attach-forged-insecure`); a fake that asks for the code learns nothing it can replay or test guesses against faster than PBKDF2 allows, and a relay fails | the socket is not in the agent's view | denied: a broker registers with the guard under its session name before it binds, and the name is its own while it runs (a second broker with that name is refused, `--dev-insecure` brokers are never registered); only registered brokers (and root) may bind, link, symlink, rename or remove in `$XDG_RUNTIME_DIR/cotty` and its `agent/` directory, and a socket a broker claimed cannot be removed or replaced by any other process, other brokers included (rows `u-session-socket-replace`, `u-second-broker-same-name`); the attach client asks the guard (`verify-broker`) whether the listener is the registered broker of that very session (rows `u-verify-broker-own-session`, `u-verify-broker-other-session`). While the guard is installed but its daemon does not answer, `cotty attach`, `new`, `share` and `kill` refuse to run instead of skipping the check. Residual: the guard refuses to register a broker that is traced at that moment, but a process can start the real cotty under `PTRACE_TRACEME` (allowed with Yama `ptrace_scope` 0 and 1), change its memory before it registers and detach; see Known limits |
| plant a fake socket where confined agents look (`$XDG_RUNTIME_DIR/cotty/agent/`) | possible (the user can write that directory); a fake there sees what the confined agent sends, which a process of the user can already see | read-only mount | as confined, and a tagged agent outside layer 2 cannot create, link or move anything there either (guarded directory) |
| learn the length and timing of a password through `state` events | denied: while secret input is active the agent's state, output counter and `person_typing` do not move; one event at the start and one at the end; the agent's screen is frozen during the prompt and the marks a program prints per key (sudo-rs's asterisks, `sudo` with `pwfeedback`) read `[private]` | as weak | as weak |
| read a command the person types in private mode | denied: agents get the state of the moment private mode began; no OSC 133 command line or exit code is recorded during it, and the last command is cleared | as weak | as weak |
| read rows the person wrote in private mode after it ends | denied: the rows read `[private]` until every column of them was rewritten or erased, wherever the agent moves them (scrolling, insert or delete line, reverse index, scroll regions, insert character, resize), and lines that leave the screen with them are committed as `[private]`; rows are never compared by text, so printing a guess does not tell whether the person saw it (rows `u-private-moved-rows`, `u-private-no-text-oracle`). Residual: what programs keep (shell history, a pager's buffer) can show it again after private mode ends, see below | as weak | as weak |
| make a fake password prompt look trusted | partly: the lock judges every member of the foreground process group and is amber when any is untrusted or an interpreter; it names the pipeline (`sleep \| python3`) and each process by the executable it judged, not by the name it was started under (a symlink called `sudo` to `head` reads `LOCK head (as sudo)`, row `u-fake-lock-renamed`); it marks every job started after an agent's Enter until the shell is back at its prompt. Residual: a trusted non-interpreter that reads a line (`head`, `dd`, `tee`) is still green under its own name, and the "started by agent" note can be shed (`stty -icanon` keeps the shell's line editor away, a builtin loop outlasts the poll): read the name, not only the colour | as weak | as weak |
| type a password ahead of a prompt so it is echoed before echo turns off | denied for up to 150 ms after any Enter at the shell prompt, the person's, the agent's or an accepted agent line: person input is held until the prompt turns echo off (row `u-typeahead-agent-enter`). A program slower than that still gets typeahead echoed | as weak | as weak |
| keep the person out of `cotty attach` by holding the one approval slot (a request nobody answers) or by opening many connections | denied: every attach proves the reattach code before an approval request is even raised, so only a holder of the code can take the slot; a request whose client hung up frees the slot at once, and a terminal whose request was denied waits 30 s before it may ask again; the main socket and the agent endpoint have separate connection caps (128 each) | no admission endpoint in view | as confined |
| stall the person's keys by typing into a program that does not read | bounded: every write to the PTY has a 2 s deadline (the master is non-blocking), so the agent's `type` fails with `internal` and the person's keys go through again; the program still sees nothing until it reads | as weak | as weak |
| lock the person out by guessing reattach codes | denied: the wrong-code backoff is per controlling terminal and kernel session (a pty number reused after the guesser closed its pty does not inherit the lockout); the person's terminal is not locked by another's guesses | no admission endpoint in view | as confined |

Without the guard, the two gaps are why `weak` is weak: an agent CLI you
start without `cotty agent` (or anything it runs) can open the session's
terminal directly, read the keys you type there, including at a password
prompt, and print text the screen shows as if the session had. cotty
cannot stop a program that has all your rights from using them; it can
only notice the agent connections (status line, `--require-confined`).
With the guard loaded the broker protects the session pts before the
shell starts, and the kernel lets it open only for that broker and for
the processes whose controlling terminal it is (the session's own
commands): an unconfined agent, tagged or not, can no longer open it by
path or through `/proc/<shell pid>/fd/0`, as long as that protection is
in place, which is for as long as the broker runs; copies taken without
opening the device (`pidfd_getfd`, ptrace of the shell, SCM_RIGHTS from
a session command) are refused too, and the session reports `strong`
only while the guard confirms the protection. The session socket the
person attaches to cannot be replaced either: only registered brokers
may bind, rename or remove in the runtime directory, a claimed socket is
its broker's alone, a session name belongs to its first broker, and the
attach client asks the guard to vouch for the listener of that session.
The rest of what a weak agent
can do with your rights stays open; start agents with `cotty agent`. The
price of the rule: a program outside the session that opens the terminal
by name (a `pinentry-curses` started by `gpg-agent` with `GPG_TTY` set to
the session's pts) is refused too, unless it is on the guard's pts
exception list (GPG, below; the list lapses with the daemon), and so is a debugger attaching from
outside the session (`gdb -p` from another terminal, not as root).

The second review round (N1, N2, N6, N7, N9 and the rows below) was run
on 2026-11-04 on Fedora 44 (kernel 6.19, Landlock ABI 7) and Ubuntu
26.04 (kernel 7.0 with `bpf` added to `lsm=`, ABI 8): every guard mode,
the broker matrix with and without the guard, the guard lifetime run
(660 s idle, restart, stop, uninstall, upgrade), the Claude config
matrix, the plain escape matrix and the integration tests. No FAIL
outside the layer 2 rows of `guard-only` and the `none` baseline, which
fail by design. Reports: `tests/attacks/results/2026-11-04-r2-*.txt`.

### Rows added after the final review

The final review (2026-11-03) found weaknesses that the matrix did not
exercise. Each now has a row. Until its fix lands the row fails, and its
detail starts with `[open: ITEM]` (ITEM is the review's numbering); the
run's summary counts those separately ("N fail, M of them open review
items"). A row turns PASS on its own once the fix is in. GAP rows
without the guard become FAIL when the guard is loaded, since the guard
is there to close them.

| Row | Script | Item | What it tries |
| --- | --- | --- | --- |
| `u-private-mode-last-command` | broker.sh | B1 | the person runs `export PRIVTOK=...` in private mode with OSC 133 shell integration; the agent reads `state` |
| `u-state-events-during-secret` | broker.sh | B2 | an agent subscribed to `state` counts events while the person types a password one key at a time |
| `u-session-socket-replace`, `u-attach-trusts-fake-socket` | broker.sh | B3 | rename the session socket, listen in its place, and see whether `cotty attach` sends the reattach code |
| `u-second-broker-same-name`, `u-second-broker-insecure` | broker.sh | N1 | start the installed `cotty __broker` with the running session's name (and with `-dev-insecure`); the session's socket inode and broker must stay as they were |
| `u-attach-forged-approval`, `u-attach-forged-insecure` | broker.sh | N1 | a forged listener that passes every consistency check (metadata with its own pid, not dumpable, comm `cotty`, argv `__broker`) admits `cotty attach` at once as an approval or as an insecure broker; the client must hang up |
| `u-insecure-broker-with-guard`, `u-verify-broker-own-session`, `u-verify-broker-other-session` | broker.sh | N1 | with the guard: a `--dev-insecure` session must not start; the guard vouches for a session's broker under its own name and refuses it under another session's name |
| `u-attach-needs-code`, `u-systemd-run-needs-code` | broker.sh | N1 | an attach without the code must not raise an approval request |
| `u-pts-race-open` | broker.sh | N2 | a process watches `/dev/pts` with inotify and retries opening each new terminal while `cotty new` creates a session; with the guard it must never open the session pts (the pty is protected while still locked) |
| `start-protect-not-broker` | guard-lifetime.sh | N2 | a process that holds the master of a pty of its own, but is no registered broker, asks the guard to protect it |
| `upgrade-before-verified`, `upgrade-inode-replaced`, `upgrade-running-verified`, `upgrade-restart-verified`, `upgrade-restart-strong` | guard-lifetime.sh | G3 | the installed cotty is replaced by a new file (as a package upgrade does) while a session runs, then the guard restarts: the guard still vouches for the running broker |
| `upgrade-map-migrated`, `upgrade-incompatible-refused`, `upgrade-incompatible-keeps-enforcing` | guard-lifetime.sh | N9 | a pinned map of an older size is migrated with its entries; one with another value layout refuses the start and the old programs keep enforcing |
| `u-pts-after-idle` | broker.sh, `COTTY_MATRIX_IDLE_SECS=620` | B4 | the session pts after more than 10 idle minutes, guard loaded |
| `u-pts-after-guard-restart`, `u-strong-after-guard-restart` | broker.sh, `COTTY_MATRIX_GUARD_RESTART=1` | B5 | the session pts and the reported level after `systemctl restart cotty-guard` |
| `u-fake-lock-pipeline` | broker.sh | B6 | a fake `[sudo] password` prompt in python behind `sleep 3; sleep 6 \|`; what the lock names |
| `u-pts-pidfd-getfd`, `c-pts-pidfd-getfd` | broker.sh | S22 | a copy of the session pts from the shell with `pidfd_getfd` |
| `person-not-locked-out` | broker.sh | S4 | the real person attaches right after an attacker's wrong guesses |
| `git-dir-rename-hook`, `git-nested-repo-hook`, `git-dir-unchanged` | inside.sh, run.sh | B7 | rename `.git`, copy it back, plant a hook; a nested repository's hooks. Fixed: `.git` is a mount point, the rename fails. A repository the agent creates cannot be prevented; `git-nested-repo-hook` reads GAP and `cotty agent` lists such repositories at exit (`git-new-nested-reported`) |
| `git-rename-*`, `git-hookspath-*`, `git-include-plant`, `git-filter-script`, `git-modules-*`, `git-worktree-*`, `git-nested-*`, `git-commondir-tripwire`, `git-init-refused` | inside.sh, run.sh | B7 | renames around the protected git files, core.hooksPath and include targets that do not exist yet, scripts named by git config, submodule and linked worktree git directories, an existing nested repository, a `commondir` redirect (the launcher stops the agent), `git init` in a project without `.git`. All denied after the fix |
| `relay-osc52`, `relay-kitty-rc`, `relay-osc5113`, `relay-title-kept` | inside.sh, run.sh | S13 | OSC 52, OSC 5113 and kitty remote control printed by the agent reach the person's terminal. Fixed: the relay filters escape sequences; the window title still passes |
| `relay-utf8-c1` | inside.sh, run.sh | N12 | OSC 52 behind a UTF-8 encoded C1 introducer and terminator (`C2 9D`, `C2 9C`), and behind ESC plus a raw C1 byte. Fixed: both relays (`cotty agent` and the attach client) drop U+0080 to U+009F in both encodings |
| `u-fake-lock-renamed` | broker.sh | N3 | `sed` started through a symlink called `sudo` reads a fake `[sudo] password` line; what the lock names |
| `u-private-moved-rows` | broker.sh | N4 | the person prints a marker in private mode; afterwards the agent inserts lines, reverse-indexes and inserts a character on every row, then reads everything |
| `u-private-no-text-oracle` | broker.sh | N5 | the agent prints a row equal to one the person printed in private mode; it must read its own row, not `[private]` |
| `u-sudo-command-not-secret` | broker.sh | sudo-rs | `sudo -n sleep 3` typed by the agent: sudo relaying the terminal for its command must not light the lock. The password prompt itself (sudo-rs on Ubuntu 26.04, `sudo` with `pwfeedback` on Fedora), a wrong password and its retry, and `sudo vim`, `-i`, `-s`, `less` are integration tests (`TestSudoPwfeedbackDetected`, `TestSudoWrongPasswordRetry`, `TestSudoCommandsNotSecret`) run on both distributions |
| `u-private-then-secret-freeze`, `u-private-then-private-freeze` | broker.sh | T1 | the person prints a marker in private mode; afterwards the agent's view freezes again, at a `read -rs` prompt the agent starts itself and when the person turns private mode on again; the agent reads everything while frozen |
| `u-forged-osc133-private-row` | broker.sh | T2 | the agent prints forged OSC 133 B and C marks around a row the person wrote in private mode, then reads `state.shell.last_command` |
| `u-typeahead-agent-enter` | broker.sh | N15 | the person types a password right after an agent's Enter, before the agent's command turned echo off |
| `abstract-socket-refusal`, `x11-abstract`, `dbus-abstract`, `kitty-abstract` | run.sh, inside.sh | S10 | on Landlock ABI below 6, `cotty agent` must refuse while an abstract X11 or D-Bus socket listens; with `--allow-abstract-sockets` the abstract rows read GAP (Ubuntu 24.04 VM) |
| `var-socket-dir` | inside.sh, run.sh | S11 | a socket in `/var/lib/incus`; covered by the mount view on every ABI |
| `socket-roots-refused` | run.sh | S12 | `/tmp`, `$XDG_RUNTIME_DIR`, `/run`, `/dev/shm`, `/var`, `/tmp/.X11-unix` as project, `--ro` or `--rw`, and a foreign `--agent-dir` |
| `env-tokens` | inside.sh | S15 | `HF_TOKEN`, `DATABASE_URL`, `STRIPE_SECRET_KEY` from the person's environment |
| `claude-seed-sanitized` | claude-config.sh | S16 | MCP servers and keys of `~/.claude.json` in the seeded copy |
| `apparmor-agent` | inside.sh | S18 | the agent's AppArmor label: `unpriv_cotty` (no capabilities) where cotty runs under its AppArmor profile |
| `runtime-cotty-rename`, `runtime-cotty-plant` | inside.sh | nit | swap `$XDG_RUNTIME_DIR/cotty` inside to fool the agent's own MCP client |
| `guard-pts-pidfd-getfd` | guard-inside.sh | S22 | as above, against the guard alone |
| `guard-clone-into-cgroup` | guard-inside.sh | S20 | `clone3(CLONE_INTO_CGROUP)` into another cgroup of the user |
| `guard-cgroup-freeze`, `guard-cgroup-kill` | guard-inside.sh | S21 | freeze or kill a cgroup of the person without a signal |
| `guard-prlimit-outside`, `guard-sigio-kill` | guard-inside.sh | S21 | `prlimit` and SIGIO (`F_SETOWN` with SIGKILL) on a process of the person |
| `guard-socket-rename-allowed` | guard-inside.sh | S19 | rename a socket of the person into the agent's allowed directory and connect |
| `guard-bind-in-cotty-dir`, `guard-bind-in-agent-dir`, `guard-link-into-agent-dir`, `guard-symlink-into-cotty-dir`, `guard-rename-cotty-dir` | guard-inside.sh | B3 (guard rule), S19 | plant, link or symlink a socket in the cotty runtime or agent endpoint directory; rename the runtime directory away |
| `guard-setnice-outside` | guard-inside.sh | S21 | the nice value of a process of the person |
| `u-ptrace-shell`, `u-pts-scm-rights`, `u-tagged-dev-tty` | broker.sh | S22, S23 | ptrace of the session shell; a session command passes its `/dev/tty` out over SCM_RIGHTS; a guard-tagged agent started inside the session opens `/dev/tty` |
| every row | guard-lifetime.sh | B4, B5, S24 | a real session idle for 660 s, a guard restart, stop, start and `uninstall` mid-session: the pts by path and through `/proc`, the level the session reports, the agent's tag, taking over the protection with an `O_PATH` descriptor, the protection gone once the broker exits |
| `home-link-protect`, `home-link-ro` | claude-config.sh | C0 | a link left in a writable profile directory on an earlier run points a protected path (`~/.claude/local`) or a read-only one (`~/.local/share/claude`) at `~/.ssh`; the start must be refused, or the target left out |
| `claude-ide-lock-hidden`, `claude-ide-show-hidden` | claude-config.sh | C1 | read an IDE lock file in `~/.claude/ide` and plant one; with `--show-hidden` the directory is visible |
| `claude-settings-missing` and the other `plant` rows, `claude-protect-around`, `claude-hook-script` | claude-config.sh | B7 | create a protected config file that did not exist at launch, and the files that define commands (`~/.claude/agents`, `commands`, `skills`, `plugins`, `CLAUDE.md`, `~/.cursor/hooks.json`, Codex rules, Gemini extensions, opencode plugins and language servers), for every built-in profile; rename around them; write a script that settings name. Fixed: protected paths are created empty outside and bound read-only |

Typeahead before a secret prompt (S9) is exercised by
`TestTypeaheadNotEchoed` in tests/integration (lab VM), next to
`TestPrivateModeLastCommand` (B1), `TestSecretPromptEvents` (B2),
`TestAttachRefusesFakeListener` (B3) and `TestFakeLockPipeline` (B6);
private rows moved by insert or delete line, reverse index, scroll up or
down, a scroll region and insert character, the absence of a text
oracle and of a length oracle, resize and alt screen after private mode,
long values printed over more than 200 lines and paged `since` reads
(B8, N4, N5, N24) by unit tests in internal/broker (`maskread_test.go`;
each move test checks on the raw screen that the row really moved); the
lock's name for a renamed program (N3), the PTY write deadline (N8), the
typeahead hold after an agent Enter (N15), the approval slot and the
connection caps (N11) by unit tests in internal/broker; UTF-8 encoded C1
controls (N12) by unit tests of both relays (internal/confine,
internal/attach); parallel MCP tool calls (S32) by unit tests in
internal/mcp. Third review: a freeze over earlier private rows and the
frozen cursor column (T1, `TestFrozenViewKeepsEarlierTaint`), forged and
genuine OSC 133 marks over a private row (T2,
`TestLastCommandSkipsTaintedRows`), a prompt program a script execs late
(T3, `TestLateExecPromptDetected`, and `TestSudoFromScriptDetected` in
tests/integration with sudo-rs on Ubuntu 26.04), the code read on a
control connection, a denied approval and two proofs of one code (A1,
A2), a second broker that must not start its shell (A4), the guard's
parse of a broker's flags (G1), `printf %q` against bash's own output
(M1), links at protected home paths (C0) and the hidden IDE directory
(C1), by unit tests in internal/broker, internal/guard/daemon,
internal/session, internal/mask and internal/confine. Not exercised yet: `setsid` plus `TIOCSCTTY`.

What the guard blocks by itself (an agent registered with the guard but
started without layer 2, `tests/attacks/guard.sh guard-only`) is in
[guard.md](guard.md).

Same-run checks of the session itself: the shell and its children have
`RLIMIT_CORE` 0 (hard), and `HISTFILE` is in
`~/.local/state/cotty/sessions/<name>/`.

## Where secrets live in memory

- Masking list: the masking engine (internal/mask) copies each value into
  memory locked with mlock, outside the Go heap where the kernel allows
  it, and zeroes it on removal and when the session ends. The copies read
  from the sources (secretsrc) are zeroed right after they are added.
- Terminal model: the broker's emulator grid and scrollback (up to 20000
  lines) hold what the session printed, unmasked, in ordinary memory; so do
  the attach client's buffers. A secret printed in the session is there.
  These are not locked (they are large and change constantly). They are
  protected by the processes, not by mlock: the broker and the attach
  client are not dumpable (no ptrace, no /proc/PID/mem, no core file for
  processes of the same user, and Yama ptrace_scope 1 on top), and a
  confined agent cannot see either process. Swap can still hold them;
  use encrypted swap.
- What the person types at a secret prompt goes from the attach client to
  the broker to the PTY and nowhere else; the broker wipes the buffer
  after the write.
- `cotty mcp` holds only masked text (it is the agent's side) and sets
  RLIMIT_CORE 0 anyway.
- Session children (the shell and everything it starts) inherit
  RLIMIT_CORE 0 with a hard limit of 0, so a crashing program that held a
  password writes no core file.

## Masking is not a boundary

Masking hides values the list knows from what the agent reads; it does
not stop the agent from obtaining them by other means (a command it types
runs with your rights, PLAN.md section 2). It also tells whoever prints
text whether that text is on the list: an agent can guess a weak secret
by printing candidates and watching which come back masked. Fragment
masking stays off for that reason. Nothing detects such guessing: a wrong
guess is no hit and leaves no trace, and `mask.probe` in the audit log
(broker.md, Audit) only counts repeated hits of one name at many places
within a minute, which happen after a value was already guessed (and a
screen clear reuses one place); it is a weak signal, not a detector. Use
long random values for anything on the list: `cotty secrets add` refuses
a typed value shorter than 6 bytes and warns on weak ones, and `cotty
secrets check` reports values under 6 bytes as NOT MASKED (the broker
cannot mask them). A masked value reads `[masked:NAME]` without padding,
and the cursor column moves with the replacement, so within a row the
length does not show; a value that wraps still shows its length in whole
rows. Covered encodings beyond the value itself: base64 at the three byte
alignments (also wrapped across lines), base64 of the base64, JSON
escapes, a private key inside a JSON string (`\n` line ends), shell
quoting with backslashes (`declare -p`, `printf %q`), multi-line values;
not covered: non-ASCII `\u` escapes, indented multi-line values, `$'...'`
quoting of values with control characters, and hex dumps in columns
(`xxd`, `hexdump -C`, `od`). The masker is given enough text around a
read to see the longest encoded value on the list (at least 200 lines,
more when a value is longer than those hold), so a long value printed
over many short lines is masked at a page edge too.

## Known limits

What follows is known and not covered yet, or covered only in part. Each
item says what can happen and what to do meanwhile.

### Private mode and reads

- Private mode hides rows, not what programs keep. After it ends, the
  shell's history (Up arrow, `history`, `!!`, zsh autosuggestions), a
  redraw (`C-l` in a full screen program that kept the text) or a pager's
  buffer can draw the text again, now as ordinary output the agent reads.
  Under `--policy confirm` agents cannot press Up, Down, PgUp, PgDn or any
  Ctrl or Meta key but C-c, nor type history expansion (`!`, `^`), which
  closes the recall keys of bash and zsh with their default bindings; an
  approved `history` and autosuggestions still show the line, and under
  the default policy nothing stops it (broker.md, Private mode). Start
  commands typed in private mode with a space and set
  `HISTCONTROL=ignorespace` (bash) or `setopt HIST_IGNORE_SPACE` (zsh,
  then run one more command), and leave pagers and editors that showed
  private text before turning private mode off.
- `cursor_since` stops during private mode and jumps when it ends; the
  jump tells how many lines scrolled meanwhile (not what they held).
- `sudo-rs` (the default `sudo` on Ubuntu 26.04) and `sudo` with
  `pwfeedback` read the password in raw mode. They are detected as
  setuid-root processes without a child (broker.md, The lock), also when
  a script or Makefile starts them late; a program that reads a password
  in raw mode and is not setuid root is not. While the terminal is raw
  with echo off (also at every idle shell prompt) the broker re-checks
  the foreground group's members and their children every 50 ms and
  walks all of `/proc` only when they change or every 5 s: a process
  that joins the group from elsewhere in the session (`setpgid`, not a
  child of a member) is judged up to 5 s late.
- A prompt inside a program that relays the terminal in raw mode for its
  whole run (`sudo -i`, `sudo -s`, `ssh host`, `tmux`, `screen`,
  `script`, `docker exec -it`) does not light the lock: the agent may
  type into it and `person_typing` moves per key (nothing is echoed, so
  the characters do not reach the model). Turn private mode on inside
  relays.
- The setuid rule asks the kernel for a process's children
  (`/proc/PID/task/*/children`, `CONFIG_PROC_CHILDREN`). Without it,
  `sudo vim` or `sudo -i` count as a prompt for their whole run: the
  agent's view stays frozen (nothing leaks; the agent sees less).
- An attach client in its own pid namespace (a Flatpak terminal) cannot
  prove the reattach code, since the proof binds both pids: it fails
  closed (`cotty attach` refuses); run it from a terminal outside such a
  sandbox.
- The status row: when a program's bottom scroll margin is above the
  last session row, a line feed or cursor down from below the region can
  reach the status row. The client redraws the status line in the same
  write, so at most it flickers; rendering the person's terminal from
  the client's own emulator would close this.

### GPG

gpg asks for a passphrase through a pinentry program that gpg-agent
starts. With `GPG_TTY` set, that is `pinentry-curses` on the session pts,
outside the session: it is not in the foreground job, so the lock does
not light for it, and with the guard loaded it may not open the pts.

On a server without a desktop, use loopback: gpg then asks on its own
terminal, in the foreground job, with echo off and ICANON on, which
lights the lock (`LOCK git | gpg` for `git commit -S`). No exception is
needed.

```
# ~/.gnupg/gpg.conf
pinentry-mode loopback
# ~/.gnupg/gpg-agent.conf (the default since GnuPG 2.1.12)
allow-loopback-pinentry
```

With the guard, `pinentry-curses` can be listed instead
(`/etc/cotty/guard-exceptions.conf`, docs/guard.md, The pts exception
list): it may then open the pts, the guard logs the use, and the lock
reads `LOCK pinentry-curses (exception, for gpg-agent)`. The list lapses
with the daemon: stopped, or silent for 90 seconds, the guard refuses
the pinentry again.

Without the guard (or while its daemon cannot answer), the broker looks
for the reader itself: while a job runs with echo off and no prompt rule
explains it, it scans `/proc/*/fd` of your processes for one outside the
session that holds the session pts, and lights the lock for it, never as
a system program: `LOCK pinentry-curses (not a system program) (outside
the session, for gpg-agent)`. The agent's input is held and its view
frozen as for any secret prompt. Loopback stays the better choice: the
scan sees the reader only once it holds the pts, and not while the shell
sits at its prompt (docs/broker.md, A reader outside the session).

Results (`tests/attacks/gpg.sh`, `tests/attacks/guard-exceptions.sh`)
are in the PR that added them and in `tests/attacks/results/`.

- An exception names a file, not the code that runs in it, nor who
  started it: a process of yours that is not an agent (a `weak` agent
  CLI included) can run the listed pinentry with `--ttyname` set to the
  session pts and read the PIN from its standard output (the pinentry
  protocol returns it to the parent), with the lock lit as the person
  expects; the lock's `for PARENT` is the signal (`for gpg-agent`, not
  `for python3`). It can also start it with `LD_PRELOAD`, or trace it
  (the process that starts a program can trace it under Yama
  `ptrace_scope` 1). Agents under `cotty agent` cannot.
- Without the guard, the broker's own scan lights the lock for the
  pinentry (row `gpg-pinentry-no-guard`), but only while a job has the
  terminal; a program that reads the pts while the shell sits at its
  prompt is not seen.
- `gpg-agent` started by an agent, and so its pinentry, is tagged: the
  exception never applies to it, and signing fails. Start gpg-agent
  yourself (`gpgconf --launch gpg-agent`) or use loopback.

### Admission

- The approval request names the requester's pid, program (always
  `cotty` for an attach), terminal and its first two parents. Those
  names are process names, which a program can choose: an agent's
  `script -c 'cotty attach S'` can call its parent `bash`. The request
  does not say whether an agent or a guard-tagged process is in the
  chain. Approve only an attach you just started yourself.
- A program in the session can draw a fake `Reattach code:` prompt on
  the session screen. The real prompt is the attach client's and never
  appears inside a session's screen; do not type a code into a session.

### The guard

- Traced brokers: the guard refuses to register a broker that is traced
  when it registers, but a parent can start the real cotty under
  `PTRACE_TRACEME` (allowed with Yama `ptrace_scope` 0 and 1, the Ubuntu
  and Debian default included), change its memory before it registers
  and detach. With `ptrace_scope` 0 a process can also follow `cotty new`
  with `PTRACE_O_TRACEFORK` and catch every new broker. The broker's own
  `--dev-insecure` refusal and the client's admission proofs still hold;
  what is lost is the guard's word that the broker runs unmodified.
- Brokers started by a cotty older than this version registered without
  a record of their executable: after a package upgrade replaces the
  installed cotty, those sessions cannot be reattached (the clients fail
  closed). End them before upgrading from such a version. This holds for
  the first upgrade to a guard that keeps the record too: sessions whose
  broker started under the previous guard are locked out once; later
  upgrades keep running sessions reachable. A downgrade to
  a build before the map migration goes through the old start path.
- The client connects to the guard's socket without a timeout. When the
  daemon's backlog is full, `cotty attach`, `new`, `share`, `kill` and an
  agent's tag request wait instead of failing.
- Each user may hold 64 connections to the guard, and every running
  broker holds one. With 64 sessions, or when a process of the user (any
  command the agent typed outside `cotty agent`) holds 64 connections,
  `cotty attach`, `new` and `kill` are refused with "daemon does not
  answer". Stopping that process, or sessions, frees the slots.
- Denials of processes that are not agents are rate limited per process,
  not per user: a loop that forks processes which each get a denial
  fills `/var/log/cotty/guard.audit.jsonl`. The log is not rotated by
  cotty; rotate it with logrotate.
- 90 seconds after the daemon stops, the runtime directory rule ends and
  a process of the user can rename `$XDG_RUNTIME_DIR/cotty` away. That
  only breaks attaching (the clients fail closed); start the guard again.

### Confinement

- Git hook managers: the shims Husky, lefthook and pre-commit install in
  `.git/hooks` run programs from the work tree (`node_modules/.bin`,
  `npx lefthook`, the project's `.venv` Python). Those are writable by the
  agent, so a hook manager installed inside the project is itself a way
  to run code with your rights at your next commit. Review the project's
  `node_modules` and `.venv` changes, or install the hook manager
  outside the project.
- The hook manager config parser covers the usual YAML and JSON list
  forms of Husky, lefthook and pre-commit. It does not cover bare script
  names (`entry: lint.sh`, `sh lint.sh`), YAML block scalars, minified
  JSON, lefthook `source_dir`, `extends` and `remotes`, the
  `.config/lefthook.*` and `*.jsonc` names, or a `--config` baked into the
  pre-commit shim. Scripts named that way stay writable.
- Placeholders: a protected config file that does not exist is created
  empty outside before the launch, and only `--dry-run` lists them. For
  lefthook a `lefthook.yml` holding `{}` is created even when the
  person's config is `.config/lefthook.yml` or `lefthook.jsonc`, which
  lefthook then ignores: the person's hooks stop running. A pre-commit
  config `repos: []` turns "no config" into a silent pass. Check `git
  status` after the first run in such a project.
- A `core.hooksPath` that goes through a symbolic link in an
  intermediate directory (`tools/hooks` with `tools -> ../shared`) is
  protected at its target; the agent can replace the `tools` link with a
  directory of its own hooks. The last component is checked
  (`--allow-git-links`), the components before it are not.
- The exit report of new repositories is skipped when the scan reaches
  its limit (50,000 entries), and it does not look inside dependency
  directories (`node_modules`, `vendor`) or below its depth limit: a
  `git init` there is not reported.
- The level `cotty agent` reports does not lower for weakening flags: a
  run with `--allow-abstract-sockets` on Landlock ABI below 6, or any
  `unshare -U` program, still reads `confined`; `--quiet` hides the
  security notes (a replaceable link, scan limits, "the cotty binary is
  in a directory the agent can write").
- Links inside a protected directory (`~/.claude/skills/x ->
  ~/dotfiles/...`) get their targets made read-only only when they lie
  in a directory the agent may write, and the scan stops after 20,000
  entries: links past that point lead to writable targets.
- The directories cotty hides because they hold service sockets
  (`/var/lib/mysql` and the others in the list) are matched by path, not
  by their real location: a symbolic link such as `/var/lib/mysql ->
  /srv/mysql` leaves the real directory visible, and so do systems that
  move `/opt` or `/var` (`/opt -> /var/opt`).
