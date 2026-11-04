# Broker and attach client

How a session behaves for the person. The wire contract is
[protocol.md](protocol.md); the vt library choice is [vt.md](vt.md).

## Commands

```
cotty new [--name N] [--ai] [--require-confined] [--policy confirm] [-d] [-- shell argv]
cotty attach [session]
cotty ls
cotty share [--off] [--require-confined[=false]] SESSION
cotty kill SESSION
cotty secrets list | add NAME [SOURCE] | remove NAME | check [NAME]
```

`cotty new` starts one broker process per session (detached, its own
kernel session, stderr in `$XDG_RUNTIME_DIR/cotty/<name>.log`) and attaches
to it. The broker runs `$SHELL` as a login shell unless a command follows
`--`. `--ai` shares the session with agents from the start; otherwise
`cotty share` or the `^] s` hotkey does it. `-d` starts the session without
attaching and prints the reattach code.

`--require-confined` (off by default) refuses agent connections whose
assurance is `weak`: agents started without `cotty agent`, or any program
of yours that speaks the protocol. They get `confinement_required`, the
audit log records the refusal and the status line counts it. Without the
option such agents are accepted and the status line shows them in red
("1 unconfined agent"), so you always know when an agent could reach more
than cotty shows it. `cotty share --require-confined SESSION` turns it on
for a running session (and closes the weak agents already connected);
`--require-confined=false` turns it off; plain `cotty share` keeps the
setting.

## The session's shell

The shell runs with `HISTFILE` set to
`$XDG_STATE_HOME/cotty/sessions/<name>/history` (default
`~/.local/state/cotty/sessions/<name>/`, mode 0700) and
`COTTY_STATE_DIR` naming that directory for shell integration scripts.
History and integration state therefore never land in a directory an agent
may write (its project), whatever the working directory is; `cotty agent`
refuses `~/.local/state/cotty` and `~/.config/cotty` (and their parents) as
a project or extra path. A shell startup file that sets `HISTFILE` itself
wins; keep it outside your projects.

The broker sets `RLIMIT_CORE` to 0, soft and hard, before it starts the
shell, so no session child can write a core file (a crashing program that
held a password) or raise the limit again.

## Status line and hotkeys

The attach client keeps the terminal's last row for a status line drawn by
cotty. The session's terminal is one row shorter; the client rewrites
scroll margins and absolute row moves so no program can write into that
row, and redraws it after every burst of output. It shows the session name,
the lock, private mode, a pending agent line, pending attach requests, who
holds the keyboard, an agent's request for the keyboard (also while you
hold it, which is when it matters), what the agent just typed, unconfined
agents (red) and agents refused by `--require-confined`, the number of
agents, `confined-only` when the session requires confined agents, and the
assurance level. A pending attach request comes first (the oldest one,
which is the one `a` and `x` answer, with a count of the others), and
names from the session are cut to a few cells, so neither can push the
lock out of the line.

The client also drops what the session's output could use to paint,
copy into, recolour or freeze that row, or to make the person's terminal
answer as if the person had typed: rectangle and screen-fill operations,
window operations, left/right margins, palette changes, encoding and
keyboard-lock modes, OSC 52 (clipboard), DCS, APC, PM and SOS strings,
and every terminal query (device attributes, cursor and status reports,
mode, setting and capability requests, colour queries). The broker's own
terminal emulator answers the queries for the session. Only a short list
of OSC commands passes (titles, working directory, hyperlinks,
notifications, shell marks, default colours). Before each draw the
client resets charset, insert and origin mode and the pen, and puts them
back after. If the output keeps the terminal inside a sequence or a
synchronized frame for more than 100 ms, the client cancels it (CAN) and
draws the line anyway. Bracketed paste stays on in the person's terminal,
and `Ctrl-]` inside pasted text is passed on, not taken as the prefix.

Hotkeys: `Ctrl-]` then

| key | action |
|-----|--------|
| k   | take the keyboard (agents are refused) or give it back |
| p   | private mode on or off |
| y n | accept or reject the agent line waiting for confirmation |
| a x | allow or deny a pending person attach |
| s   | share the session with agents, or hide it |
| c   | show the reattach code |
| d   | detach (prints the reattach code) |
| ?   | help |
| Ctrl-] | send a literal Ctrl-] |

## The lock

A secret prompt is ECHO off with ICANON on in the PTY's termios (sudo, su,
passwd, ssh, getpass, `read -s`), or ECHO off in raw mode while the
foreground process group holds a setuid-root process that has not
started a child yet (sudo-rs, Ubuntu 26.04's sudo, and sudo with
`pwfeedback` read the password that way), or a program on the secret
program list (`pinentry-curses`, `pinentry-tty`, `pinentry`, plus
`~/.config/cotty/secret-programs`). Once sudo has started the command it
was given it relays the terminal in raw mode for it, but then it has a
child and the command reads the keys: `sudo vim`, `sudo -i`, `sudo -s`,
`sudo less` do not light the lock. Setuid root comes from the kernel (a
user cannot make a root-owned setuid binary); its name is the one it was
started under, since its executable cannot be read. With the guard,
a program outside the session that opened the pts through the guard's
pts exception list (docs/guard.md) lights the lock while it runs and echo
is off, named with its parent: `LOCK pinentry-curses (exception, for
gpg-agent)`; a parent that is an agent's job marks it `(started by
agent)`. Without the guard, see A reader outside the session below. The
broker polls termios on every output chunk, before every batch of person
input and every 100 ms; after a change it holds person input for 50 ms and
reads again. The members of the foreground group are described again
when the group changes and while it is young. While the terminal is
raw with echo off and no prompt is lit (a script or a Makefile can start
sudo-rs long after it took the terminal; readline and zle keep that mode
at every idle prompt too), the members are re-checked every 50 ms from a
few `/proc` files each (alive, same executable and name, no new child in
the group), and the whole of `/proc` is walked only when that check sees
a change or 5 s have passed, outside the broker's lock. While a prompt
is lit, members that have exited are dropped, so a short helper
(`newuidmap`, `fusermount3`) does not keep the lock on after it ends. After an Enter at the shell prompt (yours, the agent's, or an
agent line you accepted), what you type next is held for up to 150 ms (or
until a secret prompt is detected), so a password typed ahead of `sudo` is
not echoed before sudo turns echo off. A program slower than that to turn
echo off still gets typeahead echoed.

The lock judges every process of the PTY's foreground process group (the
one reading the password may be any member of a pipeline, not only its
leader):

- green: every member is a process running setuid root for the user (sudo,
  su, passwd), or a root-owned binary in a system directory that the user
  cannot write and that is not an interpreter (ssh, openssl);
- amber: anything else, including shells (`read -s`), interpreters
  (python's getpass) and any pipeline with such a member, with "(started
  by agent)" when the job started after an agent line (any job that takes
  the terminal before the shell is back at its line editor, draws a prompt
  or you press Enter at the prompt).

With several members the lock names them all (`LOCK sleep | python3`).
Each process is named after the executable the lock judged, not the name
it was started under: a symlink called `sudo` to `head` reads `LOCK head
(as sudo)`. A setuid-root process (sudo, su, passwd) cannot be read by
the user, so it is named as it was started; it is a root program reading
the terminal either way.

Type a password only when the lock is lit, and read the program it names:
a green lock says the reader is a system program, not that it is the one
you expect (`head` is a system program too).

Known false negatives (the lock stays off): a program that is not setuid
root and reads a password in raw mode drawing its own field; and any
prompt inside a program that relays the terminal in raw mode for its
whole run: `sudo -i`, `sudo -s`, `ssh host`, `tmux`, `screen`, `script`,
`docker exec -it`. There the outer termios stays raw with echo off and
the foreground group is the relay, so a `sudo`, `passwd`, `read -s` or a
remote password prompt inside it does not light the lock: the agent may
type into it, and `person_typing` moves per key (nothing is echoed, so
the characters themselves do not reach the model). Use private mode
inside relays. A secret typed with echo on (`export TOKEN=...`) is
visible to the agent unless private mode is on or the value is on the
masking list.

While the lock is lit, person bytes go to the PTY only (the buffer is
wiped after the write), agent input is refused with `secret_input_active`,
and agents see `secret_input: active` until the Enter or the termios
change. Agents get one state change when the prompt starts and one when
it ends: no event, output counter or `person_typing` change per keystroke.
While the lock is lit the agent's screen is frozen as in private mode, and
rows written meanwhile (the asterisks sudo-rs and `pwfeedback` print per
key) read `[private]` afterwards, so they tell neither the length nor the
timing. Consecutive prompts with echo kept off ("Verifying - Password:",
"Sorry, try again") are reported again when the program prints.

The broker never logs person keystrokes, in secret mode or not.

### A reader outside the session

Without the guard, nothing stops a process of yours outside the session
from opening the session pts and reading what you type (a
`pinentry-curses` that gpg-agent starts with `GPG_TTY`). The broker
looks for one when the guard cannot answer (not loaded, its daemon down,
or a daemon too old for `pts-exception`): while a job (not the shell at
its line editor) has the terminal with echo off and no prompt rule
explains it, it scans `/proc/*/fd` of your processes for the session pts
and lights the lock for the first holder that is neither the broker nor
in the session (the shell's session, or a descendant of the broker):
`LOCK pinentry-curses (not a system program) (outside the session, for
gpg-agent)`. It is never green, and agent input is held and the agent's
view frozen as for any secret prompt. The lock ends when that process
exits or the job leaves the terminal.

The scan runs with the same timing as the guard question (before person
input, at most every 10 ms, and after output, at most every 250 ms) and
never under the broker's lock. Each pass reads the `/proc` directory and
looks only at the descriptors of processes it has not seen before or
that started less than 2 s ago; the descriptors of every process are
read again at most every 5 s, and never on the path of a key. A process
that kept the session terminal after it left the session (a daemon
started from the shell that did not close its standard input) lights the
lock while a job reads with echo off; close its descriptors
(`</dev/null`). Not seen: a reader while the shell sits at its prompt
(readline and zle keep echo off there, so every such daemon would lock
the session), and a holder another user owns (it cannot open your pts).

## Who is the person

The broker classifies each connection from the kernel's view of the peer
(protocol.md section 6). On top of that, a person connection is admitted
when:

1. it proves the creator token (the attach that `cotty new` runs itself);
2. or it proves the reattach code; when a person is already attached,
   that person then approves it with `^] a` as well (the request shows
   the pid, program, terminal and the names of its first two parents,
   which a program can choose; one request at a time; a
   request whose client went away is dropped at once, and a terminal whose
   request was denied waits 30 seconds before it may ask again).

An approval alone is not enough: the code is what lets the client check
that it reached the session's broker, which proves it back.

The reattach code is printed at detach and shown with `^] c`. It is read
from the terminal with echo off, never from arguments or the environment,
and never sent: the client and the broker prove it to each other
(protocol.md section 7), so a process that took the socket's place does
not learn it. It rotates when a person attaches with it, also when the
attached person denies that attach or does not answer (`cotty share` and
`cotty kill` leave it valid, and cannot read the next one); three wrong
codes from one terminal lock admission from that terminal for 30
seconds. The real code prompt is the attach client's, in a terminal of
its own: it never appears inside a session's screen. A program in the
session can draw a fake `Reattach code:` prompt there; do not type a
code into a session.

Before sending anything the attach client checks that the process on the
socket is the session's broker: a private runtime directory, the pid and
start time the session metadata names (or the pid `cotty new` started),
not dumpable, running `cotty __broker`. A process of yours can forge
those; with cotty-guard loaded the guard confirms, as root, that the
listener is the registered broker of that session name and runs the
installed binary. And whatever the listener is, the client refuses an
admission the broker does not prove (the creator token or the code).
With several sessions `cotty attach`, `share` and `kill` need the session
name. If the terminal closed without a detach and nobody noted the code,
the session can only be ended (`cotty kill`, which also needs the code).

One broker per session name: a broker holds a lock on
`$XDG_RUNTIME_DIR/cotty/NAME.lock` while it runs, refuses a name whose
lock is held (before it starts the shell, so your login files never run
for a refused broker), and never removes a socket that still answers. With the
guard loaded the name is also registered with it, and the socket is
claimed: no other process, another broker included, can remove or
replace it while the broker runs.

## Limits

At most 128 connections at a time on the session socket and 128 on the
agent endpoint (separate counts, so agents cannot fill the person's), 8
concurrent waits per connection. Every write to the PTY (person keys,
agent text, terminal query answers) has a 2 second deadline: an agent
that types more than the PTY buffers into a program that does not read
gets `internal` ("the program did not read its input in time") instead
of blocking the broker, and your keys reach the PTY again as soon as it
has room.

## Masking list

`cotty secrets` keeps references, never values, in
`~/.config/cotty/secrets.conf` (internal/secretsrc):

```
cotty secrets add GITHUB_TOKEN                     # typed with echo off, kept in secrets.env (0600)
cotty secrets add HUB_KEY --command 'ai-hub secret get openai/api-key'
cotty secrets add NPM_TOKEN --pass dev/npm
cotty secrets add DB_PASSWORD --secret-service service=db,user=app
cotty secrets list                                 # names and references
cotty secrets check                                # reads each value, prints ok or the error
cotty secrets remove GITHUB_TOKEN
```

Each broker reads every listed value when the session starts (a keyring
may ask to be unlocked; `cotty new` waits for it) and masks it, and the
built-in token rules, in everything agents read (protocol.md section 9).
A secret added later is masked in a running session when the agent calls
`term_mask NAME`. Secret Service references need `secret-tool`; `cotty
doctor` says whether it is installed.

Where the values live: the masking engine copies each value into memory
locked with mlock outside the Go heap and zeroes it when the session ends;
the copies read from the sources are zeroed right after. The terminal
model is different: its grid and scrollback hold what the session printed,
secrets included, unmasked, in ordinary memory. Both are protected the
same way: the broker is not dumpable (no ptrace, no /proc/PID/mem, no core
file for processes of the same user) and a confined agent cannot see the
broker at all (docs/security.md).

## Audit

`$XDG_STATE_HOME/cotty/audit.jsonl` (default `~/.local/state/cotty/`),
hash-chained JSON lines in basalt-agent's format: session start and end,
attaches with role, admission and assurance, agent input (masked) and
lines, confirmations, secret prompt start and end (program only, a
keystroke count only with `--count-secret-keys`), masking hits by name,
private mode, keyboard hold, sharing, agents refused by
`--require-confined`.

`mask.probe`: a masked value tells whoever prints text that it is on the
list, so an agent could guess a weak secret by printing candidates and
reading which ones come back masked. Hits for the same name at five or
more different lines within a minute are recorded as `mask.probe`
(outcome `suspected`, with the name and count, never the text). A value
that simply stays on screen hits one line, however often it is read.

## Tests

Unit tests run anywhere (`go test ./internal/...`). Everything that starts
sessions runs in a VM (`tests/lab/vm-broker.sh test`, Fedora 44 cloud
image, or Ubuntu 26.04 with `DISTRO=ubuntu2604`, qemu as the user): a scripted person types through a PTY into
`cotty new` and `cotty attach`, a test agent reads the socket, and the
tests check detection of sudo, `read -s`, python getpass, `openssl passwd`
(two prompts), su, passwd, ssh and zsh `read -s`; no detection for bash
readline, zsh line editing (emacs and vi modes), vim, less and htop;
sudo with pwfeedback (detected, asterisks hidden from the agent), a wrong
sudo password and its retry, and no secret input while sudo runs `vim`,
`-i`, `-s` or `less`; that no typed secret reaches what the agent
received, the audit log or the broker logs (with a control test showing
the check finds visible text); raw passthrough; arbitration, private mode,
the confirm policy and person admission.
