# cotty mcp: the agent's side of a shared terminal

`cotty mcp` is a stdio MCP server (JSON-RPC 2.0, MCP protocol versions
2024-11-05 to 2025-11-25). An agent CLI starts it as one of its MCP
servers; it connects to the session brokers always with the `agent` role
(docs/protocol.md), so it can only hand the model what the broker gives an
agent: the masked screen, the session state and typed errors. It has no
dependencies besides cotty itself.

```
cotty mcp [--session NAME] [--agent-dir DIR | --socket PATH] [--log FILE]
```

- `--session`: the default session for tools called without `session`.
  Without it, a call uses the only shared session, or fails with
  `ambiguous_session` when there are several.
- `--agent-dir`: the agent endpoint directory, one socket per session
  shared with agents (docs/protocol.md section 1). Default:
  `$COTTY_AGENT_DIR` (set by `cotty agent`), else
  `$XDG_RUNTIME_DIR/cotty/agent`. Sessions shared later appear without a
  restart; a name without a socket there is `not_shared`.
- `--socket`: use only this one socket (default: `$COTTY_AGENT_SOCKET`
  when set); for tests and special setups.
- `--log`: append one line per tool call to FILE (mode 0600): tool,
  session, duration, outcome, result size. Never terminal content and
  never typed text, so the log cannot leak what the masking hides.
  Default: stderr, which the agent CLI usually keeps in its MCP log.

Only sessions the person shared (`cotty new --ai`, `cotty share NAME` or
`^] s`) are listed or usable; asking for another one by name gets
`not_shared` from the broker.

## Tools

| Tool | What it does |
| --- | --- |
| `term_sessions` | lists the sessions shared with agents: name, size, policy, people and agents attached |
| `term_read` | the masked screen (`mode=screen`, with optional `context` lines above it) or the lines that scrolled off since a cursor (`mode=since`), always with the state |
| `term_run` | types a command and Enter, waits until the shell is back, returns the masked output, the exit code when the shell reports it, and a status |
| `term_type` | types text, optionally with Enter |
| `term_keys` | presses named keys (`C-c`, `Up`, `Esc`, `F1`, `M-x`, ...) |
| `term_wait` | waits for `idle`, `prompt`, `regex`, `change`, `secret_ended` or `confirmation`, with a timeout (default 30 s, max 300 s) |
| `term_mask` | asks the broker to mask a secret by its name; the value never comes back |
| `term_request_keyboard` | asks the person for the keyboard when they hold it |

Every tool takes an optional `session`. The descriptions the model reads
are in `internal/mcp/tools.go`; they tell it that secret prompts are typed
by the person only, when its input is refused and what to do then.

### State

`term_read`, `term_wait`, `term_run` and the arbitration errors include
the state, one fact per line:

```
state:
  keyboard: free
  you may type: no
  secret prompt: ACTIVE, sudo (/usr/bin/sudo), green lock (a trusted system program); only the person types it; call term_wait with for=secret_ended
  private mode: off
  policy: auto
  foreground program: sudo (pid 2817)
  shell integration: none (exit codes are not reported; run `echo $?` when you need one)
  size: 110x29, people attached: 1, agents: 1
```

With shell integration (OSC 133 marks) the shell line shows whether the
shell is at its prompt, the last command and its exit code. These marks
are hints: any program can print them.

### term_run

`term_run` types the command with Enter and then waits until the shell is
back: no output for `idle_ms` (default 500), the foreground process group
is again the one that was in front when the command was typed, and, with
shell integration, the shell is at its prompt. Statuses:

| status | meaning and what the model is told to do |
| --- | --- |
| `done` | finished; output and exit code (when reported) |
| `secret_prompt` | a password or other secret prompt is waiting; only the person types it: tell them what it is for, call `term_wait` with `for=secret_ended`, then `term_wait for=prompt` or `term_read` |
| `confirmation_pending` | the confirm policy holds the line for the person's approval: `term_wait for=confirmation` |
| `rejected` | the person rejected the line; it is still typed at the prompt |
| `running` | the timeout passed while the command runs or waits for input; read the screen and decide |
| `interactive` | a full-screen program took over (`less`, `vim`, `htop`); drive it with `term_read` and `term_keys` |
| `private_mode` | the person turned private mode on during the run |

The output is the lines committed since the command was typed followed by
the screen, from the row after the command line, without the final prompt
(at most `max_lines`, default 200). If the screen was cleared or resized
meanwhile, the whole text since the command is returned and says so.

Without shell integration a silent program that waits for input (a
`[y/N]` question) looks like a running command: `term_run` returns
`running` at the timeout with the question on screen. Use a short
`timeout_s` for commands that may ask something. A shell builtin that
waits for input (`read x`) leaves the shell in front, so without shell
integration `term_run` reports `done` only when the cursor sits at what
looks like a fresh prompt: off the command line, nothing after the
cursor, and the text before it equal to the prompt seen before the
command or ending in `$ # % > ❯ ➜ » λ`. Anything else (an empty line, a
`Name: ` question) returns `running` at once, with a note that the
command may be waiting for input. The rule is conservative: a prompt
with text right of the cursor (zsh `RPROMPT`) or an unusual last
character reads as `running` too; shell integration avoids that.

Tool calls that type into one session (`term_run`, `term_type`,
`term_keys`) take turns: each holds the session's input lock for its
whole duration (`term_run` until it returns), so parallel calls do not
mix their keystrokes or their output. Reads and waits do not take it.

### term_wait

`idle`, `prompt` and `regex` also end, with `reason: secret_prompt`, when
a secret prompt is active or appears while waiting (the broker's own wait
would sit on it). A timeout is `matched: false, reason: timeout`, not an
error. The result ends with the bottom 20 rows of the screen.

### Masking in what the agent reads

- A value on the list, or a token a rule knows, reads `[masked:NAME]`
  wherever it is, with the same width whatever the value's length: on
  the screen the replacement goes on the first row the value touches and
  the rest of the value is removed from the rows it continues into, so
  the text after it moves. The reported cursor column moves with the
  text (inside a masked span it is reported at the span's start), so it
  does not tell the length either. What still shows: a value that wraps
  over several rows leaves those rows, so its length in whole screen
  widths shows.
- `mode=since` returns exactly one line per committed line (a masked
  value spanning lines leaves the following lines empty), so cursors and
  `term_run` output stay aligned.
- The masker sees 200 committed lines before every read and, for
  `since`, the 200 after it followed by the screen, all taken at one
  instant, and more lines when the longest encoded value on the list does
  not fit in 200 (a long value printed by `base64` on 76 column lines): a
  value cut by the edge of a read, or a private key whose BEGIN line is
  up to 200 lines above, is masked.
- Rows written during private mode read `[private]` after it ends until
  every column of the row was rewritten or erased, wherever the row
  moves (scrolling, insert or delete line, scroll regions, a resize), and
  also after a `\r` overwrite or a program that switched to the
  alternate screen in the same output; once scrolled into the scrollback
  they read `[private]` for good. Rows are never matched by text, so an
  agent cannot learn whether a row it prints equals a private one. The
  cursor column on such a row reads 0. `pending_confirmation.line` hides
  such rows the same way. The shell prompt drawn while private mode was
  on is such a row too: a command typed on it right after private mode
  ends reads `[private]` until the line scrolls away (clear the screen,
  or press Enter once, to start on a fresh row).
- While a secret prompt is active the screen agents read is frozen at
  the moment it began, and what the prompt prints per key (sudo-rs's
  asterisks) reads `[private]` afterwards.
- Private mode hides rows, not what programs keep: after it ends, shell
  history, a redraw or a pager can print the text again as ordinary
  output (docs/broker.md, Private mode; docs/security.md, Known limits).
  Under the confirm policy agents cannot press Up, Down or Tab, nor type
  history expansion.
- Before a read the broker waits for the output to pause (80 ms quiet,
  at most 400 ms) so a value is not caught half printed. This is best
  effort: a value that arrives in pieces more than 80 ms apart can show
  its head in a read taken between the pieces, since fragments are not
  masked (docs/security.md).
- If masking fails (the masker does not return one row per row) the read
  is refused with `internal`, never served unmasked.
- `term_mask` answers `unknown_secret` for a name not in the list and a
  generic `unsupported` error for anything else (source failed, value
  not maskable), which says nothing about the value. A source that fails
  is not run again for 10 s, doubling up to 10 min, so a locked keyring
  is not prompted on every call. A name already masked is read again at
  most every 5 minutes; a rotated value is masked next to the old one
  (up to 4 values per name).

### Errors

Errors are tool results with `isError: true` and this text:

```
error: secret_input_active
message: a secret prompt is active; wait for secret_ended
what to do: A password or other secret prompt is active. Only the person types secrets; you cannot and must not. Tell the person what the prompt is for, then call term_wait with for=secret_ended.
state:
  ...
```

Codes: the broker's (docs/protocol.md section 11: `private_mode`,
`secret_input_active`, `keyboard_held`, `person_typing` with
`retry_after_ms`, `confirmation_pending`, `policy_denied`, `not_shared`,
`unknown_secret`, `unsupported`, `session_ended`, `bad_request`, ...) and
the server's own: `no_session`, `ambiguous_session`, `unknown_session`,
`broker_unreachable`, `bad_arguments`, `unknown_tool`, `cancelled`.
`term_type`, `term_keys` and `term_run` wait and retry once when the person
typed less than 2 s ago.

## Configuring an agent CLI

Under `cotty agent` (docs/confinement.md) Claude Code, Codex and opencode
get `cotty mcp` automatically; Gemini CLI and
Cursor need a one-time entry. Without `cotty agent` the agent runs
unconfined and the session's assurance is `weak`: the same entries work,
but nothing stops that agent from reaching cotty's sockets as something
other than `cotty mcp`. Each page in docs/agents/ has the entry for its
CLI:

| CLI | Entry | Page |
| --- | --- | --- |
| Claude Code | `claude mcp add --scope user cotty -- cotty mcp`, or `.mcp.json` | [agents/claude.md](agents/claude.md) |
| Codex CLI | `[mcp_servers.cotty]` in `~/.codex/config.toml` | [agents/codex.md](agents/codex.md) |
| Gemini CLI | `mcpServers.cotty` in `~/.gemini/settings.json` | [agents/gemini.md](agents/gemini.md) |
| Cursor (CLI and IDE) | `mcpServers.cotty` in `~/.cursor/mcp.json` or `.cursor/mcp.json` | [agents/cursor-agent.md](agents/cursor-agent.md) |
| opencode | `mcp.cotty` in `opencode.json` | [agents/opencode.md](agents/opencode.md) |
| Aider | none: Aider has no MCP client | [agents/aider.md](agents/aider.md) |

Long waits: `term_wait` and `term_run` may take up to 300 s. Codex stops a
tool after 60 s unless `tool_timeout_sec` is raised (the Codex page sets
it); Claude Code reads `MCP_TOOL_TIMEOUT` (milliseconds) when its default
is too short.

## Tests

- `go test ./internal/mcp`: unit tests against an in-process fake broker
  (no PTY, no shell; safe on any host).
- `tests/e2e/vm.sh test` (on a lab host): builds on the host, installs
  cotty root-owned in a Fedora 44 VM (`cotty-d-fedora44`, made by
  tests/lab/vm-broker.sh) and runs `tests/e2e` there. A Go MCP client
  plays the agent against the real `cotty mcp`; a scripted person types
  into `cotty new` through a PTY. Cases: commands and output, a real
  `sudo -v` (the agent gets `secret_prompt`, is refused by `term_type`,
  `term_keys` and `term_run`, waits for `secret_ended` while the person
  types the password, then reads `sudo-rc=0`), private mode, the confirm
  policy (approve, reject, pending line), person typing and keyboard hold,
  an unshared session, and `term_run` statuses with and without shell
  integration. Each leak check searches every MCP response, the MCP log,
  the audit log and the broker logs for the password and private text,
  and fails if those are empty. The masking-list case (WP-E) puts two
  values in a secrets.conf and checks that the agent reads
  `[masked:NAME]` and never the value, printed plainly, split by colour
  escape sequences, wrapped across rows, on screen, in the scrollback and
  through `term_run`, and for a second value added after the session
  started once the agent calls `term_mask`.
- `tests/e2e/vm.sh real-claude`: a real Claude Code drives the session.
  See below.

### Real agent run (Claude Code)

`tests/e2e/real-claude.sh` runs inside the VM as the test user: it
installs Claude Code with the native installer when missing, then runs
`TestRealClaude`, which starts a shared session, gives `claude -p` an MCP
config for `cotty mcp` (`--strict-mcp-config`, only `mcp__cotty` allowed,
`Bash` disallowed) and a prompt that makes it run
`sudo -k; sudo -v && echo SUDO-OK-$((40+2))` in the terminal and then
`cat` a file that holds a value on the masking list (a secrets.conf made
for the test). The scripted person types the password whenever the lock
shows sudo. It checks that the agent used the cotty tools, read
`SUDO-OK-42` and read the listed value as `[masked:E2E_TOKEN]`, and that
neither the password nor the listed value is in the stream-json
transcript, Claude Code's session files, its stderr, the MCP log, the
audit log or the broker logs. Each place is searched raw, in every string
decoded from its JSON (so JSON escapes cannot hide a value), and for the
base64, hex and URL encodings of each value. The password is typed with
echo off and never reaches the screen, so the listed value, which does,
is the case that tests masking on a real agent. By default Claude Code
runs unconfined; with `CONFINED=1` it runs under `cotty agent` (the MCP
config and log then live in the project directory), and a second short
run has it execute a fixed script with its Bash tool that tries `cotty
ls`, `cotty attach` on the session, and reading and writing the person's
and every visible `/dev/pts` terminal; the script's own output must show
each attempt failing. `MODEL=haiku` passes `--model` to keep the runs
cheap. Results are kept in `~/cotty-e2e-results/<time>/` in the VM.

Verified 2026-11-04 (Claude Code 2.1.318, haiku, r3-fixes): Fedora 44
(6.19) confined, Fedora 44 confined with the guard running (assurance
`strong`), and Ubuntu 26.04 (7.0, sudo-rs) confined: all checks pass.

The login is a Claude Code OAuth token (`claude setup-token`) in a file
inside the VM, mode 0600, named by `CLAUDE_TOKEN_FILE` (default
`~/.claude-token`). The token goes to the test process and the claude
child only, never to the session's shell or to cotty. To run it, on the
lab host in the checkout:

```
tests/e2e/vm.sh up
tests/e2e/vm.sh ssh 'umask 077; cat > ~/.claude-token' < /path/to/token-file
CONFINED=1 MODEL=haiku tests/e2e/vm.sh real-claude
tests/e2e/vm.sh ssh 'rm -f ~/.claude-token'
tests/e2e/vm.sh stop
```
