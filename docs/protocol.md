# cotty broker protocol, version 1

Status: stable contract for WP-D (MCP server) and the attach client. The Go
types live in `internal/proto`; this page is the reference. Additive
changes (new ops, new optional fields, new events, new error codes) keep
version 1. Anything that changes the meaning of an existing field bumps the
version.

## 1. Transport

One Unix stream socket per session:

```
$XDG_RUNTIME_DIR/cotty/<session>.sock
```

The directory is created with mode 0700 and must be owned by the user; the
broker refuses to start otherwise. Without `XDG_RUNTIME_DIR` the directory
is `/tmp/cotty-<uid>/` with the same checks. Next to each socket the broker
keeps `<session>.json` (mode 0600: broker pid, session pts path, creation
time) and `<session>.log` (broker diagnostics, never terminal content).

The agent endpoint is a second socket per session, in its own directory:

```
$XDG_RUNTIME_DIR/cotty/agent/<session>.sock
```

The broker serves it only while the session is shared with agents (`--ai`,
`cotty share`, `^] s`) and removes it when the session is hidden or ends.
A connection there may only take the `agent` and `info` roles, whatever
the kernel says about the peer: `person` and `control` get `role_denied`,
and a peer that would pass as a person counts as an unconfined (`weak`)
agent. The directory (mode 0700) holds nothing else, so listing it is
listing the sessions shared with agents. `cotty agent` binds this
directory, read-only, into the agent's confinement (docs/confinement.md);
because the directory and not a socket is bound, sessions shared, started
or restarted after the agent started appear inside too. `cotty mcp` uses
it by default (`--agent-dir`, `$COTTY_AGENT_DIR` inside `cotty agent`).
Each broker serves its own endpoint, so there is no shared daemon to keep
alive, and a broker that ends takes only its own socket away.

Agents may still connect to the main socket when they can reach it (an
agent started without `cotty agent`); confined agents cannot, the main
directory is not in their view.

## 2. Framing

Every message in both directions is a frame:

```
+----------------+--------+---------------------+
| length: uint32 | type:1 | payload: length-1   |
| big endian     | byte   |                     |
+----------------+--------+---------------------+
```

`length` counts the type byte and the payload, and is at most 1 MiB
(1048576). A larger length is a protocol error and the broker closes the
connection.

| type | name | payload                                   |
|------|------|-------------------------------------------|
| `j`  | JSON | one JSON object (UTF-8)                   |
| `d`  | data | raw terminal bytes (person connections)   |

Agent connections only ever send and receive `j` frames. A `d` frame from
an agent connection is a protocol error.

## 3. Messages

Requests, sent by the client:

```json
{"id": 7, "op": "screen", "args": {}}
```

`id` is chosen by the client (a positive integer, unique among its
outstanding requests). `args` may be omitted when empty.

Responses, one per request, matching the id:

```json
{"id": 7, "ok": true, "result": {}}
{"id": 7, "ok": false, "error": {"code": "secret_input_active", "message": "...", "retry_after_ms": 0}}
```

Events, sent by the broker without a request (only after `subscribe`, or
to person connections):

```json
{"event": "state", "data": {}}
```

Responses may arrive out of order relative to other requests (a `wait`
returns later than a `screen` sent after it). Unknown fields must be
ignored by both sides.

## 4. Hello and roles

The first request on a connection must be `hello`; anything else is
answered with `hello_required` and the connection is closed.

```json
{"id": 1, "op": "hello", "args": {
  "v": 1,
  "role": "agent",
  "client": "cotty-mcp/0.1",
  "rows": 40, "cols": 120,
  "auth": "",
  "nonce": "",
  "proof": ""
}}
```

| field           | meaning |
|-----------------|---------|
| `v`             | protocol version the client speaks (1) |
| `role`          | requested role: `agent`, `person`, `control` or `info` |
| `client`        | free text for the audit log |
| `rows`, `cols`  | person only: the size of the client's terminal area |
| `auth`          | person or control: `creator` (the one-time token `cotty new` passes to the broker over an inherited pipe) or `code` (the reattach code shown at detach), or empty (section 7) |
| `nonce`         | with `auth`: 32 random bytes, hex, fresh for every hello |
| `proof`         | with `auth`: the client's proof for the broker's last challenge on this connection (section 7); empty asks for a challenge |

Roles:

- `agent`: reads the masked view and types under arbitration. Any peer of
  the same uid may take it, but only when the session is shared (`--ai` or
  `cotty share`); otherwise `not_shared`. When the session requires
  confined agents (`--require-confined`), a peer whose assurance is `weak`
  or `insecure` gets `confinement_required`.
- `person`: the attach client. Gets the raw, unmasked output stream in `d`
  frames and sends input in `d` frames. Only granted to a peer the broker
  classifies as a person (section 6) and admits (section 7).
- `control`: a person connection without the stream, for one-shot
  commands (`cotty share`, `cotty kill`). Same classification and admission
  as `person`.
- `info`: one `info` request, then the broker closes. Granted to peers
  classified as person, or to any peer when the session is shared.

The broker never trusts the requested role. A peer that asks for `person`
or `control` and is not classified as a person gets `role_denied` (with the
failed checks in `message`); there is no silent downgrade.

Hello result:

```json
{"v": 1, "session": "work", "role": "agent", "assurance": "weak",
 "assurance_reason": "agent not started through cotty agent",
 "broker_pid": 4242, "policy": "auto", "shared": true}
```

Person and control results also carry `admission` (`creator`, `code`,
`code+approval` or `insecure`) and, after `creator`, `code` or
`code+approval`, `server_proof` (section 7). The attach client refuses a
result without a valid `server_proof`; `insecure` passes only when the
client itself was started with `--dev-insecure`.

Protocol versions: the broker answers `version_unsupported` (with the
supported versions in `message`) when `v` is not 1.

## 5. Ops

R = allowed roles (a = agent, p = person, c = control). All ops reply with
a result object; fields not listed may be added later.

### info (a p c, and the info role)

Result: `session`, `created` (RFC 3339), `broker_pid`, `shared`, `policy`,
`persons` (attached count), `agents` (connected count), `rows`, `cols`.

### state (a p)

Result: the state object (section 8).

### screen (a p)

Args: `context` (int, default 0, max 200): committed lines above the first
row to include, for masking context.

Result:

```json
{"rows": ["$ ls", "a b c", "$ "], "wrapped": [false, false, false],
 "cursor": {"row": 2, "col": 2, "visible": true},
 "rows_n": 40, "cols": 120, "alt_screen": false,
 "context": [], "cursor_since": 1532, "state": {}}
```

Rows are rendered text after masking (section 9). `wrapped[i]` is true when
row i continues on row i+1 (see docs/vt.md for how wrap is derived).
`cursor_since` is the `since` cursor at the moment of the snapshot. While
private mode is on, the result is the frozen snapshot taken when it
started, with `state.private` true.

### since (a p)

Args: `cursor` (int, default 0), `limit` (int, default 500, max 5000).

Result:

```json
{"lines": ["output line", "[private]"], "wrapped": [false, false],
 "cursor": 1534, "first": 1532, "truncated": false}
```

Committed lines are the lines that scrolled off the top of the main
screen. Cursors are absolute line numbers starting at 0 for the session.
`cursor` in the result is the value to pass next time. `truncated` is true
when lines older than the requested cursor were already dropped from the
broker's buffer (20000 lines). Lines committed during private mode read
`[private]`. While private mode is on, the cursor does not advance.
When a masked value lies in a group of soft-wrapped lines, that group comes
back as one line (the replacement changes the length, so the old wrap
points no longer apply): `lines` may then hold fewer entries than the
cursor advanced by.

### type (a)

Args: `text` (string, at most 4096 bytes), `enter` (bool).

Types the text into the session. A `\r` or `\n` inside `text` counts as
Enter. Result: `{"sent": 12, "held_enter": false}`; `held_enter` is true
when the confirm policy held the Enter (section 10).

### keys (a)

Args: `keys` (list of names, at most 64). Names: `Enter`, `Tab`,
`BTab` (shift tab), `Esc`, `Backspace`, `Delete`, `Insert`, `Home`, `End`,
`PgUp`, `PgDn`, `Up`, `Down`, `Left`, `Right`, `F1` to `F12`, `Space`,
`C-a` to `C-z`, `C-@`, `C-[`, `C-\`, `C-]`, `C-^`, `C-_`, `M-<char>` (Esc
prefix). Cursor keys follow the session's application cursor mode.

Result: `{"sent": 3, "held_enter": false}`.

### wait (a p)

Args:

| field        | meaning |
|--------------|---------|
| `for`        | `idle`, `prompt`, `regex`, `change`, `secret_ended`, `confirmation` |
| `timeout_ms` | default 10000, max 300000 |
| `idle_ms`    | for `idle` and the `prompt` fallback, default 500 |
| `pattern`    | for `regex`: RE2 syntax, matched on the masked screen rows and on lines committed after the wait started |

`prompt` returns at the next OSC 133 `A` or `D` mark after the wait
started; without shell integration it falls back to `idle`. `confirmation`
returns when no confirmation is pending; its `match` is `accepted` or
`denied`, the person's answer to the last held line.

Result: `{"matched": true, "reason": "idle", "match": "", "state": {}}`.
On timeout: `matched` false and `reason` `timeout` (not an error).

### subscribe (a p)

Args: `events` (list): `state` (the state object when what the agent may
see of it changed, debounced to 30 ms), `output` (`{"cursor_since": N}`
when the output the agent may see changed, never content). Neither moves
while private mode is on or while secret input is active: an agent gets
one change when secret input starts and one when it ends, never one per
keystroke. Result: `{}`.

### request_keyboard (a)

Asks the person for the keyboard; the status line shows it until the
person gives the keyboard or the agent types. Result: `{}`.

### mask (a p)

Args: `name`. Asks the broker to mask the secret with that name from the
configured secret sources (PLAN 5.5). The value is never returned. Result:
`{"masked": true}` or error `unknown_secret` / `unsupported`.

### Person and control ops

| op           | R   | args                 | effect |
|--------------|-----|----------------------|--------|
| `resize`     | p   | `rows`, `cols`       | resizes the PTY and the screen model |
| `keyboard`   | p   | `hold` (bool)        | take (`true`) or give the keyboard |
| `private`    | p   | `on` (bool)          | private mode on or off |
| `confirm`    | p   | `accept` (bool)      | answer the pending agent line |
| `approve`    | p   | `request` (int), `accept` (bool) | answer a pending person attach |
| `share`      | p c | `on` (bool), `require_confined` (bool, optional) | make the session visible to agents or hide it; `require_confined` refuses agents with assurance `weak` (and closes those connected) or accepts them again; result `{"shared", "require_confined"}` |
| `code`       | p c |                      | result `{"code": "..."}`: the current reattach code; on a control connection only when it was admitted with the creator token (`cotty new -d`), so a control connection admitted with the code (`cotty share`, `cotty kill`) cannot read the next code (`role_denied`) |
| `detach`     | p   |                      | result `{"code": "..."}`, then the broker closes |
| `kill`       | p c |                      | ends the session (SIGHUP to the shell) |

## 6. Peer classification (summary)

From the kernel, never from the client. Person requires: SO_PEERCRED uid
equal to the broker's; same user and pid namespaces as the broker; not in
an agent cgroup (a path element starting with `cotty-agent`); no guard tag;
not a descendant of the session shell and not in its kernel session; a
controlling terminal that is not a cotty session pts; `/proc/PID/exe` equal
to the broker's own executable, which must be root-owned and not writable
by the user (otherwise the person assurance is `weak`); on SELinux,
SO_PEERSEC not an agent domain. Everything else is an agent. See
`internal/peer` for the exact code.

Assurance, reported in hello and state: `strong` (guard loaded and the
agent tagged), `confined` (agent peer in its own namespaces or agent
cgroup), `weak` (no confinement evidence, or the cotty binary is writable
by the user), `insecure` (broker started with `--dev-insecure`; every
same-uid peer counts as a person; development only).

## 7. Admission of person and control connections

Every admission proves a secret, so that the client can check, through
the broker's proof, that it reached the session's broker (an approval by
itself proves nothing to the client: a forged listener could claim one).

1. `auth: "creator"`: `cotty new` creates the token, hands it to the
   broker over an inherited pipe and proves it once (below). A wrong
   proof does not void it; the right one does.
2. Otherwise the client must prove the reattach code, which the attach
   client prints at detach (and shows with the `c` hotkey). A hello
   without `auth`, or with `auth: "code"` and no proof, gets
   `code_required` with a challenge; wrong: `code_invalid`; three wrong
   codes from one controlling terminal and kernel session lock admission
   from that terminal and session for 30 s (`rate_limited`); other
   terminals, the person's included, are not affected. A person
   admission spends the code at once (a second proof of the same code
   fails) and the broker makes a new one, whether the approval below is
   then given, denied or never answered: the requester knew the code. A
   control connection (`cotty share`, `cotty kill`) leaves it as it is.
3. A person connection with the right code while a person is attached
   then waits (up to 60 s) for an attached person to approve it with the
   hotkey, a second gate (`admission: "code+approval"`); the attached
   clients get an `attach_request` event with the requester's pid,
   executable, terminal and parent chain (`chain`, "pid name" from the
   parent up); the attach client shows the first two parent names. Denied or timed out:
   `approval_denied` (a requester that closes its connection frees the
   slot at once). One request waits at a time; another gets
   `approval_unavailable`, and so does a new request from a controlling
   terminal and kernel session whose request was denied in the last 30 s.
   Since the code comes first, a request nobody answers cannot lock the
   person out: only a holder of the code can raise one. Clients act on the
   request with the lowest `id`; the order of `pending_attach` is not
   meaningful.
4. A broker started with `--dev-insecure` admits a hello without `auth`
   as `insecure` (development only; refused while the guard is loaded).

Proofs. The secret never crosses the socket. `code_required` and
`code_invalid` carry a `challenge`:

```json
{"code": "code_required", "challenge": {"kind": "code", "nonce": "<64 hex>",
 "salt": "<32 hex>", "iterations": 600000}}
```

The client answers on the same connection with a new hello that has
`auth` set to the challenge's kind, a fresh `nonce` and
`proof = hex(HMAC-SHA256(K, "client" || 0x00 || T))`, where

- K is `PBKDF2-SHA256(normalized code, salt, iterations, 32)` for `code`
  (normalized: upper case, no dashes or spaces, O read as 0, I and L as
  1), and `SHA-256("cotty-creator-token" || 0x00 || token)` for `creator`;
- T is `"cotty-admission-v1", kind, role, session name, client nonce,
  challenge nonce, client pid, broker pid` joined with 0x00, each pid as
  the side computing T sees it: the client takes its own pid and the
  listener's pid from SO_PEERCRED; the broker takes the peer's pid from
  SO_PEERCRED and its own.

On success the result carries `server_proof = hex(HMAC-SHA256(K,
"server" || 0x00 || T))`, and the client refuses the connection unless it
matches. A listener that is not the broker cannot produce it and never
sees the code; a relay between the client and the broker fails because
each end sees the relay's pid where the other put its own. A connection
gets up to five hello requests; a challenge is good for one proof.

Before any of this the attach client checks the listener (internal/attach
`Connect`): the runtime directory is the user's with mode 0700 and the
socket the user's with mode 0600; SO_PEERCRED's uid is the user's and its
pid is the broker `cotty new` started or the one the session metadata
names, with the same start time; the process is not dumpable, has the
cotty binary's name and runs `__broker`. These are consistency checks (a
process of the user can forge them). With the guard loaded the client
asks it (`verify-broker`, as root) whether the listener is the registered
broker of this session name and runs the installed cotty binary; when
the guard is installed and enforcing but its daemon does not answer, the
client refuses to attach rather than skip that check. What holds without
the guard is the proof: a forged listener that admits the client without
proving the secret (as if an attached person had approved, or as an
insecure broker) is refused before a keystroke is sent.

## 8. State object

```json
{
  "session": "work",
  "keyboard": "free",
  "person_typing": false,
  "agent_may_type": true,
  "secret_input": "none",
  "secret_program": null,
  "foreground": {"pid": 1234, "name": "bash", "exe": "/usr/bin/bash", "trust": "system", "agent_started": false},
  "private": false,
  "policy": "auto",
  "pending_confirmation": null,
  "shell": {"integration": false, "at_prompt": false, "last_command": "", "exit_code": null},
  "alt_screen": false,
  "rows": 40, "cols": 120,
  "persons": 1, "agents": 1,
  "shared": true,
  "assurance": "weak",
  "agent_requests_keyboard": false,
  "cursor_since": 1534,
  "require_confined": false
}
```

- `keyboard`: `held` (the person holds it) or `free`.
- `secret_input`: `active` or `none`. `secret_program` while active:
  `{"pid", "name", "exe", "trust": "system"|"other", "agent_started"}`.
  `trust` system means a root-owned binary in a system directory not
  writable by the user (the green lock); other is the amber lock. Every
  member of the foreground process group is judged: the lock is green
  only when all are trusted and none is an interpreter, and with several
  members `name` lists them (`"sleep | python3"`) and `pipeline` holds the
  names. `name` is the base name of the executable the trust was judged
  on, followed by `(as COMM)` when the process was started under another
  name (`"head (as sudo)"`); a setuid-root process, whose executable the
  user cannot read, is named by its comm. `agent_started` marks every job that took the terminal after an
  agent's Enter until the shell was back at its line editor, drew a
  prompt (OSC 133 A) or the person typed Enter at the prompt.
  `exception` (only when true) marks a program outside the session that
  opened its pts through cotty-guard's pts exception list (a
  pinentry-curses started by gpg-agent); it is judged like a foreground
  member. `outside` (only when true) marks a program the broker found
  outside the session holding its pts while a job read with echo off
  (no guard answer); its trust is always `other`. `parent` names the
  parent of either (`gpg-agent`): the process that receives what it
  reads.
- `pending_confirmation`: `{"line": "...", "typed": "...", "mismatch":
  false}` (masked) or null. `line` is the screen line at the cursor when
  the Enter was held, from the live screen, with rows that hold private
  mode text read as `[private]` like in `screen`; `typed` what the agent
  sent; `mismatch` is true when the line does not end with the typed
  text.
- `shell`: from OSC 133 marks; hints only, a program can print them.
  `last_command` is masked. While private mode is on agents get the
  state of the moment it began (shell, foreground, cursor, alt screen),
  with only `keyboard`, `persons`, `agents`, `shared`, `assurance`,
  `require_confined`, `agent_requests_keyboard`, `agent_may_type` and
  `pending_confirmation` live. No command line or exit code is recorded
  during private mode, and the last command recorded before it is
  cleared. While secret input is active `person_typing` keeps the value it
  had when the prompt started.

- `require_confined`: agent connections with assurance `weak` are refused
  (`--require-confined`).

Person connections also get a `status` event with the same object plus
`pending_attach` (list of requests), `agent_text` (the last agent input,
masked, for the status line), `weak_agents` (connected agents with
assurance `weak`) and `refused_agents` (agent connections refused by
`--require-confined` since the session started).

## 9. Masking and private mode in reads

All text an agent receives (screen rows, committed lines, last command,
pending line) goes through the masking engine after the vt model.
The engine sees soft-wrapped rows joined without a separator and hard line
ends as "\n", so a value that wraps is one run of text. A `screen` read is
masked with the end of the scrollback above it as context (a value
scrolled half out of view); a `since` read with the committed lines before
the cursor and the current screen after it (a value split by the edges of
the read is masked on both sides). Before answering `screen` and `since`
for an agent the broker waits until the program has printed nothing for
80 ms (at most 400 ms), so a value still being printed is not read in
part. Partial values are never masked as fragments (that would make the
masker an oracle for guessing them).
Rows written while private mode was on read `[private]` until every
column of them was rewritten or erased after it ends, wherever they move
(scrolling, insert and delete line, reverse index, scroll regions, insert
character, resize); a line that leaves the screen during private mode, or
while it still holds such text, reads `[private]` for good. Rows are
never matched by text (docs/vt.md). The masking context is at least 200
committed lines on each side, and more when the longest encoded value on
the masking list does not fit in those.

## 10. Arbitration errors

Agent `type` and `keys` are refused, with these codes, in this order:

| code                   | when |
|------------------------|------|
| `private_mode`         | private mode is on |
| `secret_input_active`  | a secret prompt is active |
| `keyboard_held`        | the person holds the keyboard |
| `person_typing`        | the person typed in the last 1.5 s; `retry_after_ms` set |
| `confirmation_pending` | an agent line waits for the person's answer |
| `policy_denied`        | under the confirm policy: control characters other than Enter, Tab, Backspace and C-c, or escape sequences in `text` |

Under the confirm policy the text before an Enter is typed, the Enter is
held and the person sees "agent wants to run: LINE" (or, when the line
does not end with what the agent typed, both texts and advice to deny).
Accept sends the Enter, unless the line on screen changed since it was
shown: then accept fails with `confirmation_stale` and only reject is
possible. Reject drops the Enter and leaves the typed text in place.

## 11. Error codes

`hello_required`, `version_unsupported`, `role_denied`, `not_shared`,
`code_required`, `code_invalid`, `rate_limited`, `approval_denied`,
`approval_unavailable` (reserved, no longer sent), `bad_request`,
`unknown_op`, `forbidden` (op not
allowed for the role), `private_mode`, `secret_input_active`,
`keyboard_held`, `person_typing`, `confirmation_pending`, `policy_denied`,
`no_pending`, `unknown_secret`, `unsupported`, `session_ended`,
`internal`, `confinement_required`, `confirmation_stale` (accept of a held
line that changed on screen), `too_many_requests` (more than 8 waits at a
time on one connection).
