# Claude Code (`claude`)

```
cotty agent -- claude                 # interactive
cotty agent -- claude -p "task"       # one prompt
```

Visible from `$HOME`:

| Path | Access | Why |
| --- | --- | --- |
| `~/.claude/` | read-write (created if missing) | login (`.credentials.json`), settings file (`.claude.json`, see below), sessions, project history, todos |
| `~/.claude/settings.json`, `settings.local.json` | read-only, created as `{}` when missing | hooks, status line, `apiKeyHelper`, permissions: commands Claude Code runs |
| `~/.claude/CLAUDE.md`, `rules/`, `agents/`, `commands/`, `skills/`, `workflows/`, `output-styles/`, `plugins/`, `hooks/` | read-only, created empty when missing | instructions, subagents and skills (their frontmatter can define hooks and MCP servers), plugins (hooks, MCP servers), the usual place of hook scripts |
| scripts named in `settings.json` (hook commands, status line) | read-only when they lie in `~/.claude` | they run with your rights |
| `~/.claude/local/` | read-only, created empty when missing | the older local npm install (`claude migrate-installer`); its `cli.js` runs when you start `claude` from there |
| `~/.claude/ide/` | empty inside (a tmpfs; created empty outside when missing) | the IDE extensions write `PORT.lock` there with the port and an auth token of their local MCP server, which runs with your rights; a lock planted there would point your next IDE-started `claude` at the agent's server. `cotty agent --show-hidden` keeps it visible when the agent should talk to your IDE |
| `~/.claude.json` | not visible | your settings file outside; it can define MCP servers that run with your rights |
| `~/.local/share/claude` | read-only | the native install (versions) |
| `~/.local/bin/claude` | read-only link | the launcher link into `~/.local/share/claude` |

Inside, Claude Code runs with `CLAUDE_CONFIG_DIR=~/.claude`, so its main
settings file is `~/.claude/.claude.json` instead of `~/.claude.json`. The
reason: Claude Code saves that file by writing a temporary file next to it
and renaming it over the old one (container users who bind-mount the
single file report rename errors), and a rename onto a single bind-mounted
file fails (EBUSY, or EXDEV from the private home). Keeping the file in a
bound directory makes the rename an ordinary one. Before the first
confined run, `cotty agent` copies `~/.claude.json` to
`~/.claude/.claude.json` (profile `seed`), so onboarding, trusted folders
and project state carry over; the copy leaves out MCP server definitions
(their `env` and headers often hold tokens) and every key whose name says
it holds a credential (`primaryApiKey` and similar). After that the two
files evolve separately.
A side effect we want: your `~/.claude.json`, whose user MCP servers run
with your rights when you start `claude` yourself, is not visible to the
confined agent, so it cannot plant one there. The login itself
(`~/.claude/.credentials.json`) is shared by both. Verified with a fake
writer that saves the way Claude Code does (`tests/attacks/claude-config.sh`):
a single bound file cannot be replaced, the claude profile's file can, the
result persists outside, and `~/.claude.json` stays untouched.

`DISABLE_AUTOUPDATER=1`: the program directory is read-only inside;
update outside with `claude update`.

Environment: the profile keeps `ANTHROPIC_*`, `CLAUDE_CODE_*` and Claude
Code's timeout and telemetry switches. Bedrock or Vertex need cloud
credentials, which are not kept: copy the profile and add them with
`[scrub] keep` if you accept that.

Only the paths in the table above are read-only. What stays writable in
`~/.claude` and is used later by the Claude Code you start yourself
(residual, by design):

- `projects/*/memory/` (auto memory, loaded into every session) and
  `agent-memory/`: a confined agent can write instructions there;
- `shell-snapshots/`: shell state files Claude Code sources before Bash
  tool calls; a confined agent running at the same time as your own
  unconfined Claude Code could change one between its creation and use;
- `.claude.json` inside (`~/.claude/.claude.json`) is only read by
  confined runs, unless you set `CLAUDE_CONFIG_DIR=~/.claude` yourself;
- readable by design: `.credentials.json` (OAuth access and refresh
  tokens), transcripts in `projects/`, `history.jsonl`, `file-history/`.

Project level (read-write by design, runs when you start `claude` in the
project yourself): `.claude/settings.json`, `.claude/settings.local.json`
(allow rules apply without a prompt while the file is untracked),
`.mcp.json`, `CLAUDE.md`, `CLAUDE.local.md`, `.claude/` agents, commands,
skills and rules.

MCP: `cotty agent` appends
`--mcp-config '{"mcpServers":{"cotty":{"command":"$XDG_RUNTIME_DIR/cotty/bin/cotty","args":["mcp"]}}}'`
to a session (interactive or `-p`), never to subcommands such as
`claude mcp list`. Your other MCP servers in `~/.claude.json` still load;
those that are programs in `$HOME` or sockets need their paths given with
`--ro` or a profile copy.

Notes:

- Claude Code's own sandbox (bubblewrap) cannot start inside: nested
  namespaces are denied. cotty is the sandbox.
- An npm install (`npm i -g @anthropic-ai/claude-code`) under `$HOME`
  needs `--ro` for the npm prefix (or nvm directory). The local install
  in `~/.claude/local` is visible read-only through the profile; when you
  do not use it, cotty leaves an empty `~/.claude/local` directory there.
- Verified: starts, reads its directory, reaches the login check (the lab
  VM has no Claude login), the `--mcp-config` command line is built, and
  the settings file layout above with a fake writer. Not verified: a
  logged-in interactive session (no login in the lab).

MCP entry, for a Claude Code started without `cotty agent` (assurance
`weak`, see [../mcp.md](../mcp.md)) or for a fixed setup:

```
claude mcp add --scope user cotty -- cotty mcp
```

or, for one project, `.mcp.json` in its root (Claude Code asks once
before using a project server):

```
{"mcpServers": {"cotty": {"type": "stdio", "command": "cotty", "args": ["mcp"]}}}
```

`term_wait` and `term_run` may run up to 300 s; if a call is cut short,
raise `MCP_TOOL_TIMEOUT` (milliseconds). Verified 2026-11-03 (WP-D, lab
VM, Claude Code 2.1.317): after `claude mcp add`, `claude mcp list` shows
`cotty: cotty mcp - Connected`. A logged-in `claude -p` run is
`tests/e2e/real-claude.sh`.
