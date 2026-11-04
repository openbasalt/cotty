# Cursor CLI (`cursor-agent`)

```
cotty agent -- cursor-agent
cotty agent -- cursor-agent -p "task"
```

Visible from `$HOME`:

| Path | Access | Why |
| --- | --- | --- |
| `~/.cursor/` | read-write (created if missing) | CLI state |
| `~/.config/cursor/` | read-write (created if missing) | login (`auth.json`) |
| `~/.cursor/mcp.json`, `cli-config.json`, `hooks.json` | read-only, created as `{}` when missing | MCP servers, command permissions, hooks |
| `~/.cursor/hooks/`, `rules/`, `skills/`, `agents/`, `commands/` | read-only, created empty when missing | hook scripts, rules, skills, subagents, commands |
| `~/.cursor/extensions/`, `~/.cursor/argv.json` | read-only, created empty (`{}` for `argv.json`) when missing | the Cursor IDE's extensions and launch arguments, code and flags the IDE runs with your rights |
| `~/.local/share/cursor-agent` | read-only | the install (versions, bundled node) |
| `~/.local/bin/cursor-agent`, `~/.local/bin/agent` | read-only links | launcher links into the install |

The launcher is a shell script that finds its bundled node next to
itself, which is why the links are recreated as links inside.

Environment: the profile keeps `CURSOR_API_KEY`.

Residual, by design: only the paths in the table are read-only; the rest
of `~/.cursor` stays writable. Permissions approved for good inside are not saved
(`cli-config.json` is read-only); if your Cursor CLI keeps its settings in
`~/.config/cursor/cli-config.json` instead, that file is writable inside.
Login files are readable. Project level (read-write by design, used when
you start Cursor in the project yourself): `.cursor/mcp.json`,
`.cursor/cli.json`, `.cursor/hooks.json`, `.cursor/rules/`, `AGENTS.md`,
`CLAUDE.md`, skills and agents directories.

MCP: add cotty once, outside, to `~/.cursor/mcp.json`:

```
{"mcpServers": {"cotty": {"command": "cotty", "args": ["mcp"]}}}
```

Verified: starts (`--version`). Not verified: a logged-in session.

The same file serves the Cursor IDE (global `~/.cursor/mcp.json`, or
`.cursor/mcp.json` in a project). Cursor asks to approve a new MCP server
before it loads it (in the IDE's MCP settings; `cursor-agent mcp enable
cotty` in the CLI). Verified 2026-11-03 (WP-D, lab VM, Cursor CLI
2026.10.22, no login): `cursor-agent mcp list` shows `cotty: not loaded
(needs approval)` and `cursor-agent mcp list-tools cotty` starts the
server and lists its 8 tools. See [../mcp.md](../mcp.md).
