# opencode (`opencode`)

```
cotty agent -- opencode
cotty agent -- opencode run "task"
```

Visible from `$HOME`:

| Path | Access | Why |
| --- | --- | --- |
| `~/.config/opencode/` | read-write (created if missing) | settings directory |
| `~/.local/share/opencode/` | read-write (created if missing) | login (`auth.json`), sessions (`opencode.db`), snapshots |
| `~/.local/state/opencode/` | read-write (created if missing) | state |
| `~/.cache/opencode/` | private, empty each run | plugin and provider packages opencode installs there are code it loads, so the cache is not shared with your own opencode |
| `~/.config/opencode/opencode.json`, `opencode.jsonc`, `config.json` | read-only, created as `{}` when missing | MCP servers, formatters, plugins, shell, permissions |
| `~/.config/opencode/` `AGENTS.md`, `plugin(s)/`, `tool(s)/`, `agent(s)/`, `mode(s)/`, `command(s)/`, `skills/` | read-only, created empty when missing | code opencode loads at start, custom tools, agents and commands (which run shell) |
| `~/.local/share/opencode/bin/` | read-only, created empty when missing | language servers opencode downloads and runs |
| `~/.opencode` | read-only | the install script's location |

Installed with npm (`opencode-ai`) under `$HOME`: add `--ro` for the npm
prefix. Environment: the profile keeps `OPENCODE_*` and the API key
variables of the usual providers (Anthropic, OpenAI, OpenRouter, Google,
Groq, DeepSeek, xAI, Mistral).

Residual, by design: opencode downloads its provider packages again each
run (the cache is private) and cannot install language servers inside;
packages opencode installs into `~/.config/opencode/node_modules` for your
own plugins (from a `package.json` there) are writable inside, and a
plugin of yours that imports them loads what the agent wrote: add
`protect = .config/opencode/node_modules/` to a copy of the profile if
you use such plugins (opencode then cannot install them inside);
`auth.json` and the session database are readable. Project level
(read-write by design, used when you start `opencode` in the project
yourself): `opencode.json(c)`, `.opencode/` (plugins, tools, agents,
commands), `AGENTS.md`.

MCP: with a cotty broker running, `cotty agent` sets
`OPENCODE_CONFIG_CONTENT` with a local `cotty` server
(`$XDG_RUNTIME_DIR/cotty/bin/cotty mcp`); `opencode mcp list` inside shows
it.

Verified: a real session inside, with one of opencode's free models and no
login: it wrote a file in the project with its edit tool and ran shell
commands with its bash tool; those commands could not read `~/.ssh`, saw
no other pts and no systemd user manager, and saw 6 processes.

MCP entry, for opencode started without `cotty agent` (assurance `weak`,
see [../mcp.md](../mcp.md)), in `~/.config/opencode/opencode.json` or a
project's `opencode.json`:

```
{"$schema": "https://opencode.ai/config.json",
 "mcp": {"cotty": {"type": "local", "command": ["cotty", "mcp"], "enabled": true}}}
```

Verified 2026-11-03 (WP-D, lab VM, opencode 1.19.5): `opencode mcp list`
shows `cotty connected`.
