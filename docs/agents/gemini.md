# Gemini CLI (`gemini`)

```
cotty agent -- gemini
cotty agent -- gemini -p "task"
```

Visible from `$HOME`:

| Path | Access | Why |
| --- | --- | --- |
| `~/.gemini/` | read-write (created if missing) | login (`oauth_creds.json`), history, cache |
| `~/.gemini/settings.json`, `trustedFolders.json` | read-only, created as `{}` when missing | MCP servers, hooks, tool discovery and call commands; which folders may load their own configuration |
| `~/.gemini/.env`, `GEMINI.md`, `commands/`, `extensions/`, `skills/`, `policies/` | read-only, created empty when missing | environment of the CLI and its children, instructions, commands with shell, extensions (MCP servers, hooks), policy rules that allow shell commands |

`GEMINI_CLI_DISABLE_AUTO_UPDATE=true`. Installed with npm under `$HOME`:
add `--ro` for the npm prefix. Environment: the profile keeps `GEMINI_*`,
`GOOGLE_API_KEY` and the Vertex AI project and location variables.

Residual, by design: trusting a folder inside does not persist (trust it
outside), extensions cannot be installed inside, and the login files are
readable. Project level (read-write by design, loaded only in a trusted
folder when you start `gemini` yourself): `.gemini/settings.json`,
`.gemini/.env`, `.env`, `.gemini/commands/`, `.gemini/skills/`,
`.agents/skills/`, `GEMINI.md`.

MCP: Gemini CLI has no flag for an extra server. Add cotty once, outside
the confinement (the settings file is read-only inside):

```
gemini mcp add --scope user cotty cotty mcp
```

`cotty` resolves inside because `$XDG_RUNTIME_DIR/cotty/bin` is first in
the agent's `PATH`. Do not use a Google login stored in the keyring; the
file login works.

Verified: starts, `gemini -p` reaches its authentication check (no login in
the lab VM).

The same entry by hand, in `~/.gemini/settings.json`:

```
{"mcpServers": {"cotty": {"command": "cotty", "args": ["mcp"]}}}
```

Gemini CLI disables every MCP server, user-level ones included, in a
folder it does not trust; trust the project once (the CLI asks, or
`~/.gemini/trustedFolders.json`). Verified 2026-11-03 (WP-D, lab VM,
Gemini CLI 0.66.0): in a trusted folder `gemini mcp list` shows
`cotty: cotty mcp (stdio) - Connected`; in an untrusted one, `Disabled`.
See [../mcp.md](../mcp.md).
