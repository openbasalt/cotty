# Codex CLI (`codex`)

```
cotty agent -- codex
cotty agent -- codex exec "task"
```

Visible from `$HOME`:

| Path | Access | Why |
| --- | --- | --- |
| `~/.codex/` | read-write (created if missing) | login (`auth.json`), sessions, logs, history |
| `~/.codex/config.toml`, `hooks.json` | read-only, created empty when missing | MCP servers, `notify`, hooks, model provider auth commands |
| `~/.codex/rules/`, `AGENTS.md`, `prompts/`, `plugins/`, `skills/`, `agents/` | read-only, created empty when missing | execpolicy rules that approve commands, global instructions, custom prompts, plugins (hooks, MCP servers, skills) |
| `~/.local/bin/codex` | read-only | a standalone install |

Installed with npm (`npm i -g @openai/codex`) under `$HOME`: add `--ro`
for the npm prefix, for example `cotty agent --ro ~/.npm-global -- codex`.

Environment: the profile keeps `OPENAI_*`.

Residual, by design: per-profile files (`~/.codex/NAME.config.toml`) and
`AGENTS.override.md` are not protected (create them outside if you use
them; an existing one is writable inside), `memories/` is writable, and
`auth.json` and `sessions/` are readable inside. Approving a command for
good inside fails (`rules/` is read-only). User skills in
`~/.agents/skills` are not visible inside. Project level (read-write by
design, used when you start `codex` in the project yourself, once the
project is trusted): `.codex/config.toml`, `.codex/hooks.json`,
`.codex/rules/`, `.agents/skills/`, `AGENTS.md`.

MCP: with a cotty broker running, `cotty agent` passes
`-c mcp_servers.cotty.command="$XDG_RUNTIME_DIR/cotty/bin/cotty"` and
`-c mcp_servers.cotty.args=["mcp"]`; `codex mcp list` inside shows the
`cotty` server. Codex can keep its login in the keyring
(`cli_auth_credentials_store`); inside, use the default file store.

Verified: starts, `codex exec` reaches the OpenAI API and gets 401 without
a login, `codex mcp list` shows the injected server.

MCP entry, for Codex started without `cotty agent` (assurance `weak`, see
[../mcp.md](../mcp.md)), in `~/.codex/config.toml`:

```
[mcp_servers.cotty]
command = "cotty"
args = ["mcp"]
tool_timeout_sec = 330
```

`tool_timeout_sec` matters: Codex stops a tool after 60 s by default and
`term_wait` may take up to 300 s. Verified 2026-11-03 (WP-D, lab VM, Codex
CLI 0.166.0): `codex mcp list` shows `cotty` enabled and `codex mcp get
cotty` the timeout (Codex does not start the server for these commands).
