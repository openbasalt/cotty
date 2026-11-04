# Aider (`aider`)

```
cotty agent -- aider
```

Visible from `$HOME`:

| Path | Access | Why |
| --- | --- | --- |
| `~/.aider/` | read-write (created if missing) | caches |
| `~/.aider.conf.yml`, `~/.aider.model.settings.yml`, `~/.aider.model.metadata.json` | read-only | settings |
| `~/.local/bin/aider` | read-only link | the launcher |
| `~/.local/share/uv` | read-only | `uv tool install aider-chat` (also holds the Python uv installed) |
| `~/.local/pipx/venvs/aider-chat` | read-only | a pipx install |
| `~/.local/lib` | read-only | a `pip install --user` |

`AIDER_ANALYTICS=false`, `AIDER_CHECK_UPDATE=false`,
`AIDER_SHOW_RELEASE_NOTES=false`. API keys come from the environment (the
profile keeps `AIDER_*`, `OPENAI_*` and the usual providers' key
variables) or a `.env` file in the project; a `.env` in your home is not
visible.

Residual, by design: a `.aider.conf.yml` or `.env` in the project is
read-write inside, and Aider reads both when you start it there yourself;
`lint-cmd` and `test-cmd` (with `auto-lint`, the default, or `auto-test`)
then run shell commands with your rights after every edit. Review them.
`~/.aider/` holds caches and, after an OpenRouter OAuth login,
`oauth-keys.env`, which Aider loads into its environment when you start
it yourself; it stays writable inside so the login works there.

MCP: Aider has no MCP client, so it is confined but cannot drive cotty's
shared terminal.

Verified: starts (`--version`), installed with `uv tool install`.
