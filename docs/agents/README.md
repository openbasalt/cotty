# Agent CLIs under `cotty agent`

One page per agent CLI: what its profile exposes, where it keeps its
login, how it reaches `cotty mcp`, and what was verified. The model is in
[../confinement.md](../confinement.md).

| CLI | Profile | Starts inside | Real work inside | MCP wiring |
| --- | --- | --- | --- | --- |
| [Claude Code](claude.md) | `claude` | yes | up to login (no login in the lab VM) | `--mcp-config`, automatic |
| [Codex CLI](codex.md) | `codex` | yes | up to the API's 401 (no login) | `-c mcp_servers.cotty.*`, automatic, listed by `codex mcp list` |
| [Gemini CLI](gemini.md) | `gemini` | yes | up to "set an auth method" (no login) | one-time `gemini mcp add`, outside |
| [Cursor CLI](cursor-agent.md) | `cursor-agent` | yes | not tried (no login) | one-time entry in `~/.cursor/mcp.json`, outside |
| [Aider](aider.md) | `aider` | yes | not tried (no key) | none: Aider has no MCP client |
| [opencode](opencode.md) | `opencode` | yes | yes: a free model wrote a file and ran shell commands | `OPENCODE_CONFIG_CONTENT`, automatic, listed by `opencode mcp list` |
| any other program | `generic` | yes (the escape matrix runs under it) | yes | none |

Verified 2026-11-03 in Fedora 44 lab VMs on kernels 6.19 (Landlock ABI 7)
and 7.2 (ABI 10) with `tests/attacks/agents.sh`. Versions: Claude Code
2.1.317, Codex CLI 0.166.0, Gemini CLI 0.66.0, opencode 1.19.5, Cursor CLI
2026.10.22, Aider 0.86.2.

Again 2026-11-04 with the profiles that protect every file a CLI runs
later (Fedora 44, kernel 6.19): Claude Code 2.1.318, Codex CLI 0.166.0,
Gemini CLI 0.66.0, opencode 1.19.5 and Cursor CLI 2026.10.22 start and
reach their login or API check, the MCP wiring of Codex and opencode is
listed; Aider was not installed. Profile layouts were checked against
the CLIs' documentation of 2026-11 (Claude Code, Codex, Cursor, Gemini
CLI, opencode, Aider).

Common to every profile:

- the project read-write, except what git runs with your rights (git
  config, hooks, hooksPath, includes, submodule and worktree git
  directories; see "What git runs" in ../confinement.md),
  `~/.gitconfig` and `~/.config/git/{config,ignore,attributes}` read-only;
- the environment is an allowlist: each profile keeps only the model
  provider variables its CLI reads (`[scrub] keep`); other tokens in your
  environment do not reach the agent;
- everything else in `$HOME` hidden; writes to `~` land in a private tmpfs
  and are gone when the agent exits;
- a CLI installed somewhere the profile does not list (an npm prefix, nvm,
  a custom directory) needs `cotty agent --ro DIR` for that directory;
- the CLI's login files are read-write: the agent can read its own token,
  as it always could. cotty protects your other credentials, not the
  agent's own;
- logins that store tokens in the desktop keyring (Secret Service over
  D-Bus) do not work inside: the session bus is not reachable. Use the
  CLI's file-based login.
- readable inside by design: the CLI's own login and refresh tokens
  (OAuth files such as `~/.claude/.credentials.json`,
  `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`,
  `~/.config/cursor/auth.json`, `~/.local/share/opencode/auth.json`), its
  transcripts and history (`~/.claude/projects/`, `~/.codex/sessions/`,
  opencode's database). The network is open, so a prompt-injected agent
  can send them away; use a separate account or API key for confined work
  if that matters. A seeded settings file carries no MCP server
  definitions and no keys (the claude seed drops them).
- project level configuration is read-write by design and runs later
  when you start the CLI yourself in that project: `.claude/settings.json`,
  `.claude/settings.local.json`, `.claude/` agents, commands and skills,
  `.mcp.json`, `CLAUDE.md`, `AGENTS.md`, `.codex/`, `.agents/skills/`,
  `.cursor/`, `.gemini/`, `GEMINI.md`, `opencode.json`, `.opencode/`,
  `.aider.conf.yml`, `.env`, `.vscode/tasks.json`. A confined agent can
  plant a hook or an MCP server there that runs, unconfined, the next
  time you start that CLI in the project yourself. Review what the agent
  changed there before you do.
- in `$HOME`, every path a profile lists as `protect` is read-only, also
  when it does not exist at launch (cotty creates it empty, outside,
  first, and leaves it there afterwards) and it cannot be renamed away;
  scripts a protected settings file names are read-only too, and so are
  program directories inside a profile directory (`~/.claude/local`, the
  Cursor IDE's `~/.cursor/extensions`, opencode's language servers). `tests/attacks/claude-config.sh` checks each
  built-in profile. Anything else the profile directory holds and the CLI
  loads later (listed on each page) stays writable.
