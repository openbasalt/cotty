#!/usr/bin/env bash
# Smoke test: every agent CLI that is installed starts under `cotty agent`
# with its own profile, sees its own config directory and nothing else of
# $HOME. Run it in a lab VM (tests/lab/vm.sh ssh NAME bash ~/cotty/tests/attacks/agents.sh).
# CLIs installed with npm under ~/.npm-global are given with --ro.
#
# Prints PASS/FAIL/SKIP per CLI. A CLI that is not logged in still counts
# as started when it reaches its own "log in" message: it ran, read its
# directory and reached the network inside the confinement.
set -u
COTTY=${COTTY:-$HOME/cotty/bin/cotty}
P=$HOME/cotty-agents-project
mkdir -p "$P"
export PATH=$HOME/.local/bin:$HOME/.npm-global/bin:$PATH
EXTRA=()
[ -d "$HOME/.npm-global" ] && EXTRA+=(--ro "$HOME/.npm-global")

row() { printf '%-4s  %-14s %s\n' "$1" "$2" "$3"; }

run() { # run PROFILE CMD...: confined, output on one line, its last 220 characters
	local prof=$1
	shift
	timeout 120 "$COTTY" agent --quiet --profile "$prof" --project "$P" "${EXTRA[@]}" -- "$@" </dev/null 2>&1 | tr -d '\r' | tr '\n' ' ' | tail -c 220
}

check() { # check PROFILE CMD --version-args: version must print
	local prof=$1 cmd=$2
	shift 2
	if ! command -v "$cmd" >/dev/null; then
		row SKIP "$prof" "$cmd not installed"
		return
	fi
	local out
	out=$(run "$prof" "$cmd" "$@")
	if echo "$out" | grep -qE '[0-9]+\.[0-9]+'; then
		row PASS "$prof" "$cmd $*: $out"
	else
		row FAIL "$prof" "$cmd $*: $out"
	fi
}

check claude claude --version
check codex codex --version
check gemini gemini --version
check opencode opencode --version
check cursor-agent cursor-agent --version
check aider aider --version

# Beyond --version: a real request path. Without a login each CLI must
# fail on authentication, not on a missing file, socket or permission.
if command -v claude >/dev/null; then
	before=$(stat -c %Y "$HOME/.claude.json" 2>/dev/null)
	out=$(run claude claude -p "Reply with the single word PONG")
	after=$(stat -c %Y "$HOME/.claude.json" 2>/dev/null)
	if echo "$out" | grep -q PONG; then
		row PASS claude-prompt "answered: $out"
	elif echo "$out" | grep -qiE 'log ?in|api key|authenticat|/login'; then
		row PASS claude-prompt "reached authentication (no login in this VM): $out"
	else
		row FAIL claude-prompt "$out"
	fi
	if echo "$out" | grep -qiE 'EBUSY|EROFS|EACCES|permission denied'; then
		row FAIL claude-files "file error inside: $out"
	else
		row PASS claude-files "no file errors; ~/.claude.json mtime $before -> $after"
	fi
fi

# MCP wiring: cotty agent always binds the agent endpoint directory
# ($XDG_RUNTIME_DIR/cotty/agent, created when missing) and points the CLI
# at `cotty mcp`; the server is expected to show up in the CLI's list.
mcp() { # mcp PROFILE CMD...: the cotty server must be listed
	local prof=$1 out
	shift
	command -v "$1" >/dev/null || { row SKIP "$prof-mcp" "$1 not installed"; return; }
	out=$(run "$prof" "$@")
	if echo "$out" | grep -q cotty; then row PASS "$prof-mcp" "$out"; else row FAIL "$prof-mcp" "$out"; fi
}
# Claude Code's --mcp-config servers do not show in `claude mcp list`;
# check the command line cotty agent builds instead.
if command -v claude >/dev/null; then
	if "$COTTY" agent --dry-run --profile claude --project "$P" -- claude -p hi 2>/dev/null | grep -q '"--mcp-config"'; then
		row PASS claude-mcp "the session command line carries --mcp-config with the cotty server"
	else
		row FAIL claude-mcp "no --mcp-config in the planned command line"
	fi
fi
mcp codex codex mcp list
mcp opencode opencode mcp list
if command -v codex >/dev/null; then
	out=$(run codex codex exec --skip-git-repo-check "Reply with PONG")
	if echo "$out" | grep -qiE 'PONG|log ?in|auth|api key|401'; then
		row PASS codex-prompt "$out"
	else
		row FAIL codex-prompt "$out"
	fi
fi
if command -v gemini >/dev/null; then
	out=$(run gemini gemini -p "Reply with PONG")
	if echo "$out" | grep -qiE 'PONG|auth|api key|GEMINI_API_KEY|login'; then
		row PASS gemini-prompt "$out"
	else
		row FAIL gemini-prompt "$out"
	fi
fi
if command -v opencode >/dev/null; then
	out=$(run opencode opencode models)
	row INFO opencode-models "$out"
fi
