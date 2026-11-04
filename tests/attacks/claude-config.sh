#!/usr/bin/env bash
# Claude Code's settings file under cotty agent (WP-E item 5), with a fake
# writer instead of a logged-in Claude Code (no login in the lab). Run in
# a lab VM: tests/lab/vm.sh claude-config NAME.
#
# Claude Code saves ~/.claude.json by writing a temporary file next to it
# and renaming it over the old one (the usual atomic save; container users
# who bind-mount that single file report rename errors). The fake writer
# does the same. Checks:
#
#   1. control: a single file bound into the confinement (--rw FILE, how
#      WP-C exposed ~/.claude.json) cannot be replaced by rename;
#   2. the claude profile: CLAUDE_CONFIG_DIR points at ~/.claude, the
#      inside settings file is seeded from ~/.claude.json, the fake writer
#      replaces it by rename, the result persists outside, and
#      ~/.claude.json itself is neither visible nor changed; the seeded
#      copy carries no MCP server definitions and no keys;
#   3. "protect" means always read-only: files and directories that define
#      what a CLI runs (hooks, MCP servers, plugins, commands) cannot be
#      created inside when they are missing, nor renamed away, for every
#      profile, and scripts named by a protected settings file are
#      read-only too.
set -u
COTTY=${COTTY:-/usr/local/bin/cotty}
W=$HOME/cotty-claude-config/$(date +%Y%m%d-%H%M%S)
P=$W/project
mkdir -p "$P"
FAIL=0
row() { printf '%-4s  %-30s %s\n' "$1" "$2" "$3"; [ "$1" = FAIL ] && FAIL=1; }

# A writer like Claude Code's: temp file in the same directory, rename.
cat >"$W/writer.sh" <<'EOS'
#!/bin/sh
f=$1
tmp="$f.tmp.$$.$(date +%s%N)"
printf '{"numStartups": %s, "writer": "fake"}\n' "$2" >"$tmp" || exit 3
mv -f "$tmp" "$f" || { rm -f "$tmp"; exit 4; }
cat "$f"
EOS
chmod +x "$W/writer.sh"

# 1. control: a single bound file.
echo '{"numStartups": 1}' >"$HOME/.cotty-lab-bound.json"
out=$("$COTTY" agent --quiet --profile generic --project "$P" --ro "$W" --rw "$HOME/.cotty-lab-bound.json" -- \
	"$W/writer.sh" "$HOME/.cotty-lab-bound.json" 2 2>&1)
rc=$?
if [ $rc -ne 0 ] && grep -q '"numStartups": 1' "$HOME/.cotty-lab-bound.json"; then
	row PASS file-bind-rename-fails "rename onto a bound file fails as expected (exit $rc: $(echo "$out" | tail -1))"
else
	row FAIL file-bind-rename-fails "exit $rc: $out"
fi

# 2. the claude profile.
mkdir -p "$HOME/.claude"
rm -f "$HOME/.claude/.claude.json"
echo '{"numStartups": 7, "seeded": true, "primaryApiKey": "fake-lab-key", "mcpServers": {"lab": {"command": "lab-mcp", "env": {"LAB_TOKEN": "fake-lab-token"}}}}' >"$HOME/.claude.json"
before=$(sha256sum "$HOME/.claude.json")
out=$("$COTTY" agent --quiet --no-mcp --profile claude --project "$P" --ro "$W" -- \
	sh -c 'echo "dir=$CLAUDE_CONFIG_DIR"; test -e "$HOME/.claude.json" && echo home-json-visible; cat "$CLAUDE_CONFIG_DIR/.claude.json"; "$0" "$CLAUDE_CONFIG_DIR/.claude.json" 8' "$W/writer.sh" 2>&1)
rc=$?
if [ $rc -eq 0 ] && echo "$out" | grep -q "dir=$HOME/.claude" && echo "$out" | grep -q '"seeded": true'; then
	row PASS claude-config-dir "CLAUDE_CONFIG_DIR=~/.claude, settings seeded from ~/.claude.json"
else
	row FAIL claude-config-dir "exit $rc: $(echo "$out" | tr '\n' ' ')"
fi
if echo "$out" | grep -q home-json-visible; then
	row FAIL claude-home-json-hidden "~/.claude.json is visible inside"
else
	row PASS claude-home-json-hidden "~/.claude.json (which can define MCP servers) is not visible inside"
fi
if grep -q '"numStartups": 8' "$HOME/.claude/.claude.json" 2>/dev/null; then
	row PASS claude-rename-save "the rename save inside reached ~/.claude/.claude.json outside"
else
	row FAIL claude-rename-save "~/.claude/.claude.json: $(cat "$HOME/.claude/.claude.json" 2>&1)"
fi
if grep -qE 'fake-lab|mcpServers' "$HOME/.claude/.claude.json"; then
	row FAIL claude-seed-sanitized "the seeded copy holds MCP servers or keys"
else
	row PASS claude-seed-sanitized "the seeded copy has no MCP servers and no keys"
fi
if [ "$(sha256sum "$HOME/.claude.json")" = "$before" ]; then
	row PASS claude-home-json-unchanged "~/.claude.json outside is unchanged"
else
	row FAIL claude-home-json-unchanged "~/.claude.json was changed"
fi
# Settings that define hooks stay read-only, also when they do not exist
# yet: cotty creates them empty outside and binds them read-only.
rm -rf "$HOME/.claude/settings.json" "$HOME/.claude/agents" "$HOME/.claude/hooks" "$HOME/.claude/scripts"
out=$("$COTTY" agent --quiet --no-mcp --profile claude --project "$P" --ro "$W" -- \
	"$W/writer.sh" "$HOME/.claude/settings.json" 9 2>&1)
if grep -q '^{}$' "$HOME/.claude/settings.json" && ! grep -q writer "$HOME/.claude/settings.json"; then
	row PASS claude-settings-missing "a missing ~/.claude/settings.json cannot be created inside (left as {} outside)"
else
	row FAIL claude-settings-missing "settings.json: $(cat "$HOME/.claude/settings.json" 2>&1)"
fi
out=$("$COTTY" agent --quiet --no-mcp --profile claude --project "$P" --ro "$W" -- \
	"$W/writer.sh" "$HOME/.claude/settings.json" 10 2>&1)
if grep -q '^{}$' "$HOME/.claude/settings.json"; then
	row PASS claude-settings-protected "~/.claude/settings.json cannot be replaced inside"
else
	row FAIL claude-settings-protected "settings.json changed: $(cat "$HOME/.claude/settings.json")"
fi
# Renames around the protected paths.
for t in "mv $HOME/.claude/agents $HOME/.claude/agents.old" "mv $HOME/.claude $HOME/.claude.old" \
	"mv $HOME/.claude/settings.json $HOME/.claude/s.old" "mkdir -p $HOME/.claude/agents/x" "touch $HOME/.claude/hooks/h.sh" \
	"touch $HOME/.claude/CLAUDE.md"; do
	# shellcheck disable=SC2086
	if "$COTTY" agent --quiet --no-mcp --profile claude --project "$P" -- $t >/dev/null 2>&1; then
		row FAIL claude-protect-around "allowed inside: $t"
	else
		row PASS claude-protect-around "denied inside: $t"
	fi
done
if [ -e "$HOME/.claude.old" ] || [ -e "$HOME/.claude/agents.old" ] || [ -n "$(ls -A "$HOME/.claude/agents")" ]; then
	row FAIL claude-protect-outside "something moved or appeared outside: $(ls -a "$HOME/.claude" | tr '\n' ' ')"
fi
# A script a protected settings file names (status line, hooks) is
# read-only, wherever it lives in the profile's directory.
mkdir -p "$HOME/.claude/scripts"
printf '#!/bin/sh\necho status\n' >"$HOME/.claude/scripts/status.sh"
chmod +x "$HOME/.claude/scripts/status.sh"
cat >"$HOME/.claude/settings.json" <<EOJ
{"statusLine": {"type": "command", "command": "~/.claude/scripts/status.sh"},
 "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "bash $HOME/.claude/scripts/status.sh --x"}]}]}}
EOJ
if "$COTTY" agent --quiet --no-mcp --profile claude --project "$P" -- sh -c "echo 'touch /tmp/x' >>$HOME/.claude/scripts/status.sh" >/dev/null 2>&1; then
	row FAIL claude-hook-script "the status line script was writable inside"
else
	row PASS claude-hook-script "the status line and hook script named by settings.json is read-only inside"
fi
rm -rf "$HOME/.cotty-lab-bound.json" "$HOME/.claude/settings.json" "$HOME/.claude/scripts"


# --- rows added after the final review (B7): a protected file that does
# not exist at launch must not be creatable inside (cotty creates it
# empty outside and binds it read-only), for every profile, and files
# that define commands are listed in the profiles.
# plant NAME PROFILE FILE: FILE (relative to $HOME) must not be created
# or changed from inside by the profile's agent. An empty placeholder
# left by cotty is expected.
plant() {
	local name=$1 profile=$2 f=$HOME/$3 out rc
	mkdir -p "$(dirname "$f")"
	rm -rf "$f"
	out=$("$COTTY" agent --quiet --no-mcp --profile "$profile" --project "$P" --ro "$W" -- \
		sh -c 'mkdir -p "$(dirname "$1")" && printf "{\"hooks\": \"planted\"}\n" >"$1"' sh "$f" 2>&1)
	rc=$?
	if grep -qs planted "$f"; then
		row FAIL "$name" "created from inside, it persists outside: $f"
	elif [ $rc -eq 0 ]; then
		row PASS "$name" "written inside but not outside: $3"
	else
		row PASS "$name" "refused inside (exit $rc): $(echo "$out" | tail -1 | cut -c1-80)"
	fi
	rm -rf "$f"
}
plant claude-settings-local claude .claude/settings.local.json
plant claude-plugins-dir claude .claude/plugins/planted/hooks/hooks.json
plant claude-skills-dir claude .claude/skills/planted/SKILL.md
plant codex-rules codex .codex/rules/planted.rules
plant gemini-extension gemini .gemini/extensions/planted/gemini-extension.json
plant opencode-lsp-bin opencode .local/share/opencode/bin/planted
plant claude-agents-dir claude .claude/agents/planted.md
plant claude-commands-dir claude .claude/commands/planted.md
plant claude-md claude .claude/CLAUDE.md
plant codex-config-missing codex .codex/config.toml
plant gemini-settings-missing gemini .gemini/settings.json
plant cursor-mcp-missing cursor-agent .cursor/mcp.json
plant cursor-hooks cursor-agent .cursor/hooks.json
plant opencode-config-missing opencode .config/opencode/opencode.json
plant opencode-plugin opencode .config/opencode/plugin/planted.js
# Program directories inside a profile directory (Claude Code's local
# install, the Cursor IDE's extensions and launch arguments).
plant claude-local-install claude .claude/local/claude
plant cursor-extensions cursor-agent .cursor/extensions/planted/package.json
plant cursor-argv cursor-agent .cursor/argv.json

# C0 (round 3): a link at a protected or read-only home path, left by an
# agent of an earlier run in a writable profile directory, never gets its
# target bound. A protected path that is such a link refuses the start.
mkdir -p "$HOME/.ssh" "$HOME/.claude"
chmod 700 "$HOME/.ssh"
CMARK=COTTY-C0-$RANDOM$RANDOM
[ -e "$HOME/.ssh/cotty-lab-c0" ] || echo "$CMARK" >"$HOME/.ssh/cotty-lab-c0"
CMARK=$(cat "$HOME/.ssh/cotty-lab-c0")
rm -rf "$HOME/.claude/local"
ln -s "$HOME/.ssh" "$HOME/.claude/local"
out=$("$COTTY" agent --quiet --no-mcp --profile claude --project "$P" -- sh -c 'cat "$HOME/.claude/local/cotty-lab-c0"' 2>&1)
rc=$?
if echo "$out" | grep -q "$CMARK"; then
	row FAIL home-link-protect "~/.ssh read through the link ~/.claude/local"
elif [ $rc -ne 0 ] && echo "$out" | grep -q "claude/local"; then
	row PASS home-link-protect "refused: $(echo "$out" | tail -1 | cut -c1-100)"
else
	row FAIL home-link-protect "started without refusing (exit $rc): $(echo "$out" | tail -1 | cut -c1-80)"
fi
rm -f "$HOME/.claude/local"
mkdir -p "$HOME/.local/share"
if [ ! -e "$HOME/.local/share/claude" ]; then
	ln -s "$HOME/.ssh" "$HOME/.local/share/claude"
	out=$("$COTTY" agent --quiet --no-mcp --profile claude --project "$P" -- sh -c 'cat "$HOME/.local/share/claude/cotty-lab-c0"' 2>&1)
	rc=$?
	if echo "$out" | grep -q "$CMARK"; then
		row FAIL home-link-ro "~/.ssh read through the link ~/.local/share/claude"
	else
		row PASS home-link-ro "the link's target is not bound (exit $rc)"
	fi
	rm -f "$HOME/.local/share/claude"
else
	row SKIP home-link-ro "~/.local/share/claude exists"
fi

# C1 (round 3): the IDE lock files in ~/.claude/ide (port and auth token
# of the IDE's MCP server) are not readable inside, and a lock planted
# inside does not reach the person's directory; --show-hidden shows them.
mkdir -p "$HOME/.claude/ide"
IMARK=COTTY-IDE-$RANDOM$RANDOM
echo "{\"authToken\": \"$IMARK\"}" >"$HOME/.claude/ide/65000.lock"
out=$("$COTTY" agent --quiet --no-mcp --profile claude --project "$P" -- sh -c 'cat "$HOME"/.claude/ide/*.lock; echo planted >"$HOME/.claude/ide/65001.lock"' 2>&1)
if echo "$out" | grep -q "$IMARK"; then
	row FAIL claude-ide-lock-hidden "the IDE lock file is readable inside"
elif [ -e "$HOME/.claude/ide/65001.lock" ]; then
	row FAIL claude-ide-lock-hidden "a lock planted inside reached ~/.claude/ide"
else
	row PASS claude-ide-lock-hidden "~/.claude/ide is empty inside and planted locks stay inside"
fi
out=$("$COTTY" agent --quiet --no-mcp --show-hidden --profile claude --project "$P" -- sh -c 'cat "$HOME"/.claude/ide/*.lock' 2>&1)
if echo "$out" | grep -q "$IMARK"; then
	row PASS claude-ide-show-hidden "--show-hidden leaves ~/.claude/ide visible"
else
	row FAIL claude-ide-show-hidden "not visible with --show-hidden: $(echo "$out" | tail -1 | cut -c1-80)"
fi
rm -f "$HOME/.claude/ide/65000.lock" "$HOME/.claude/ide/65001.lock"

# Round 4: dotfiles layouts. A protected path that is a link (GNU stow,
# chezmoi's symlink mode) stays read-only: through the link, at the
# link's target when the agent sees it writable (the dotfiles repository
# as the project), and the link itself cannot be replaced.
D=$W/dotfiles
mkdir -p "$D/claude"
echo '{}' >"$D/claude/settings.json"
rm -rf "$HOME/.claude/settings.json"
ln -s "$D/claude/settings.json" "$HOME/.claude/settings.json"
for t in "printf '{\"hooks\":\"planted\"}' >$HOME/.claude/settings.json" \
	"printf '{\"hooks\":\"planted\"}' >$D/claude/settings.json" \
	"rm -f $HOME/.claude/settings.json && echo planted >$HOME/.claude/settings.json" \
	"echo planted >$HOME/.claude/s.new && mv -f $HOME/.claude/s.new $HOME/.claude/settings.json"; do
	"$COTTY" agent --quiet --no-mcp --profile claude --project "$D" -- sh -c "$t" >/dev/null 2>&1
	if [ -L "$HOME/.claude/settings.json" ] && [ "$(readlink "$HOME/.claude/settings.json")" = "$D/claude/settings.json" ] &&
		[ "$(cat "$D/claude/settings.json")" = "{}" ]; then
		row PASS dotfiles-link-protect "denied: ${t//$HOME/\~}"
	else
		row FAIL dotfiles-link-protect "allowed: ${t//$HOME/\~} ($(ls -l "$HOME/.claude/settings.json"; cat "$D/claude/settings.json"))"
	fi
	rm -f "$HOME/.claude/s.new"
done
out=$("$COTTY" agent --quiet --no-mcp --profile claude --project "$D" -- cat "$HOME/.claude/settings.json" 2>&1)
if echo "$out" | grep -qx '{}'; then
	row PASS dotfiles-link-readable "the linked settings file reads as usual inside"
else
	row FAIL dotfiles-link-readable "inside: $(echo "$out" | tail -1 | cut -c1-80)"
fi
# The same with the target next to the link, in the writable ~/.claude.
rm -f "$HOME/.claude/settings.json"
echo '{}' >"$HOME/.claude/shared.json"
ln -s shared.json "$HOME/.claude/settings.json"
"$COTTY" agent --quiet --no-mcp --profile claude --project "$P" -- sh -c "printf planted >$HOME/.claude/shared.json" >/dev/null 2>&1
if [ "$(cat "$HOME/.claude/shared.json")" = "{}" ] && [ -L "$HOME/.claude/settings.json" ]; then
	row PASS dotfiles-link-sibling "the target in ~/.claude of a protected link is read-only inside"
else
	row FAIL dotfiles-link-sibling "the target was changed: $(cat "$HOME/.claude/shared.json")"
fi
rm -f "$HOME/.claude/settings.json" "$HOME/.claude/shared.json"
# A protected directory that is a link cannot be kept read-only: refused.
mkdir -p "$D/claude/skills"
rm -rf "$HOME/.claude/skills"
ln -s "$D/claude/skills" "$HOME/.claude/skills"
out=$("$COTTY" agent --quiet --no-mcp --profile claude --project "$D" -- true 2>&1)
rc=$?
if [ $rc -ne 0 ] && echo "$out" | grep -q "no-folding"; then
	row PASS dotfiles-link-dir-refused "refused: $(echo "$out" | tail -1 | cut -c1-90)"
else
	row FAIL dotfiles-link-dir-refused "started (exit $rc): $(echo "$out" | tail -1 | cut -c1-80)"
fi
rm -f "$HOME/.claude/skills"

# ~/.claude itself a link into the dotfiles repository: the hidden IDE
# directory and the protected files below it stay in force, whether the
# repository is the project (the link is recreated inside) or not (the
# target is bound at ~/.claude).
mv "$HOME/.claude" "$W/claude.saved"
mkdir -p "$D/claude/ide"
echo "{\"authToken\": \"$IMARK\"}" >"$D/claude/ide/65000.lock"
ln -s "$D/claude" "$HOME/.claude"
for proj in "$D" "$P"; do
	out=$("$COTTY" agent --quiet --no-mcp --profile claude --project "$proj" -- sh -c "cat $HOME/.claude/ide/*.lock $D/claude/ide/*.lock 2>/dev/null; printf planted >$HOME/.claude/settings.json; printf planted >$D/claude/settings.json" 2>&1)
	rc=$?
	if echo "$out" | grep -q "$IMARK"; then
		row FAIL claude-dir-link-hide "the IDE lock is readable inside (project ${proj//$HOME/\~})"
	elif [ $rc -eq 125 ]; then
		row FAIL claude-dir-link-hide "the agent did not start: $(echo "$out" | tail -1 | cut -c1-80)"
	else
		row PASS claude-dir-link-hide "~/.claude/ide is hidden through the ~/.claude link (project ${proj//$HOME/\~})"
	fi
	if [ "$(cat "$D/claude/settings.json")" = "{}" ]; then
		row PASS claude-dir-link-protect "settings.json below the ~/.claude link stays read-only (project ${proj//$HOME/\~})"
	else
		row FAIL claude-dir-link-protect "settings.json changed (project ${proj//$HOME/\~})"
		echo '{}' >"$D/claude/settings.json"
	fi
done
rm -f "$HOME/.claude"
# ~/.claude a link to a place no agent may see: skipped, and nothing is
# created through it (placeholders, hidden directories).
before=$(cd "$HOME/.ssh" && find . | sort | sha256sum)
ln -s "$HOME/.ssh" "$HOME/.claude"
"$COTTY" agent --quiet --no-mcp --profile claude --project "$P" -- true >/dev/null 2>&1
if [ "$(cd "$HOME/.ssh" && find . | sort | sha256sum)" = "$before" ]; then
	row PASS claude-dir-link-skipped "nothing created in ~/.ssh through a ~/.claude link to it"
else
	row FAIL claude-dir-link-skipped "created in ~/.ssh: $(cd "$HOME/.ssh" && ls -A | tr '\n' ' ')"
fi
rm -f "$HOME/.claude"
mv "$W/claude.saved" "$HOME/.claude"
exit $FAIL
