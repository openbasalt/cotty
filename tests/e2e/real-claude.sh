#!/usr/bin/env bash
# real-claude.sh: a real Claude Code drives a cotty session through
# `cotty mcp` and hits a sudo prompt that the scripted person answers.
# Runs INSIDE the lab VM as the test user (tests/e2e/vm.sh real-claude
# installs and starts it), never on a host.
#
# Login: CLAUDE_TOKEN_FILE names a file (mode 0600, owned by you) holding
# a Claude Code OAuth token (from `claude setup-token`) on one line. The
# script never prints it; it reaches only the test process and the claude
# child, not the cotty session's shell.
#
# Environment (defaults fit tests/e2e/vm.sh):
#   CLAUDE_TOKEN_FILE         required
#   COTTY_BIN                 /usr/local/bin/cotty
#   COTTY_TEST_PASSWORD_FILE  ~/.cotty-test-password (the sudo password)
#   COTTY_E2E_TEST            ~/cotty-e2e.test (the e2e test binary)
#   COTTY_E2E_RESULTS         ~/cotty-e2e-results/<time>
#   COTTY_E2E_CONFINED        1: claude runs under `cotty agent`, plus the probe run
#   COTTY_E2E_CLAUDE_MODEL    passed to claude --model (e.g. haiku)
set -euo pipefail

die() { echo "real-claude: $*" >&2; exit 1; }

: "${CLAUDE_TOKEN_FILE:?set CLAUDE_TOKEN_FILE to the 0600 file with the Claude Code OAuth token}"
[ -f "$CLAUDE_TOKEN_FILE" ] || die "$CLAUDE_TOKEN_FILE does not exist"
[ "$(stat -c %u "$CLAUDE_TOKEN_FILE")" = "$(id -u)" ] || die "$CLAUDE_TOKEN_FILE is not yours"
[ "$(stat -c %a "$CLAUDE_TOKEN_FILE")" = 600 ] || die "$CLAUDE_TOKEN_FILE must have mode 0600"

export COTTY_BIN=${COTTY_BIN:-/usr/local/bin/cotty}
export COTTY_TEST_PASSWORD_FILE=${COTTY_TEST_PASSWORD_FILE:-$HOME/.cotty-test-password}
TEST=${COTTY_E2E_TEST:-$HOME/cotty-e2e.test}
[ -x "$COTTY_BIN" ] || die "no cotty at $COTTY_BIN"
[ -x "$TEST" ] || die "no e2e test binary at $TEST"
[ -f "$COTTY_TEST_PASSWORD_FILE" ] || die "no test password at $COTTY_TEST_PASSWORD_FILE"

# Claude Code: the native installer puts it in ~/.local/bin.
export PATH=$HOME/.local/bin:$PATH
if ! command -v claude >/dev/null; then
	echo "real-claude: installing Claude Code (native installer)"
	curl -fsSL https://claude.ai/install.sh | bash
fi
claude --version

CLAUDE_CODE_OAUTH_TOKEN=$(head -n1 "$CLAUDE_TOKEN_FILE" | tr -d '[:space:]')
[ -n "$CLAUDE_CODE_OAUTH_TOKEN" ] || die "$CLAUDE_TOKEN_FILE is empty"
export CLAUDE_CODE_OAUTH_TOKEN
export COTTY_REAL_CLAUDE=1

exec "$TEST" -test.run '^TestRealClaude$' -test.v -test.timeout 20m
