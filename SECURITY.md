# Security policy

cotty promises that what a person types at a secret prompt never reaches
the agent, that values on the masking list never reach it either, that
the person's view of the session is honest, and that an agent at a given
assurance level cannot do what docs/security.md says that level stops. A
way around any of these is a security problem. Please report it privately
and give us time to fix it before it is disclosed.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository: the
"Report a vulnerability" button under the Security tab
(https://github.com/openbasalt/cotty/security/advisories/new). If you
cannot use GitHub, write to security@openbasalt.org.

Do not open a public issue, pull request or discussion for a security
problem.

Examples of what we want to hear about:

- secret input, a listed value or text typed in private mode that reaches
  an agent connection, the MCP server, a log or the audit file;
- an agent that takes the person's role, approves its own command, forges
  the lock or the status line, or reads or writes the session's terminal;
- an agent under `cotty agent` that reaches something docs/confinement.md
  says is out of its view, or plants something that runs unconfined later;
- an agent tagged by `cotty-guard` that gets past one of its rules, or a
  session that reports `strong` while the protection is not in place.

Known open weaknesses are listed as rows marked `[open: ITEM]` in the
escape matrix results and in docs/security.md; a report that one of them
is worse than described is still welcome.

Please include what you can of:

- the cotty commit or version, the distribution and the kernel version,
  and the output of `cotty doctor` and `cotty guard facts`;
- steps to reproduce, and what an attacker gains (who the attacker is: a
  prompt-injected agent under `cotty agent`, an unconfined program of the
  same user, another user);
- whether you want to be credited, and how.

We aim to acknowledge a report within 7 days and to agree on a disclosure
date with you, normally within 90 days of the report or when a fix is
released, whichever comes first. Fixes are published with a GitHub
security advisory (and a CVE when it applies).

## Supported versions

cotty is pre-release. Only the latest commit on `main` receives fixes.

## Testing

Run the escape matrix and the guard only in throwaway VMs
(`tests/lab/vm.sh`), never on a machine you care about.
