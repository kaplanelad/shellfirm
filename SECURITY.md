# Security policy

shellfirm is a safety tool: a way to run a risky command without the
challenge, deny list or project policy stopping it is a security bug.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability or a bypass.

1. Email the maintainer, Elad Kaplan, at
   [kaplan.elad@gmail.com](mailto:kaplan.elad@gmail.com?subject=shellfirm%20security%20report).
2. Or use GitHub's private vulnerability reporting on this repository
   (**Security** tab -> **Report a vulnerability**) when it is enabled.

Include the shellfirm version (`shellfirm --version`), your shell and OS, how
shellfirm is hooked in (shell hook, `wrap`, Claude Code / Cursor / MCP), and an exact
reproduction. We aim to acknowledge reports within 7 days and to agree on a
disclosure date with you once a fix is ready.

## What counts

In scope:

- a command that matches a built-in check, deny list or project policy but
  runs without a challenge or denial (parser, quoting, wrapper or hook
  bypasses);
- ways for an AI agent or a repository to weaken shellfirm settings or
  policies without the user noticing;
- audit-log tampering or spoofing that shellfirm claims to prevent;
- crashes or hangs that make a hook fail open.

Out of scope: a dangerous command that no check covers (please open a normal
issue or PR to add a check, see [docs/add-new-patterns.md](docs/add-new-patterns.md)),
and limits that are already documented (for example nushell built-ins, see
[Known limitations](README.md#known-limitations)).

## Supported versions

Security fixes go into the latest release only.
