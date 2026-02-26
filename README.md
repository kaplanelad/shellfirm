<p align="center">
<img src="https://github.com/kaplanelad/shellfirm/actions/workflows/ci.yaml/badge.svg"/>
<img src="https://github.com/kaplanelad/shellfirm/actions/workflows/release.yml/badge.svg"/>
</p>

# shellfirm

**Think before you execute.**

Humans make mistakes. AI agents make them faster. shellfirm intercepts dangerous shell commands before the damage is done — for both.

```
$ rm -rf ./src
============ RISKY COMMAND DETECTED ============
Severity: Critical
Blast radius: [PROJECT] — Deletes 347 files (12.4 MB) in ./src
Description: You are going to delete everything in the path.

Solve the challenge: 8 + 0 = ? (^C to cancel)
```

```
$ git push origin main --force
============ RISKY COMMAND DETECTED ============
Severity: High
Blast radius: [RESOURCE] — Force-pushes branch main (3 commits behind remote)
Description: This command will force push and overwrite remote history.
Alternative: git push --force-with-lease
  (Checks that your local ref is up-to-date before force pushing, preventing accidental overwrites of others' work.)

Solve the challenge: 3 + 5 = ? (^C to cancel)
```

---

## Features

- **100+ patterns** across 9 ecosystems (filesystem, git, Kubernetes, Terraform, Docker, AWS, GCP/Azure, Heroku, databases)
- **8 shells** — Zsh, Bash, Fish, Nushell, PowerShell, Elvish, Xonsh, Oils
- **Context-aware escalation** — harder challenges when connected via SSH, running as root, on protected git branches, or in production Kubernetes clusters
- **Safe alternative suggestions** — actionable safer commands shown alongside every warning
- **Severity levels** with configurable thresholds (`Critical`, `High`, `Medium`, `Low`, `Info`)
- **Project policies** — share team safety rules via `.shellfirm.yaml` (additive-only, never weakens)
- **Audit trail** — every intercepted command and decision logged as JSON-lines
- **Blast radius detection** — runtime context signals feed into risk scoring
- **MCP server** — expose shellfirm as an AI tool for Claude Code, Cursor, and other agents

---

## AI Agent Integration

shellfirm ships as an [MCP](https://modelcontextprotocol.io/) server so AI coding agents can check commands before running them.

### MCP Tools

| Tool | Description |
|------|-------------|
| `check_command` | Check if a command is risky — returns severity, matched rules, and alternatives |
| `suggest_alternative` | Get safer replacement commands |
| `explain_risk` | Detailed explanation of why a command is dangerous |
| `get_policy` | Read the active shellfirm configuration and project policy |

### MCP Setup

#### Claude Code

Add to `~/.claude.json` (global) or `.claude.json` (per-project):

```json
{
  "mcpServers": {
    "shellfirm": {
      "command": "shellfirm",
      "args": ["mcp"]
    }
  }
}
```

For Cursor, Windsurf, Zed, Cline, Continue, Amazon Q, and other MCP-compatible tools, see the [integration guides](https://shellfirm.vercel.app/docs/agents-and-automation/cursor-and-others).

---

## Installation

### npm

```bash
npm install -g @shellfirm/cli
```

### Homebrew

```bash
brew tap kaplanelad/tap && brew install shellfirm
```

### Cargo

```bash
cargo install shellfirm
```

Or download the binary from the [releases page](https://github.com/kaplanelad/shellfirm/releases).

---

## Quick Start

**1. Install the shell hook** (auto-detects your shell):

```bash
shellfirm init --install
```

**2. Restart your shell** (or `source` your rc file).

**3. Try it:**

```bash
git reset --hard  # Should trigger shellfirm!
```

For manual setup, shell-specific instructions, and Oh My Zsh plugin, see the [shell setup docs](https://shellfirm.dev/docs/getting-started/shell-setup).

---

## Documentation

Full documentation is available at **[shellfirm.dev](https://shellfirm.dev)**:

- [Configuration](https://shellfirm.dev/docs/configuration) — challenge types, severity thresholds, custom checks
- [Context-Aware Protection](https://shellfirm.dev/docs/context-aware) — SSH, root, git branches, Kubernetes, environment variables
- [Team Policies](https://shellfirm.dev/docs/team-policies) — `.shellfirm.yaml` project-level rules
- [AI Agents & Automation](https://shellfirm.vercel.app/docs/agents-and-automation) — MCP server, LLM analysis, agent mode

---

## Contributing

Contributions are welcome! Please open an issue or pull request on [GitHub](https://github.com/kaplanelad/shellfirm).

## License

[Apache-2.0](LICENSE)
