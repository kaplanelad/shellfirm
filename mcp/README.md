# Shellfirm MCP — Human verification before risky commands execute

Shellfirm MCP adds a consequence‑aware approval step before any flagged command runs. Think of it as a purpose‑built CAPTCHA/second‑factor for shell commands: when a command is risky, you must pass a short challenge and explicitly accept the consequences before it can execute. It’s a Model Context Protocol (MCP) server that intercepts shell commands from your IDE/AI assistant and enforces this double‑verification via a focused browser challenge.

## Why teams use Shellfirm MCP

- **Mandatory protection**: All commands flow through a single secure gate — no bypass.
- **Human-in-the-loop**: Risky commands pause execution until you explicitly approve.
- **Single source of truth**: Rules are authored in Rust and compiled to WASM — fast, consistent, portable across platforms.
- **Drop-in for Cursor**: Works out of the box with Cursor MCP; easy to add to other MCP clients.
- **Extensible**: Multiple challenge types, severity filtering, and pluggable rule sets.

## Features

- **Deep, local command analysis**: Validates commands against Shellfirm’s Rust rules compiled to WASM.
- **Browser challenges**: Confirm, math, or word-entry challenges to reduce misclicks and automate “are you sure?” checks.
- **Severity gates**: Enforce only `critical` and `high`, or include `medium,low` for stricter environments.
- **Environment propagation control**: Run commands with or without inheriting `process.env` using the `--no-propagate-env` flag.
- **Cross‑platform headless UI**: Powered by Playwright for Chromium/WebKit/Firefox in headless mode when desired.
- **Offline by default**: No external calls required during validation.

## Getting started

Use the standard MCP configuration below with your client. This mirrors the multi‑client setup style from Playwright MCP ([source](https://raw.githubusercontent.com/microsoft/playwright-mcp/refs/heads/main/README.md)).

Standard config (works in most MCP clients):

```json
{
  "mcpServers": {
    "shellfirm": {
      "command": "npx",
      "args": ["@shellfirm/mcp@latest"]
    }
  }
}
```

### Cursor

- Go to `Cursor Settings` → `MCP` → `Add new MCP Server`.
- Type: `command`
- Command: `npx @shellfirm/mcp@latest`
- Optionally add args, for example `--challenge word` or `--severity critical,high`.

### VS Code / VS Code Insiders

- Follow the MCP server install guide and use the standard config above.
- You can also add via CLI:

```bash
code --add-mcp '{"name":"shellfirm","command":"npx","args":["@shellfirm/mcp@latest"]}'
```

### Claude Desktop

- Follow the MCP quickstart guide and add this to your config file.
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "shellfirm": {
      "command": "npx",
      "args": ["@shellfirm/mcp@latest"]
    }
  }
}
```

### Other MCP clients (Windsurf, Goose, LM Studio, etc.)

- Add a local MCP server with the standard config above.
- If your client supports command‑line addition, point it to `npx @shellfirm/mcp@latest` and include optional args.

## Configuration

- **Challenge type** (default `confirm`):
  - `--challenge confirm|math|word`
- **Severity filter**:
  - `--severity critical,high,medium,low`
- **Environment propagation** (default propagate):
- `--no-propagate-env` to run commands without inheriting the current process environment

Examples:

Default (confirm, critical+high+medium):

```json
{
  "mcpServers": {
    "shellfirm": {
      "command": "npx",
      "args": ["@shellfirm/mcp@latest"],
      "env": {}
    }
  }
}
```

Custom challenge type:

```json
{
  "mcpServers": {
    "shellfirm": {
      "command": "npx",
      "args": ["@shellfirm/mcp@latest", "--challenge", "word"]
    }
  }
}
```

Restrict to critical + high only:

```json
{
  "mcpServers": {
    "shellfirm": {
      "command": "npx",
      "args": ["@shellfirm/mcp@latest", "--severity", "critical,high"]
    }
  }
}
```

Disable environment propagation (do not inherit current `process.env` for executed commands):

```json
{
  "mcpServers": {
    "shellfirm": {
      "command": "npx",
      "args": ["@shellfirm/mcp@latest", "--no-propagate-env"]
    }
  }
}
```

## Developer guide

For a no‑LLM local workflow to run and call this MCP server directly (including MCP Inspector usage and a local challenge preview script), see `DEVELOPERS.md`.

## How it works

1. The MCP server receives a terminal command from your IDE/AI via the MCP transport.
2. The command is evaluated against Rust‑based rules compiled to WASM for speed and portability.
3. If risky, a lightweight browser challenge opens (headless or visible) and requires approval.
4. Approved commands are executed; denied commands are cancelled and never run.

## Screenshots

![Challenge Preview](../docs/media/example.gif)

## Development

- Rules: defined in Rust in `shellfirm_core` and shipped to this server via WASM.
- UI & Challenges: rendered using Playwright’s browser automation in headless/non‑headless modes.
- Local testing: use your MCP‑compatible client (Cursor, Claude Desktop, etc.) to send commands.

## FAQ

- Does this block everything?
  - No. Safe commands execute immediately. Only commands matched by risky patterns require approval.
- Is this offline?
  - Yes. Rule evaluation runs locally via WASM.
- Which OSes are supported?
  - macOS, Linux, and Windows. Headless browsers are supported on all platforms (via Playwright).
- Can I customize rules?
  - Yes. Rules live in this repo (Rust), compiled to WASM, and can be extended.

## Related work and inspiration

- Vibe MCP emphasizes unified AI rules and clean JSON designed for AI consumption. Shellfirm MCP shares the same spirit of AI‑friendly, structured outputs and MCP compliance ([README source](https://raw.githubusercontent.com/Jinjos/vibe-mcp/refs/heads/main/README.md)).
- Playwright provides resilient, fast, cross‑browser automation and headless execution used for the challenge UI ([README source](https://raw.githubusercontent.com/microsoft/playwright/refs/heads/main/README.md)).

## Roadmap

- More challenge templates and themes
- Per‑workspace policies and profiles
- Audit logs and approvals history

## Contributing

We welcome contributions! See `CONTRIBUTING.md` for guidelines, developer setup, and user guidance.
