# Shellfirm MCP — Developer Guide (no LLM required)

This guide shows how to build, run, and exercise the MCP server locally without integrating it into an IDE or LLM.

## 1) Install and build

```bash
cd mcp
npm install
npm run build
```

## 2) Interact via MCP Inspector (recommended)

Use the MCP Inspector to connect to any stdio MCP server and call its tools:

```bash
npx @modelcontextprotocol/inspector
```

In the Inspector UI:

- Click "Start a server"
- Command: `node`
- Args (from mcp/ dir): `lib/index.js --challenge confirm --severity critical,high,medium`
- Connect

Once connected you can:

- List tools (`secure_shell_execute`, `validate_shell_command`)
- Call `validate_shell_command` (safety check only):

* `command`: `rm -r example && echo "test" || ls && terraform apply -auto-approve`
* `working_directory`: `.`
* `explanation`: "Delete the example folder"
