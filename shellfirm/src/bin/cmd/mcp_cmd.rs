use anyhow::Result;
use clap::{ArgMatches, Command};
use shellfirm::{checks::Check, env::RealEnvironment, mcp::McpServer, Config, Settings};

pub fn command() -> Command {
    Command::new("mcp")
        .about("Start the MCP (Model Context Protocol) server for AI agent integration")
        .long_about(
            "Start a JSON-RPC 2.0 server over stdio that exposes shellfirm as an MCP tool server.\n\
            AI coding agents (Claude Code, Cursor, etc.) can connect to check commands before \
            executing them.\n\n\
            Configure in Claude Code's ~/.claude.json:\n\
            {\"mcpServers\": {\"shellfirm\": {\"command\": \"shellfirm\", \"args\": [\"mcp\"]}}}"
        )
}

pub fn run(
    _matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
    _config: &Config,
) -> Result<shellfirm::CmdExit> {
    let env = RealEnvironment;
    let session_id = uuid::Uuid::new_v4().to_string();

    log::info!("Starting shellfirm MCP server (session: {session_id})");

    let server = McpServer::new(settings, checks, &env, session_id);
    server.run_stdio()?;

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}
