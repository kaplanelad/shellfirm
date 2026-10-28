use clap::{Arg, ArgMatches, Command};
use shellfirm::error::Result;
use shellfirm::{
    agent, checks::Check, env::Environment, env::RealEnvironment, mcp::McpServer, Config, Settings,
};

pub fn command() -> Command {
    Command::new("mcp")
        .about("Start the MCP (Model Context Protocol) server for AI agent integration")
        .long_about(
            "Start a JSON-RPC 2.0 server over stdio (newline-delimited) that exposes shellfirm \
            as an MCP tool server with the tools check_command, suggest_alternative, get_policy \
            and explain_risk.\n\n\
            MCP tools are advisory: the agent decides whether to call them. To have commands \
            intercepted automatically, also install the hook (`shellfirm connect claude-code`).\n\n\
            Register it with Claude Code (user scope, stored in ~/.claude.json):\n  \
            shellfirm connect claude-code --mcp-only\n  \
            # or: claude mcp add --scope user shellfirm -- shellfirm mcp\n\n\
            Manual entry (~/.claude.json, project .mcp.json, ~/.cursor/mcp.json, ...):\n  \
            {\"mcpServers\": {\"shellfirm\": {\"type\": \"stdio\", \"command\": \"shellfirm\", \"args\": [\"mcp\"]}}}\n\n\
            check_command decisions (ask/deny) are written to the audit log when auditing is enabled. \
            An invalid project policy makes every check_command answer at least `ask`.",
        )
        .arg(
            Arg::new("config-dir")
                .long("config-dir")
                .value_name("DIR")
                .help("Use the shellfirm configuration in DIR (written by `shellfirm connect` so a redirected HOME/XDG_CONFIG_HOME is not followed)"),
        )
}

pub fn run(
    matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
    config: &Config,
) -> Result<shellfirm::CmdExit> {
    let env = RealEnvironment;
    let session_id = uuid::Uuid::new_v4().to_string();

    tracing::info!("Starting shellfirm MCP server (session: {session_id})");

    // A recorded configuration directory wins over HOME/XDG_CONFIG_HOME. A
    // directory that does not exist yet (recorded before the first setting
    // was saved) means defaults; anything else is reported.
    let requested = matches.get_one::<String>("config-dir");
    if let Some(d) = requested {
        let p = std::path::Path::new(d);
        if p.exists() && !p.is_dir() {
            eprintln!(
                "shellfirm: warning: --config-dir {d} is not a directory; using the default configuration"
            );
        }
    }
    let pinned = match requested.filter(|d| std::path::Path::new(d).is_dir()) {
        Some(dir) => {
            let pinned_config = Config::new(Some(dir))?;
            let cwd = env.current_dir().unwrap_or_default();
            let inputs = agent::load_agent_inputs(&pinned_config, &env, &cwd)?;
            Some((pinned_config, inputs))
        }
        None => None,
    };
    let (settings, checks, config) = pinned
        .as_ref()
        .map_or((settings, checks, config), |(c, i)| {
            (&i.settings, i.checks.as_slice(), c)
        });

    let server =
        McpServer::new(settings, checks, &env, session_id).with_audit_path(config.audit_log_path());
    server.run_stdio()?;

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}
