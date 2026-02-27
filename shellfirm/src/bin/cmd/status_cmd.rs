use clap::{crate_version, ArgMatches, Command};
use shellfirm::{
    checks::Check,
    context,
    env::{Environment, RealEnvironment},
    policy, Config, Settings,
};

pub fn command() -> Command {
    Command::new("status")
        .about("Show shellfirm installation status and current configuration overview")
}

pub fn run(
    _matches: &ArgMatches,
    config: &Config,
    settings: &Settings,
    checks: &[Check],
) -> shellfirm::CmdExit {
    let env = RealEnvironment;

    // Version
    let version = crate_version!();

    // Config path
    let config_path = config.setting_file_path.display();

    // Active groups
    let groups = if settings.enabled_groups.is_empty() {
        "(none)".to_string()
    } else {
        format!(
            "{} ({})",
            settings.enabled_groups.join(", "),
            settings.enabled_groups.len()
        )
    };

    // Checks count
    let active_count = checks.len();

    // Custom checks
    let custom_checks_dir = config.custom_checks_dir();
    let custom_count = shellfirm::checks::load_custom_checks(&custom_checks_dir)
        .map(|c| c.len())
        .unwrap_or(0);

    // Context detection
    let runtime_ctx = context::detect(&env, &settings.context);

    let ssh_status = if runtime_ctx.is_ssh { "yes" } else { "no" };
    let root_status = if runtime_ctx.is_root { "yes" } else { "no" };
    let branch_status = runtime_ctx
        .git_branch
        .as_deref()
        .unwrap_or("(not in a git repo)");
    let k8s_status = runtime_ctx
        .k8s_context
        .as_deref()
        .unwrap_or("(not detected)");

    // Policy detection
    let cwd = env.current_dir().unwrap_or_default();
    let policy_status = match policy::discover(&env, &cwd) {
        Some(_) => "found (valid)".to_string(),
        None => "not found".to_string(),
    };

    // MCP feature status
    let mcp_status = if cfg!(feature = "mcp") {
        "available (run `shellfirm mcp` to start)"
    } else {
        "not compiled (build with --features mcp)"
    };

    // LLM feature status
    let llm_status = if cfg!(feature = "llm") {
        let has_key = env.var("SHELLFIRM_LLM_API_KEY").is_some()
            || env.var("ANTHROPIC_API_KEY").is_some()
            || env.var("OPENAI_API_KEY").is_some();
        if has_key {
            settings.llm.as_ref().map_or_else(
                || "available (no API key configured, LLM not configured)".to_string(),
                |llm| format!("available (provider: {})", llm.provider),
            )
        } else {
            "available (no API key configured)".to_string()
        }
    } else {
        "not compiled (build with --features llm)".to_string()
    };

    let output = format!(
        "\
shellfirm v{version}

Configuration:
  Config file:         {config_path}
  Challenge:           {challenge}
  Active groups:       {groups}
  Active checks:       {active_count}
  Custom checks:       {custom_count}
  Audit:               {audit}

Context (current environment):
  SSH session:         {ssh_status}
  Root user:           {root_status}
  Git branch:          {branch_status}
  Kubernetes context:  {k8s_status}
  Risk level:          {risk_level:?}

Policy:
  .shellfirm.yaml:     {policy_status}

AI Features:
  Agent guardrails:    auto-deny >= {auto_deny_sev}
  MCP server:          {mcp_status}
  LLM analysis:        {llm_status}",
        challenge = settings.challenge,
        audit = if settings.audit_enabled {
            "enabled"
        } else {
            "disabled"
        },
        risk_level = runtime_ctx.risk_level,
        auto_deny_sev = settings.agent.auto_deny_severity,
    );

    println!("{output}");
    shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    }
}
