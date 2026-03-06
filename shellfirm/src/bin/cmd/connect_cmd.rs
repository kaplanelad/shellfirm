use std::fs;
use std::path::PathBuf;

use clap::{Arg, ArgAction, ArgMatches, Command};
use console::style;
use shellfirm::error::Result;

// ---------------------------------------------------------------------------
// AI Tool Provider trait
// ---------------------------------------------------------------------------

#[allow(dead_code)]
trait AiToolProvider {
    fn name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn config_path(&self) -> Option<PathBuf>;
    fn supports_hooks(&self) -> bool;
    fn supports_mcp(&self) -> bool;
    fn is_hooks_installed(&self, config: &serde_json::Value) -> bool;
    fn is_mcp_installed(&self, config: &serde_json::Value) -> bool;
    fn install_hooks(&self, config: &mut serde_json::Value);
    fn install_mcp(&self, config: &mut serde_json::Value);
    fn uninstall(&self, config: &mut serde_json::Value);
}

// ---------------------------------------------------------------------------
// Claude Code provider
// ---------------------------------------------------------------------------

struct ClaudeCodeProvider;

impl ClaudeCodeProvider {
    const HOOK_COMMAND: &'static str = "shellfirm check --stdin --format json --exit-code";

    /// Check if a `PreToolUse` entry contains a shellfirm hook.
    fn entry_is_shellfirm(entry: &serde_json::Value) -> bool {
        entry
            .get("hooks")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|hooks_arr| {
                hooks_arr.iter().any(|h| {
                    h.get("command")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|s| s.contains("shellfirm"))
                })
            })
    }
}

impl AiToolProvider for ClaudeCodeProvider {
    fn name(&self) -> &'static str {
        "claude-code"
    }

    fn display_name(&self) -> &'static str {
        "Claude Code"
    }

    fn config_path(&self) -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".claude").join("settings.json"))
    }

    fn supports_hooks(&self) -> bool {
        true
    }

    fn supports_mcp(&self) -> bool {
        true
    }

    fn is_hooks_installed(&self, config: &serde_json::Value) -> bool {
        config
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|arr| arr.iter().any(Self::entry_is_shellfirm))
    }

    fn is_mcp_installed(&self, config: &serde_json::Value) -> bool {
        is_standard_mcp_installed(config)
    }

    fn install_hooks(&self, config: &mut serde_json::Value) {
        let hooks = config
            .as_object_mut()
            .unwrap()
            .entry("hooks")
            .or_insert_with(|| serde_json::json!({}));
        let pre_tool_use = hooks
            .as_object_mut()
            .unwrap()
            .entry("PreToolUse")
            .or_insert_with(|| serde_json::json!([]));
        let arr = pre_tool_use.as_array_mut().unwrap();

        // Don't add duplicate (check both new and legacy formats)
        if arr.iter().any(Self::entry_is_shellfirm) {
            return;
        }

        arr.push(serde_json::json!({
            "matcher": "Bash",
            "hooks": [{
                "type": "command",
                "command": Self::HOOK_COMMAND
            }]
        }));
    }

    fn install_mcp(&self, config: &mut serde_json::Value) {
        install_standard_mcp(config);
    }

    fn uninstall(&self, config: &mut serde_json::Value) {
        // Remove hooks (both new and legacy formats)
        if let Some(pre_tool_use) = config
            .get_mut("hooks")
            .and_then(|h| h.get_mut("PreToolUse"))
            .and_then(serde_json::Value::as_array_mut)
        {
            pre_tool_use.retain(|entry| !Self::entry_is_shellfirm(entry));
        }

        // Remove MCP server
        uninstall_standard_mcp(config);
    }
}

// ---------------------------------------------------------------------------
// Shared MCP helpers (standard mcpServers format)
// ---------------------------------------------------------------------------

const MCP_SERVER_COMMAND: &str = "shellfirm";
const MCP_SERVER_ARGS: &[&str] = &["mcp"];

fn is_standard_mcp_installed(config: &serde_json::Value) -> bool {
    config
        .get("mcpServers")
        .and_then(|m| m.get("shellfirm"))
        .is_some()
}

fn install_standard_mcp(config: &mut serde_json::Value) {
    let servers = config
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    servers.as_object_mut().unwrap().insert(
        "shellfirm".to_string(),
        serde_json::json!({
            "command": MCP_SERVER_COMMAND,
            "args": MCP_SERVER_ARGS
        }),
    );
}

fn uninstall_standard_mcp(config: &mut serde_json::Value) {
    if let Some(servers) = config
        .get_mut("mcpServers")
        .and_then(serde_json::Value::as_object_mut)
    {
        servers.remove("shellfirm");
    }
}

// ---------------------------------------------------------------------------
// Cursor provider (project-level .cursor/mcp.json)
// ---------------------------------------------------------------------------

struct CursorProvider;

impl AiToolProvider for CursorProvider {
    fn name(&self) -> &'static str {
        "cursor"
    }

    fn display_name(&self) -> &'static str {
        "Cursor"
    }

    fn config_path(&self) -> Option<PathBuf> {
        Some(
            std::env::current_dir()
                .unwrap_or_default()
                .join(".cursor")
                .join("mcp.json"),
        )
    }

    fn supports_hooks(&self) -> bool {
        false
    }

    fn supports_mcp(&self) -> bool {
        true
    }

    fn is_hooks_installed(&self, _config: &serde_json::Value) -> bool {
        false
    }

    fn is_mcp_installed(&self, config: &serde_json::Value) -> bool {
        is_standard_mcp_installed(config)
    }

    fn install_hooks(&self, _config: &mut serde_json::Value) {}

    fn install_mcp(&self, config: &mut serde_json::Value) {
        install_standard_mcp(config);
    }

    fn uninstall(&self, config: &mut serde_json::Value) {
        uninstall_standard_mcp(config);
    }
}

// ---------------------------------------------------------------------------
// Windsurf provider (~/.codeium/windsurf/mcp_config.json)
// ---------------------------------------------------------------------------

struct WindsurfProvider;

impl AiToolProvider for WindsurfProvider {
    fn name(&self) -> &'static str {
        "windsurf"
    }

    fn display_name(&self) -> &'static str {
        "Windsurf"
    }

    fn config_path(&self) -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".codeium").join("windsurf").join("mcp_config.json"))
    }

    fn supports_hooks(&self) -> bool {
        false
    }

    fn supports_mcp(&self) -> bool {
        true
    }

    fn is_hooks_installed(&self, _config: &serde_json::Value) -> bool {
        false
    }

    fn is_mcp_installed(&self, config: &serde_json::Value) -> bool {
        is_standard_mcp_installed(config)
    }

    fn install_hooks(&self, _config: &mut serde_json::Value) {}

    fn install_mcp(&self, config: &mut serde_json::Value) {
        install_standard_mcp(config);
    }

    fn uninstall(&self, config: &mut serde_json::Value) {
        uninstall_standard_mcp(config);
    }
}

// ---------------------------------------------------------------------------
// Zed provider (~/.config/zed/settings.json) — uses context_servers format
// ---------------------------------------------------------------------------

struct ZedProvider;

impl AiToolProvider for ZedProvider {
    fn name(&self) -> &'static str {
        "zed"
    }

    fn display_name(&self) -> &'static str {
        "Zed"
    }

    fn config_path(&self) -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".config").join("zed").join("settings.json"))
    }

    fn supports_hooks(&self) -> bool {
        false
    }

    fn supports_mcp(&self) -> bool {
        true
    }

    fn is_hooks_installed(&self, _config: &serde_json::Value) -> bool {
        false
    }

    fn is_mcp_installed(&self, config: &serde_json::Value) -> bool {
        config
            .get("context_servers")
            .and_then(|m| m.get("shellfirm"))
            .is_some()
    }

    fn install_hooks(&self, _config: &mut serde_json::Value) {}

    fn install_mcp(&self, config: &mut serde_json::Value) {
        let servers = config
            .as_object_mut()
            .unwrap()
            .entry("context_servers")
            .or_insert_with(|| serde_json::json!({}));
        servers.as_object_mut().unwrap().insert(
            "shellfirm".to_string(),
            serde_json::json!({
                "command": {
                    "path": MCP_SERVER_COMMAND,
                    "args": MCP_SERVER_ARGS
                },
                "settings": {}
            }),
        );
    }

    fn uninstall(&self, config: &mut serde_json::Value) {
        if let Some(servers) = config
            .get_mut("context_servers")
            .and_then(serde_json::Value::as_object_mut)
        {
            servers.remove("shellfirm");
        }
    }
}

// ---------------------------------------------------------------------------
// Cline provider (VS Code extension settings)
// ---------------------------------------------------------------------------

struct ClineProvider;

impl AiToolProvider for ClineProvider {
    fn name(&self) -> &'static str {
        "cline"
    }

    fn display_name(&self) -> &'static str {
        "Cline"
    }

    fn config_path(&self) -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            dirs::home_dir().map(|h| {
                h.join("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json")
            })
        }
        #[cfg(target_os = "linux")]
        {
            dirs::home_dir().map(|h| {
                h.join(".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json")
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }

    fn supports_hooks(&self) -> bool {
        false
    }

    fn supports_mcp(&self) -> bool {
        true
    }

    fn is_hooks_installed(&self, _config: &serde_json::Value) -> bool {
        false
    }

    fn is_mcp_installed(&self, config: &serde_json::Value) -> bool {
        is_standard_mcp_installed(config)
    }

    fn install_hooks(&self, _config: &mut serde_json::Value) {}

    fn install_mcp(&self, config: &mut serde_json::Value) {
        install_standard_mcp(config);
    }

    fn uninstall(&self, config: &mut serde_json::Value) {
        uninstall_standard_mcp(config);
    }
}

// ---------------------------------------------------------------------------
// Provider registry
// ---------------------------------------------------------------------------

fn get_provider(name: &str) -> Option<Box<dyn AiToolProvider>> {
    match name {
        "claude-code" => Some(Box::new(ClaudeCodeProvider)),
        "cursor" => Some(Box::new(CursorProvider)),
        "windsurf" => Some(Box::new(WindsurfProvider)),
        "zed" => Some(Box::new(ZedProvider)),
        "cline" => Some(Box::new(ClineProvider)),
        _ => None,
    }
}

const SUPPORTED_PROVIDERS: &str = "claude-code, cursor, windsurf, zed, cline";

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn dry_run_arg() -> Arg {
    Arg::new("dry-run")
        .long("dry-run")
        .help("Preview changes without writing anything")
        .action(ArgAction::SetTrue)
}

fn uninstall_arg() -> Arg {
    Arg::new("uninstall")
        .long("uninstall")
        .help("Remove all shellfirm config")
        .action(ArgAction::SetTrue)
}

fn mcp_only_subcommand(name: &'static str, about: &'static str) -> Command {
    Command::new(name)
        .about(about)
        .arg(dry_run_arg())
        .arg(uninstall_arg())
}

pub fn command() -> Command {
    Command::new("connect")
        .about("Connect AI tool integrations (hooks + MCP)")
        .arg_required_else_help(true)
        .subcommand(
            Command::new("claude-code")
                .about("Connect Claude Code integration (hooks + MCP)")
                .arg(
                    Arg::new("hooks-only")
                        .long("hooks-only")
                        .help("Install hooks only (no MCP)")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("mcp-only"),
                )
                .arg(
                    Arg::new("mcp-only")
                        .long("mcp-only")
                        .help("Install MCP only (no hooks)")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("hooks-only"),
                )
                .arg(dry_run_arg())
                .arg(uninstall_arg()),
        )
        .subcommand(mcp_only_subcommand(
            "cursor",
            "Connect Cursor integration (MCP)",
        ))
        .subcommand(mcp_only_subcommand(
            "windsurf",
            "Connect Windsurf integration (MCP)",
        ))
        .subcommand(mcp_only_subcommand("zed", "Connect Zed integration (MCP)"))
        .subcommand(mcp_only_subcommand(
            "cline",
            "Connect Cline integration (MCP)",
        ))
}

pub fn run(matches: &ArgMatches) -> Result<shellfirm::CmdExit> {
    let (provider_name, sub_matches) = matches.subcommand().unwrap();
    let Some(provider) = get_provider(provider_name) else {
        return Ok(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some(format!(
                "Unknown AI tool: {provider_name}. Supported: {SUPPORTED_PROVIDERS}"
            )),
        });
    };

    let dry_run = sub_matches.get_flag("dry-run");
    let uninstall = sub_matches.get_flag("uninstall");
    // hooks-only/mcp-only flags only exist on providers that support hooks
    let hooks_only = sub_matches
        .try_get_one::<bool>("hooks-only")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false);
    let mcp_only = sub_matches
        .try_get_one::<bool>("mcp-only")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false);

    if hooks_only && !provider.supports_hooks() {
        return Ok(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some(format!(
                "{} does not support hooks. Use `shellfirm connect {}` for MCP setup.",
                provider.display_name(),
                provider.name()
            )),
        });
    }

    let install_hooks = !mcp_only && provider.supports_hooks();
    let install_mcp = !hooks_only && provider.supports_mcp();

    let Some(config_path) = provider.config_path() else {
        return Ok(shellfirm::CmdExit {
            code: 1,
            message: Some(format!(
                "Could not determine config path for {}. Is your home directory set?",
                provider.display_name()
            )),
        });
    };

    // Load existing config or start with empty object
    let mut config = if config_path.exists() {
        let content = fs::read_to_string(&config_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    if uninstall {
        return run_uninstall(&*provider, &config_path, &mut config, dry_run);
    }

    run_install(
        &*provider,
        &config_path,
        &mut config,
        install_hooks,
        install_mcp,
        dry_run,
    )
}

fn run_install(
    provider: &dyn AiToolProvider,
    config_path: &PathBuf,
    config: &mut serde_json::Value,
    install_hooks: bool,
    install_mcp: bool,
    dry_run: bool,
) -> Result<shellfirm::CmdExit> {
    println!(
        "\n{}",
        style(format!(
            "shellfirm — connecting {} integration",
            provider.display_name()
        ))
        .bold()
    );
    println!();

    let hooks_already = provider.is_hooks_installed(config);
    let mcp_already = provider.is_mcp_installed(config);

    if install_hooks && !hooks_already {
        provider.install_hooks(config);
    }
    if install_mcp && !mcp_already {
        provider.install_mcp(config);
    }

    // Display status
    if install_hooks {
        let (icon, note) = if hooks_already {
            (style("✓").dim(), style("(already installed)").dim())
        } else {
            (
                style("✓").green().bold(),
                style("(pre-tool-use safety net)").cyan(),
            )
        };
        println!(
            "  {icon} {:<8} → {} {note}",
            "Hooks",
            style(config_path.display()).cyan()
        );
    }
    if install_mcp {
        let (icon, note) = if mcp_already {
            (style("✓").dim(), style("(already installed)").dim())
        } else {
            (
                style("✓").green().bold(),
                style("(on-demand analysis tools)").cyan(),
            )
        };
        println!(
            "  {icon} {:<8} → {} {note}",
            "MCP",
            style(config_path.display()).cyan()
        );
    }

    println!();

    if dry_run {
        let json = serde_json::to_string_pretty(config).unwrap_or_else(|_| "{}".to_string());
        println!("Would write to {}:\n{json}", config_path.display());
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("No changes made. Run without --dry-run to apply.".to_string()),
        });
    }

    // Don't write if nothing changed
    if (!install_hooks || hooks_already) && (!install_mcp || mcp_already) {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "{} is already protected by shellfirm.",
                provider.display_name()
            )),
        });
    }

    write_config(config_path, config)?;

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "{} is now protected by shellfirm.",
            provider.display_name()
        )),
    })
}

fn run_uninstall(
    provider: &dyn AiToolProvider,
    config_path: &PathBuf,
    config: &mut serde_json::Value,
    dry_run: bool,
) -> Result<shellfirm::CmdExit> {
    let hooks_installed = provider.is_hooks_installed(config);
    let mcp_installed = provider.is_mcp_installed(config);

    if !hooks_installed && !mcp_installed {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "No shellfirm config found in {}.",
                provider.display_name()
            )),
        });
    }

    provider.uninstall(config);

    println!(
        "\n{}",
        style(format!(
            "shellfirm — removing {} integration",
            provider.display_name()
        ))
        .bold()
    );
    println!();

    if hooks_installed {
        println!("  {} {:<8} removed", style("✓").green().bold(), "Hooks");
    }
    if mcp_installed {
        println!("  {} {:<8} removed", style("✓").green().bold(), "MCP");
    }
    println!();

    if dry_run {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("No changes made. Run without --dry-run to apply.".to_string()),
        });
    }

    write_config(config_path, config)?;

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "shellfirm removed from {}.",
            provider.display_name()
        )),
    })
}

fn write_config(path: &PathBuf, config: &serde_json::Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| shellfirm::error::Error::Other(e.to_string()))?;
    fs::write(path, format!("{json}\n"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_config() -> serde_json::Value {
        serde_json::json!({})
    }

    fn config_with_existing_stuff() -> serde_json::Value {
        serde_json::json!({
            "permissions": {"allow": ["Read"]},
            "mcpServers": {
                "other-tool": {"command": "other"}
            }
        })
    }

    #[test]
    fn install_hooks_adds_pre_tool_use() {
        let provider = ClaudeCodeProvider;
        let mut config = empty_config();
        provider.install_hooks(&mut config);

        assert!(provider.is_hooks_installed(&config));
        let arr = config["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        // matcher is a regex string
        assert_eq!(arr[0]["matcher"], "Bash");
        // hooks is an array of command objects
        let hooks_arr = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(hooks_arr.len(), 1);
        assert_eq!(hooks_arr[0]["type"], "command");
        assert!(hooks_arr[0]["command"]
            .as_str()
            .unwrap()
            .contains("shellfirm"));
    }

    #[test]
    fn install_mcp_adds_server() {
        let provider = ClaudeCodeProvider;
        let mut config = empty_config();
        provider.install_mcp(&mut config);

        assert!(provider.is_mcp_installed(&config));
        assert_eq!(config["mcpServers"]["shellfirm"]["command"], "shellfirm");
        assert_eq!(config["mcpServers"]["shellfirm"]["args"][0], "mcp");
    }

    #[test]
    fn install_preserves_existing_config() {
        let provider = ClaudeCodeProvider;
        let mut config = config_with_existing_stuff();
        provider.install_hooks(&mut config);
        provider.install_mcp(&mut config);

        // Existing stuff preserved
        assert!(config["permissions"]["allow"].as_array().unwrap().len() == 1);
        assert!(config["mcpServers"]["other-tool"]["command"] == "other");
        // New stuff added
        assert!(provider.is_hooks_installed(&config));
        assert!(provider.is_mcp_installed(&config));
    }

    #[test]
    fn install_hooks_is_idempotent() {
        let provider = ClaudeCodeProvider;
        let mut config = empty_config();
        provider.install_hooks(&mut config);
        provider.install_hooks(&mut config);

        let arr = config["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "should not duplicate hook entry");
    }

    #[test]
    fn uninstall_removes_hooks_and_mcp() {
        let provider = ClaudeCodeProvider;
        let mut config = config_with_existing_stuff();
        provider.install_hooks(&mut config);
        provider.install_mcp(&mut config);

        assert!(provider.is_hooks_installed(&config));
        assert!(provider.is_mcp_installed(&config));

        provider.uninstall(&mut config);

        assert!(!provider.is_hooks_installed(&config));
        assert!(!provider.is_mcp_installed(&config));
        // Other config preserved
        assert!(config["permissions"]["allow"].as_array().unwrap().len() == 1);
        assert!(config["mcpServers"]["other-tool"]["command"] == "other");
    }

    #[test]
    fn uninstall_noop_when_not_installed() {
        let provider = ClaudeCodeProvider;
        let mut config = config_with_existing_stuff();
        let before = config.clone();
        provider.uninstall(&mut config);
        assert_eq!(config, before);
    }

    #[test]
    fn detection_on_empty_config() {
        let provider = ClaudeCodeProvider;
        let config = empty_config();
        assert!(!provider.is_hooks_installed(&config));
        assert!(!provider.is_mcp_installed(&config));
    }

    #[test]
    fn config_path_resolves() {
        let provider = ClaudeCodeProvider;
        let path = provider.config_path();
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.ends_with("settings.json"));
        assert!(p.to_string_lossy().contains(".claude"));
    }

    #[test]
    fn write_and_read_config_roundtrip() {
        let dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let path = dir.root.join(".claude").join("settings.json");

        let config = serde_json::json!({
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hook": "shellfirm check --stdin"}]}
        });

        write_config(&path, &config).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let loaded: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded["hooks"]["PreToolUse"][0]["matcher"], "Bash");
    }

    // -- Cursor provider tests --

    #[test]
    fn cursor_install_mcp() {
        let provider = CursorProvider;
        let mut config = empty_config();
        provider.install_mcp(&mut config);

        assert!(provider.is_mcp_installed(&config));
        assert_eq!(config["mcpServers"]["shellfirm"]["command"], "shellfirm");
        assert_eq!(config["mcpServers"]["shellfirm"]["args"][0], "mcp");
    }

    #[test]
    fn cursor_does_not_support_hooks() {
        let provider = CursorProvider;
        assert!(!provider.supports_hooks());
        assert!(provider.supports_mcp());
    }

    #[test]
    fn cursor_config_path_is_project_level() {
        let provider = CursorProvider;
        let path = provider.config_path().unwrap();
        assert!(path.ends_with(".cursor/mcp.json"));
    }

    // -- Windsurf provider tests --

    #[test]
    fn windsurf_install_mcp() {
        let provider = WindsurfProvider;
        let mut config = empty_config();
        provider.install_mcp(&mut config);

        assert!(provider.is_mcp_installed(&config));
        assert_eq!(config["mcpServers"]["shellfirm"]["command"], "shellfirm");
    }

    #[test]
    fn windsurf_config_path() {
        let provider = WindsurfProvider;
        let path = provider.config_path().unwrap();
        assert!(path
            .to_string_lossy()
            .contains(".codeium/windsurf/mcp_config.json"));
    }

    // -- Zed provider tests --

    #[test]
    fn zed_install_uses_context_servers() {
        let provider = ZedProvider;
        let mut config = empty_config();
        provider.install_mcp(&mut config);

        assert!(provider.is_mcp_installed(&config));
        // Zed uses context_servers, not mcpServers
        assert!(config.get("mcpServers").is_none());
        assert_eq!(
            config["context_servers"]["shellfirm"]["command"]["path"],
            "shellfirm"
        );
        assert_eq!(
            config["context_servers"]["shellfirm"]["command"]["args"][0],
            "mcp"
        );
        assert!(config["context_servers"]["shellfirm"]["settings"]
            .as_object()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn zed_uninstall_removes_context_server() {
        let provider = ZedProvider;
        let mut config = serde_json::json!({
            "context_servers": {
                "shellfirm": {"command": {"path": "shellfirm", "args": ["mcp"]}, "settings": {}},
                "other": {"command": {"path": "other"}}
            }
        });

        provider.uninstall(&mut config);

        assert!(!provider.is_mcp_installed(&config));
        assert!(config["context_servers"]["other"]["command"]["path"] == "other");
    }

    #[test]
    fn zed_config_path() {
        let provider = ZedProvider;
        let path = provider.config_path().unwrap();
        assert!(path.to_string_lossy().contains(".config/zed/settings.json"));
    }

    // -- Cline provider tests --

    #[test]
    fn cline_install_mcp() {
        let provider = ClineProvider;
        let mut config = empty_config();
        provider.install_mcp(&mut config);

        assert!(provider.is_mcp_installed(&config));
        assert_eq!(config["mcpServers"]["shellfirm"]["command"], "shellfirm");
    }

    #[test]
    fn cline_config_path() {
        let provider = ClineProvider;
        let path = provider.config_path();
        // May be None on unsupported platforms
        if let Some(p) = path {
            assert!(p.to_string_lossy().contains("cline_mcp_settings.json"));
        }
    }

    // -- Cross-provider tests --

    #[test]
    fn all_providers_preserve_existing_config() {
        let providers: Vec<Box<dyn AiToolProvider>> = vec![
            Box::new(CursorProvider),
            Box::new(WindsurfProvider),
            Box::new(ZedProvider),
            Box::new(ClineProvider),
        ];

        for provider in &providers {
            let mut config = serde_json::json!({
                "existing_key": "existing_value",
                "mcpServers": {"other-tool": {"command": "other"}}
            });
            provider.install_mcp(&mut config);
            assert_eq!(
                config["existing_key"],
                "existing_value",
                "{} should preserve existing config",
                provider.name()
            );
            assert_eq!(
                config["mcpServers"]["other-tool"]["command"],
                "other",
                "{} should preserve other MCP servers",
                provider.name()
            );
        }
    }

    #[test]
    fn all_providers_are_idempotent() {
        let providers: Vec<Box<dyn AiToolProvider>> = vec![
            Box::new(CursorProvider),
            Box::new(WindsurfProvider),
            Box::new(ClineProvider),
        ];

        for provider in &providers {
            let mut config = empty_config();
            provider.install_mcp(&mut config);
            let after_first = config.clone();
            provider.install_mcp(&mut config);
            assert_eq!(
                config,
                after_first,
                "{} install should be idempotent",
                provider.name()
            );
        }
    }

    #[test]
    fn zed_install_is_idempotent() {
        let provider = ZedProvider;
        let mut config = empty_config();
        provider.install_mcp(&mut config);
        let after_first = config.clone();
        provider.install_mcp(&mut config);
        assert_eq!(config, after_first);
    }

    #[test]
    fn provider_registry_resolves_all() {
        for name in ["claude-code", "cursor", "windsurf", "zed", "cline"] {
            assert!(
                get_provider(name).is_some(),
                "provider '{name}' should be registered"
            );
        }
        assert!(get_provider("unknown").is_none());
    }
}
