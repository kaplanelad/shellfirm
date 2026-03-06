use std::fmt::Write;
use std::io::Read as _;

use clap::{Arg, ArgAction, ArgMatches, Command};
use shellfirm::agent::{self, RiskAssessment};
use shellfirm::error::Result;
use shellfirm::{
    checks::{self, Check},
    env::RealEnvironment,
    Settings,
};

/// Exit code used by hooks to signal "block this command".
const HOOK_BLOCK_EXIT: i32 = 2;

pub fn command() -> Command {
    Command::new("check")
        .about("Test commands against shellfirm checks or list available checks")
        .arg_required_else_help(true)
        .arg(
            Arg::new("command")
                .short('c')
                .long("command")
                .help("Command to test (dry-run, no challenge prompted)")
                .conflicts_with_all(["list", "stdin"]),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .help("Read command from stdin JSON ({\"command\": \"...\"})")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["command", "list"]),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .help("Output format: text (default) or json")
                .value_parser(["text", "json"])
                .default_value("text"),
        )
        .arg(
            Arg::new("exit-code")
                .long("exit-code")
                .help("Exit 0 if safe, exit 2 if risky/blocked (for hooks)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("list")
                .short('l')
                .long("list")
                .help("List all active checks")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["command", "stdin"]),
        )
        .arg(
            Arg::new("group")
                .short('g')
                .long("group")
                .help("Filter checks by group (used with --list)")
                .requires("list"),
        )
        .arg(
            Arg::new("all")
                .short('a')
                .long("all")
                .help("Include checks from disabled groups (used with --list)")
                .action(ArgAction::SetTrue)
                .requires("list"),
        )
}

pub fn run(
    matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
) -> Result<shellfirm::CmdExit> {
    if matches.get_flag("list") {
        let group_filter = matches.get_one::<String>("group").map(String::as_str);
        let show_all = matches.get_flag("all");
        return run_list(settings, checks, group_filter, show_all);
    }

    let format = matches
        .get_one::<String>("format")
        .map_or("text", String::as_str);
    let exit_code_mode = matches.get_flag("exit-code");

    // Resolve the command string: --command or --stdin
    let command_str = if matches.get_flag("stdin") {
        match read_command_from_stdin() {
            Ok(cmd) => cmd,
            Err(msg) => {
                return Ok(shellfirm::CmdExit {
                    code: exitcode::USAGE,
                    message: Some(msg),
                });
            }
        }
    } else if let Some(cmd) = matches.get_one::<String>("command") {
        cmd.clone()
    } else {
        return Ok(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some(
                "Provide --command or --stdin or --list. See: shellfirm check --help".to_string(),
            ),
        });
    };

    let env = RealEnvironment;
    let agent_config = settings.agent.clone();
    let assessment = agent::assess_command(&command_str, settings, checks, &env, &agent_config)?;

    let (exit, message) = match format {
        "json" if exit_code_mode => {
            // Claude Code hook protocol: always exit 0, use hookSpecificOutput
            // to communicate allow/deny decisions via stdout JSON.
            let hook_output = build_hook_output(&assessment);
            let json = serde_json::to_string_pretty(&hook_output)
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
            println!("{json}");
            (exitcode::OK, None)
        }
        "json" => {
            let json = serde_json::to_string_pretty(&assessment)
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
            println!("{json}");
            (exitcode::OK, None)
        }
        _ => {
            let exit = if exit_code_mode && !assessment.allowed {
                HOOK_BLOCK_EXIT
            } else {
                exitcode::OK
            };
            (exit, Some(format_text_output(&assessment)))
        }
    };

    Ok(shellfirm::CmdExit {
        code: exit,
        message,
    })
}

/// Build Claude Code hook-protocol output wrapping a `RiskAssessment`.
///
/// Claude Code hooks expect exit 0 with stdout JSON containing
/// `hookSpecificOutput.permissionDecision` ("allow" or "deny").
fn build_hook_output(assessment: &RiskAssessment) -> serde_json::Value {
    let decision = if assessment.allowed { "allow" } else { "deny" };

    let reason = if assessment.allowed {
        "Command passed shellfirm checks".to_string()
    } else {
        let mut parts: Vec<String> = Vec::new();
        for m in &assessment.matched_rules {
            let mut line = format!("[{}] [{}] {}", m.id, m.severity, m.description);
            if let Some(ref scope) = m.blast_radius_scope {
                let detail = m.blast_radius_detail.as_deref().unwrap_or("");
                let _ = write!(line, " — Blast radius: [{scope}] {detail}");
            }
            parts.push(line);
        }
        if let Some(ref denial) = assessment.denial_reason {
            parts.push(format!("BLOCKED: {denial}"));
        }
        for alt in &assessment.alternatives {
            let mut line = format!("Safe alternative: {}", alt.command);
            if let Some(ref info) = alt.explanation {
                let _ = write!(line, " ({info})");
            }
            parts.push(line);
        }
        parts.join("\n")
    };

    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    })
}

/// Read a command from stdin, expecting either JSON `{"command": "..."}` or a plain string.
fn read_command_from_stdin() -> std::result::Result<String, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("Failed to read stdin: {e}"))?;
    parse_command_input(&input)
}

/// Parse a command from input text — supports JSON and plain text formats.
///
/// JSON formats:
/// - `{"command": "..."}` — simple format
/// - `{"tool_name": "Bash", "tool_input": {"command": "..."}}` — Claude Code hooks format
///
/// Falls back to treating the input as a plain text command.
fn parse_command_input(input: &str) -> std::result::Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("No input received on stdin".to_string());
    }

    // Try parsing as JSON first
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        // Claude Code hooks pass: {"tool_name": "Bash", "tool_input": {"command": "..."}}
        if let Some(cmd) = value
            .get("tool_input")
            .and_then(|ti| ti.get("command"))
            .and_then(serde_json::Value::as_str)
        {
            return Ok(cmd.to_string());
        }
        // Simple format: {"command": "..."}
        if let Some(cmd) = value.get("command").and_then(serde_json::Value::as_str) {
            return Ok(cmd.to_string());
        }
        return Err(
            "JSON input must contain \"command\" field or \"tool_input.command\"".to_string(),
        );
    }

    // Fall back to plain text
    Ok(trimmed.to_string())
}

/// Format a `RiskAssessment` as human-readable text.
fn format_text_output(assessment: &RiskAssessment) -> String {
    if assessment.matched_rules.is_empty() {
        return "No risky patterns matched.".to_string();
    }

    let mut output = String::new();
    let _ = writeln!(
        output,
        "{} risky pattern(s) matched:",
        assessment.matched_rules.len()
    );
    for m in &assessment.matched_rules {
        let _ = write!(
            output,
            "\n  [{}] [{}] {}\n",
            m.id, m.severity, m.description
        );
        if let Some(ref scope) = m.blast_radius_scope {
            let detail = m.blast_radius_detail.as_deref().unwrap_or("");
            let _ = writeln!(output, "    Blast radius: [{scope}] — {detail}");
        }
    }
    for alt in &assessment.alternatives {
        let _ = write!(output, "    > Safe alternative: {}", alt.command);
        if let Some(ref info) = alt.explanation {
            let _ = write!(output, " ({info})");
        }
        output.push('\n');
    }
    if !assessment.allowed {
        if let Some(ref reason) = assessment.denial_reason {
            let _ = writeln!(output, "\n  BLOCKED: {reason}");
        }
    }
    output
}

fn run_list(
    settings: &Settings,
    active_checks: &[Check],
    group_filter: Option<&str>,
    show_all: bool,
) -> Result<shellfirm::CmdExit> {
    if show_all {
        let all = checks::get_all()?;
        let filtered: Vec<Check> = match group_filter {
            Some(group) => all.into_iter().filter(|c| c.from == group).collect(),
            None => all,
        };
        let mut output = format!("{} check(s) available:\n\n", filtered.len());
        for c in &filtered {
            let active = if active_checks.iter().any(|ac| ac.id == c.id) {
                "+"
            } else {
                "-"
            };
            let _ = writeln!(
                output,
                "  [{active}] {id:<45} {group:<18} {sev:<10} {desc}",
                id = c.id,
                group = c.from,
                sev = format!("{}", c.severity),
                desc = c.description
            );
        }
        output.push_str("\n  [+] = active, [-] = inactive\n");
        println!("{output}");
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        });
    }

    let checks_to_show: Vec<&Check> = group_filter.map_or_else(
        || active_checks.iter().collect(),
        |group| active_checks.iter().filter(|c| c.from == group).collect(),
    );

    let mut output = format!(
        "{} active check(s) (groups: {}):\n\n",
        checks_to_show.len(),
        settings.enabled_groups.join(", ")
    );
    for c in &checks_to_show {
        let _ = writeln!(
            output,
            "  {id:<45} {group:<18} {sev:<10} {desc}",
            id = c.id,
            group = c.from,
            sev = format!("{}", c.severity),
            desc = c.description
        );
    }

    println!("{output}");
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use shellfirm::agent::{Alternative, AssessmentContext, MatchedRule, RiskAssessment};
    use shellfirm::checks::Severity;

    // -- parse_command_input tests --

    #[test]
    fn parse_simple_json_command() {
        let input = r#"{"command": "rm -rf /"}"#;
        assert_eq!(parse_command_input(input).unwrap(), "rm -rf /");
    }

    #[test]
    fn parse_claude_code_hooks_format() {
        let input = r#"{"tool_name": "Bash", "tool_input": {"command": "git push --force"}}"#;
        assert_eq!(parse_command_input(input).unwrap(), "git push --force");
    }

    #[test]
    fn parse_plain_text_fallback() {
        let input = "ls -la /tmp";
        assert_eq!(parse_command_input(input).unwrap(), "ls -la /tmp");
    }

    #[test]
    fn parse_plain_text_with_whitespace() {
        let input = "  echo hello  \n";
        assert_eq!(parse_command_input(input).unwrap(), "echo hello");
    }

    #[test]
    fn parse_empty_input_returns_error() {
        assert!(parse_command_input("").is_err());
        assert!(parse_command_input("   \n  ").is_err());
    }

    #[test]
    fn parse_json_without_command_field_returns_error() {
        let input = r#"{"foo": "bar"}"#;
        let err = parse_command_input(input).unwrap_err();
        assert!(err.contains("command"));
    }

    #[test]
    fn parse_tool_input_takes_precedence_over_command() {
        // If both exist, tool_input.command wins (it's checked first)
        let input = r#"{"command": "echo fallback", "tool_input": {"command": "echo preferred"}}"#;
        assert_eq!(parse_command_input(input).unwrap(), "echo preferred");
    }

    // -- format_text_output tests --

    #[test]
    fn text_output_safe_command() {
        let assessment = RiskAssessment {
            allowed: true,
            risk_level: "Normal".into(),
            severity: None,
            matched_rules: vec![],
            alternatives: vec![],
            context: AssessmentContext {
                risk_level: "Normal".into(),
                labels: vec![],
            },
            explanation: None,
            requires_human_approval: false,
            denial_reason: None,
            blast_radius_scope: None,
            blast_radius_detail: None,
        };
        let output = format_text_output(&assessment);
        assert_eq!(output, "No risky patterns matched.");
    }

    #[test]
    fn text_output_risky_command_includes_match_and_blocked() {
        let assessment = RiskAssessment {
            allowed: false,
            risk_level: "Normal".into(),
            severity: Some(Severity::Critical),
            matched_rules: vec![MatchedRule {
                id: "fs:rm_rf".into(),
                description: "Recursive delete".into(),
                severity: Severity::Critical,
                group: "fs".into(),
                blast_radius_scope: Some("MACHINE".into()),
                blast_radius_detail: Some("Deletes everything".into()),
            }],
            alternatives: vec![Alternative {
                command: "trash /path".into(),
                explanation: Some("Moves to trash".into()),
                source: "regex-pattern".into(),
            }],
            context: AssessmentContext {
                risk_level: "Normal".into(),
                labels: vec![],
            },
            explanation: None,
            requires_human_approval: false,
            denial_reason: Some("Severity CRITICAL meets threshold".into()),
            blast_radius_scope: None,
            blast_radius_detail: None,
        };
        let output = format_text_output(&assessment);
        assert!(output.contains("1 risky pattern(s) matched:"));
        assert!(output.contains("fs:rm_rf"));
        assert!(output.contains("Recursive delete"));
        assert!(output.contains("Blast radius: [MACHINE]"));
        assert!(output.contains("Safe alternative: trash /path"));
        assert!(output.contains("Moves to trash"));
        assert!(output.contains("BLOCKED:"));
    }

    #[test]
    fn text_output_allowed_risky_has_no_blocked_line() {
        let assessment = RiskAssessment {
            allowed: true,
            risk_level: "Normal".into(),
            severity: Some(Severity::Low),
            matched_rules: vec![MatchedRule {
                id: "test:low".into(),
                description: "Low risk".into(),
                severity: Severity::Low,
                group: "test".into(),
                blast_radius_scope: None,
                blast_radius_detail: None,
            }],
            alternatives: vec![],
            context: AssessmentContext {
                risk_level: "Normal".into(),
                labels: vec![],
            },
            explanation: None,
            requires_human_approval: false,
            denial_reason: None,
            blast_radius_scope: None,
            blast_radius_detail: None,
        };
        let output = format_text_output(&assessment);
        assert!(output.contains("1 risky pattern(s) matched:"));
        assert!(!output.contains("BLOCKED"));
    }

    // -- exit code logic tests --

    #[test]
    fn text_exit_code_safe_command_returns_ok() {
        // Text mode with --exit-code: allowed=true → exit 0
        let exit_code_mode = true;
        let allowed = true;
        let exit = if exit_code_mode && !allowed {
            HOOK_BLOCK_EXIT
        } else {
            exitcode::OK
        };
        assert_eq!(exit, exitcode::OK);
    }

    #[test]
    fn text_exit_code_risky_command_returns_2() {
        // Text mode with --exit-code: allowed=false → exit 2
        let exit_code_mode = true;
        let allowed = false;
        let exit = if exit_code_mode && !allowed {
            HOOK_BLOCK_EXIT
        } else {
            exitcode::OK
        };
        assert_eq!(exit, HOOK_BLOCK_EXIT);
        assert_eq!(exit, 2);
    }

    #[test]
    fn no_exit_code_flag_always_returns_ok() {
        // Without --exit-code, even risky commands return 0
        let exit_code_mode = false;
        let allowed = false;
        let exit = if exit_code_mode && !allowed {
            HOOK_BLOCK_EXIT
        } else {
            exitcode::OK
        };
        assert_eq!(exit, exitcode::OK);
    }

    // -- build_hook_output tests (Claude Code hook protocol) --

    #[test]
    fn hook_output_allowed_has_allow_decision() {
        let assessment = RiskAssessment {
            allowed: true,
            risk_level: "Normal".into(),
            severity: None,
            matched_rules: vec![],
            alternatives: vec![],
            context: AssessmentContext {
                risk_level: "Normal".into(),
                labels: vec![],
            },
            explanation: None,
            requires_human_approval: false,
            denial_reason: None,
            blast_radius_scope: None,
            blast_radius_detail: None,
        };
        let output = build_hook_output(&assessment);
        let hook = &output["hookSpecificOutput"];
        assert_eq!(hook["hookEventName"], "PreToolUse");
        assert_eq!(hook["permissionDecision"], "allow");
        assert_eq!(
            hook["permissionDecisionReason"],
            "Command passed shellfirm checks"
        );
    }

    #[test]
    fn hook_output_denied_has_deny_decision_with_details() {
        let assessment = RiskAssessment {
            allowed: false,
            risk_level: "Normal".into(),
            severity: Some(Severity::Critical),
            matched_rules: vec![MatchedRule {
                id: "fs:rm_rf".into(),
                description: "Recursive delete".into(),
                severity: Severity::Critical,
                group: "fs".into(),
                blast_radius_scope: Some("MACHINE".into()),
                blast_radius_detail: Some("Deletes everything".into()),
            }],
            alternatives: vec![Alternative {
                command: "trash /path".into(),
                explanation: Some("Moves to trash".into()),
                source: "regex-pattern".into(),
            }],
            context: AssessmentContext {
                risk_level: "Normal".into(),
                labels: vec![],
            },
            explanation: None,
            requires_human_approval: false,
            denial_reason: Some("Severity CRITICAL meets threshold".into()),
            blast_radius_scope: None,
            blast_radius_detail: None,
        };
        let output = build_hook_output(&assessment);
        let hook = &output["hookSpecificOutput"];
        assert_eq!(hook["permissionDecision"], "deny");

        let reason = hook["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains("fs:rm_rf"));
        assert!(reason.contains("Recursive delete"));
        assert!(reason.contains("MACHINE"));
        assert!(reason.contains("BLOCKED:"));
        assert!(reason.contains("Safe alternative: trash /path"));
        assert!(reason.contains("Moves to trash"));
    }

    #[test]
    fn hook_output_is_valid_json_for_claude_code() {
        let assessment = RiskAssessment {
            allowed: false,
            risk_level: "Normal".into(),
            severity: Some(Severity::High),
            matched_rules: vec![MatchedRule {
                id: "git:force_push".into(),
                description: "Force push".into(),
                severity: Severity::High,
                group: "git".into(),
                blast_radius_scope: None,
                blast_radius_detail: None,
            }],
            alternatives: vec![],
            context: AssessmentContext {
                risk_level: "Normal".into(),
                labels: vec![],
            },
            explanation: None,
            requires_human_approval: false,
            denial_reason: Some("Denied".into()),
            blast_radius_scope: None,
            blast_radius_detail: None,
        };
        let output = build_hook_output(&assessment);
        // Verify it serializes to valid JSON
        let json_str = serde_json::to_string(&output).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(reparsed["hookSpecificOutput"].is_object());
        assert_eq!(
            reparsed["hookSpecificOutput"]["permissionDecision"],
            "deny"
        );
    }

    // -- JSON serialization test --

    #[test]
    fn json_output_is_valid_json_with_expected_fields() {
        let assessment = RiskAssessment {
            allowed: false,
            risk_level: "Normal".into(),
            severity: Some(Severity::High),
            matched_rules: vec![MatchedRule {
                id: "git:force_push".into(),
                description: "Force push".into(),
                severity: Severity::High,
                group: "git".into(),
                blast_radius_scope: None,
                blast_radius_detail: None,
            }],
            alternatives: vec![],
            context: AssessmentContext {
                risk_level: "Normal".into(),
                labels: vec![],
            },
            explanation: None,
            requires_human_approval: false,
            denial_reason: Some("Denied".into()),
            blast_radius_scope: None,
            blast_radius_detail: None,
        };
        let json = serde_json::to_string_pretty(&assessment).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["allowed"], false);
        assert_eq!(parsed["severity"], "High");
        assert_eq!(parsed["matched_rules"][0]["id"], "git:force_push");
        assert_eq!(parsed["denial_reason"], "Denied");
    }

    // -- Integration-style tests using real checks --

    fn test_settings() -> Settings {
        Settings {
            challenge: shellfirm::Challenge::Math,
            enabled_groups: vec!["base".into(), "fs".into(), "git".into()],
            ..Settings::default()
        }
    }

    #[test]
    fn check_command_risky_text_exit_code_returns_2() {
        // Text mode with --exit-code still uses exit 2 for risky commands
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = RealEnvironment;
        let agent_config = settings.agent.clone();

        let assessment =
            agent::assess_command("rm -rf /", &settings, &checks, &env, &agent_config).unwrap();

        assert!(!assessment.allowed);
        assert!(!assessment.matched_rules.is_empty());

        // Text mode: exit 2
        let exit = if !assessment.allowed {
            HOOK_BLOCK_EXIT
        } else {
            exitcode::OK
        };
        assert_eq!(exit, 2);
    }

    #[test]
    fn check_command_safe_returns_exit_0() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = RealEnvironment;
        let agent_config = settings.agent.clone();

        let assessment =
            agent::assess_command("echo hello", &settings, &checks, &env, &agent_config).unwrap();

        assert!(assessment.allowed);
        assert!(assessment.matched_rules.is_empty());

        let exit = if !assessment.allowed {
            HOOK_BLOCK_EXIT
        } else {
            exitcode::OK
        };
        assert_eq!(exit, 0);
    }

    #[test]
    fn check_command_risky_json_exit_code_returns_0_with_deny() {
        // JSON + --exit-code (Claude Code hook mode): always exit 0, deny via JSON
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = RealEnvironment;
        let agent_config = settings.agent.clone();

        let assessment =
            agent::assess_command("rm -rf /", &settings, &checks, &env, &agent_config).unwrap();

        assert!(!assessment.allowed);

        // JSON + exit-code mode: always exit 0
        // The deny decision is in the hookSpecificOutput JSON
        let hook_output = build_hook_output(&assessment);
        assert_eq!(
            hook_output["hookSpecificOutput"]["permissionDecision"],
            "deny"
        );
    }

    #[test]
    fn check_command_safe_json_exit_code_returns_0_with_allow() {
        // JSON + --exit-code (Claude Code hook mode): exit 0 with allow
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = RealEnvironment;
        let agent_config = settings.agent.clone();

        let assessment =
            agent::assess_command("echo hello", &settings, &checks, &env, &agent_config).unwrap();

        assert!(assessment.allowed);

        let hook_output = build_hook_output(&assessment);
        assert_eq!(
            hook_output["hookSpecificOutput"]["permissionDecision"],
            "allow"
        );
    }

    #[test]
    fn check_risky_command_json_has_allowed_false() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = RealEnvironment;
        let agent_config = settings.agent.clone();

        let assessment =
            agent::assess_command("rm -rf /", &settings, &checks, &env, &agent_config).unwrap();

        let json = serde_json::to_string(&assessment).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["allowed"], false);
        assert!(parsed["matched_rules"].as_array().unwrap().len() > 0);
        assert!(parsed["denial_reason"].as_str().is_some());
    }

    #[test]
    fn check_safe_command_json_has_allowed_true() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = RealEnvironment;
        let agent_config = settings.agent.clone();

        let assessment =
            agent::assess_command("ls", &settings, &checks, &env, &agent_config).unwrap();

        let json = serde_json::to_string(&assessment).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["allowed"], true);
        assert!(parsed["matched_rules"].as_array().unwrap().is_empty());
    }

    #[test]
    fn backward_compat_text_mode_without_exit_code_returns_ok_for_risky() {
        // Without --exit-code, the exit code should always be OK
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = RealEnvironment;
        let agent_config = settings.agent.clone();

        let assessment =
            agent::assess_command("rm -rf /", &settings, &checks, &env, &agent_config).unwrap();

        // Simulate text mode without --exit-code
        let exit_code_mode = false;
        let exit = if exit_code_mode && !assessment.allowed {
            HOOK_BLOCK_EXIT
        } else {
            exitcode::OK
        };
        assert_eq!(exit, exitcode::OK);

        // Text output should still report the match
        let text = format_text_output(&assessment);
        assert!(text.contains("risky pattern(s) matched:"));
    }
}
