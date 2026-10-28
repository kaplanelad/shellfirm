//! MCP (Model Context Protocol) server — exposes shellfirm as an MCP tool server.
//!
//! AI agents connect via stdio (newline-delimited JSON-RPC 2.0) and can check
//! commands before executing them.
//!
//! Protocol behaviour:
//! - Methods: `initialize`, `ping`, `tools/list`, `tools/call`. Everything else
//!   is `-32601 Method not found`.
//! - Notifications (messages without an `id`) never get a response.
//! - Errors: `-32700` parse error (invalid JSON or invalid UTF-8), `-32600`
//!   invalid request (bad envelope, batch, oversized line), `-32601` unknown
//!   method, `-32602` invalid params (unknown tool, malformed params),
//!   `-32603` internal error (a request whose handling failed unexpectedly).
//! - Protocol version negotiation: the client's requested version is echoed
//!   when supported, otherwise the latest supported version is returned.
//! - One bad line (invalid UTF-8, > [`MAX_LINE_BYTES`], or a request whose
//!   handling panics) never stops the server.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::error::Result;
use serde_json::{json, Value};

use crate::{
    agent::{self, AgentAuditInfo},
    checks::Check,
    config::{Mode, Settings},
    env::Environment,
    policy,
};

/// Protocol versions this server can speak (newest first).
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Maximum size of a single JSON-RPC message line.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

type RpcResult = std::result::Result<Value, (i64, String)>;

#[allow(clippy::needless_pass_by_value)]
fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() }
    })
}

/// Negotiate the protocol version for an `initialize` request.
#[must_use]
pub fn negotiate_protocol_version(requested: Option<&str>) -> &'static str {
    requested
        .and_then(|r| SUPPORTED_PROTOCOL_VERSIONS.iter().find(|v| **v == r))
        .copied()
        .unwrap_or(SUPPORTED_PROTOCOL_VERSIONS[0])
}

/// Read one `\n`-terminated line into `buf`, keeping at most `cap` bytes.
///
/// Returns `Ok(None)` on EOF, `Ok(Some(true))` when the line exceeded `cap`
/// (its content is discarded), `Ok(Some(false))` otherwise.
fn read_line_capped<R: BufRead>(
    reader: &mut R,
    cap: usize,
    buf: &mut Vec<u8>,
) -> io::Result<Option<bool>> {
    buf.clear();
    let mut too_long = false;
    let mut read_any = false;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(read_any.then_some(too_long));
        }
        read_any = true;
        let (chunk_len, consumed, done) = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or((available.len(), available.len(), false), |i| {
                (i, i + 1, true)
            });
        if !too_long {
            if buf.len() + chunk_len > cap {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(&available[..chunk_len]);
            }
        }
        reader.consume(consumed);
        if done {
            return Ok(Some(too_long));
        }
    }
}

// ---------------------------------------------------------------------------
// McpServer
// ---------------------------------------------------------------------------

/// The MCP server holds configuration and processes JSON-RPC requests.
pub struct McpServer<'a> {
    settings: &'a Settings,
    checks: &'a [Check],
    env: &'a dyn Environment,
    session_id: String,
    audit_path: Option<PathBuf>,
    protocol_version: Mutex<Option<&'static str>>,
}

impl<'a> McpServer<'a> {
    /// Create a new MCP server instance.
    pub fn new(
        settings: &'a Settings,
        checks: &'a [Check],
        env: &'a dyn Environment,
        session_id: String,
    ) -> Self {
        Self {
            settings,
            checks,
            env,
            session_id,
            audit_path: None,
            protocol_version: Mutex::new(None),
        }
    }

    /// Log `check_command` decisions to this audit log (when auditing is enabled).
    #[must_use]
    pub fn with_audit_path(mut self, path: PathBuf) -> Self {
        self.audit_path = Some(path);
        self
    }

    /// Run the stdio JSON-RPC loop. Reads requests from stdin, writes responses to stdout.
    ///
    /// # Errors
    /// Returns an error if stdin/stdout operations fail.
    pub fn run_stdio(&self) -> Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        self.serve(stdin.lock(), stdout.lock())
    }

    /// Serve newline-delimited JSON-RPC from `reader`, writing responses to `writer`.
    ///
    /// # Errors
    /// Returns an error only on I/O failure of the underlying streams.
    pub fn serve<R: BufRead, W: Write>(&self, mut reader: R, mut writer: W) -> Result<()> {
        let mut buf = Vec::new();
        while let Some(too_long) = read_line_capped(&mut reader, MAX_LINE_BYTES, &mut buf)? {
            let response = if too_long {
                Some(error_response(
                    Value::Null,
                    INVALID_REQUEST,
                    format!("Invalid Request: message exceeds {MAX_LINE_BYTES} bytes"),
                ))
            } else {
                match std::str::from_utf8(&buf) {
                    Ok(text) => {
                        let text = text.trim();
                        if text.is_empty() {
                            continue;
                        }
                        self.handle_line_guarded(text)
                    }
                    Err(e) => Some(error_response(
                        Value::Null,
                        PARSE_ERROR,
                        format!("Parse error: invalid UTF-8 ({e})"),
                    )),
                }
            };
            if let Some(response) = response {
                let json = serde_json::to_string(&response)?;
                writeln!(writer, "{json}")?;
                writer.flush()?;
            }
        }
        Ok(())
    }

    /// [`Self::handle_line`], answering `-32603` instead of stopping the
    /// server when handling the request panics. The agent gets no verdict
    /// for that call (no allow), and later requests are served as usual.
    fn handle_line_guarded(&self, line: &str) -> Option<Value> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.handle_line(line)))
            .unwrap_or_else(|_| {
                let msg = serde_json::from_str::<Value>(line).ok();
                let id = msg.as_ref().and_then(|m| m.get("id"));
                match id {
                    // A notification never gets a response.
                    None if msg.is_some() => None,
                    _ => Some(error_response(
                        id.filter(|v| v.is_string() || v.is_number())
                            .cloned()
                            .unwrap_or(Value::Null),
                        INTERNAL_ERROR,
                        "Internal error: this request could not be checked; treat the command as not allowed",
                    )),
                }
            })
    }

    /// Handle a single JSON-RPC line, returning a response (or None for notifications).
    #[must_use]
    pub fn handle_line(&self, line: &str) -> Option<Value> {
        match serde_json::from_str::<Value>(line) {
            Ok(v) => self.handle_message(&v),
            Err(e) => Some(error_response(
                Value::Null,
                PARSE_ERROR,
                format!("Parse error: {e}"),
            )),
        }
    }

    /// Handle a parsed JSON-RPC message.
    fn handle_message(&self, msg: &Value) -> Option<Value> {
        let Some(obj) = msg.as_object() else {
            let text = if msg.is_array() {
                "Invalid Request: batch requests are not supported"
            } else {
                "Invalid Request: expected a JSON object"
            };
            return Some(error_response(Value::Null, INVALID_REQUEST, text));
        };

        // A message without an "id" member is a notification: never respond.
        let id = match obj.get("id") {
            None => return None,
            Some(v @ (Value::String(_) | Value::Number(_))) => v.clone(),
            Some(_) => {
                return Some(error_response(
                    Value::Null,
                    INVALID_REQUEST,
                    "Invalid Request: id must be a string or a number",
                ))
            }
        };

        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(error_response(
                id,
                INVALID_REQUEST,
                "Invalid Request: jsonrpc must be \"2.0\"",
            ));
        }
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            return Some(error_response(
                id,
                INVALID_REQUEST,
                "Invalid Request: method must be a string",
            ));
        };
        let params = match obj.get("params") {
            None | Some(Value::Null) => None,
            Some(p @ Value::Object(_)) => Some(p),
            Some(_) => {
                return Some(error_response(
                    id,
                    INVALID_PARAMS,
                    "Invalid params: params must be an object",
                ))
            }
        };

        let result = match method {
            "initialize" => Ok(self.handle_initialize(params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(Self::tools_list()),
            "tools/call" => self.handle_tools_call(params),
            _ => Err((METHOD_NOT_FOUND, format!("Method not found: {method}"))),
        };

        Some(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => error_response(id, code, message),
        })
    }

    fn handle_initialize(&self, params: Option<&Value>) -> Value {
        let requested = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str);
        let version = negotiate_protocol_version(requested);
        if let Ok(mut v) = self.protocol_version.lock() {
            *v = Some(version);
        }
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": {
                "name": "shellfirm",
                "title": "shellfirm",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": "Call check_command before running any shell command. \
                Follow the returned decision: \"allow\" = no objection, \"ask\" = get \
                explicit confirmation from the user first, \"deny\" = do not run it; \
                use the suggested alternatives instead.",
        })
    }

    fn tools_list() -> Value {
        let cwd_schema = json!({
            "type": "string",
            "description": "Absolute directory the command will run in (optional; defaults to \
                the MCP server's directory). Its project policy applies."
        });
        let command_schema = |desc: &str| {
            json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": desc },
                    "cwd": cwd_schema.clone(),
                },
                "required": ["command"]
            })
        };
        let read_only = json!({ "readOnlyHint": true, "openWorldHint": false });
        json!({
            "tools": [
                {
                    "name": "check_command",
                    "title": "Check shell command",
                    "description": "Check if a shell command is risky before running it. Returns \
                        a versioned risk assessment with decision (allow | ask | deny), \
                        severity, matched rules and safer alternatives.",
                    "inputSchema": command_schema("The shell command to check"),
                    "outputSchema": {
                        "type": "object",
                        "properties": {
                            "schema_version": { "type": "integer" },
                            "decision": { "type": "string", "enum": ["allow", "ask", "deny"] },
                            "allowed": { "type": "boolean" },
                            "requires_human_approval": { "type": "boolean" },
                            "matched_rules": { "type": "array" },
                            "alternatives": { "type": "array" }
                        },
                        "required": ["schema_version", "decision", "allowed"]
                    },
                    "annotations": read_only,
                },
                {
                    "name": "suggest_alternative",
                    "title": "Suggest safer alternative",
                    "description": "Get safer alternative commands for a risky shell command.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": { "type": "string", "description": "The risky shell command" },
                            "goal": { "type": "string", "description": "What you're trying to accomplish (optional)" },
                            "cwd": cwd_schema.clone(),
                        },
                        "required": ["command"]
                    },
                    "annotations": read_only,
                },
                {
                    "name": "get_policy",
                    "title": "Get shellfirm policy",
                    "description": "Get the active shellfirm agent policy: decision thresholds, \
                        deny lists, active check groups and project policy.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "cwd": cwd_schema.clone() }
                    },
                    "annotations": read_only,
                },
                {
                    "name": "explain_risk",
                    "title": "Explain command risk",
                    "description": "Get a detailed explanation of why a command is risky, \
                        including context and matched patterns.",
                    "inputSchema": command_schema("The shell command to explain risks for"),
                    "annotations": read_only,
                }
            ]
        })
    }

    fn handle_tools_call(&self, params: Option<&Value>) -> RpcResult {
        let params = params.ok_or_else(|| {
            (
                INVALID_PARAMS,
                "Invalid params: tools/call requires params".to_string(),
            )
        })?;
        let tool_name = params.get("name").and_then(Value::as_str).ok_or_else(|| {
            (
                INVALID_PARAMS,
                "Invalid params: 'name' must be a string".to_string(),
            )
        })?;
        let empty = Value::Object(serde_json::Map::new());
        let arguments = match params.get("arguments") {
            None | Some(Value::Null) => &empty,
            Some(a @ Value::Object(_)) => a,
            Some(_) => {
                return Err((
                    INVALID_PARAMS,
                    "Invalid params: 'arguments' must be an object".to_string(),
                ))
            }
        };

        let outcome = match tool_name {
            "check_command" => self.tool_check_command(arguments),
            "suggest_alternative" => self.tool_suggest_alternative(arguments),
            "get_policy" => self.tool_get_policy(arguments),
            "explain_risk" => self.tool_explain_risk(arguments),
            _ => {
                return Err((INVALID_PARAMS, format!("Unknown tool: {tool_name}")));
            }
        };

        Ok(match outcome {
            Ok(value) => json!({
                "content": [{ "type": "text", "text": value.to_string() }],
                "structuredContent": value,
                "isError": false,
            }),
            Err(message) => json!({
                "content": [{ "type": "text", "text": format!("Error: {message}") }],
                "isError": true,
            }),
        })
    }

    // -----------------------------------------------------------------------
    // Tool implementations
    // -----------------------------------------------------------------------

    fn command_arg(args: &Value) -> std::result::Result<&str, String> {
        match args.get("command") {
            None | Some(Value::Null) => Err("Missing required argument 'command'".into()),
            Some(Value::String(s)) => Ok(s.as_str()),
            Some(other) => Err(format!(
                "Argument 'command' must be a string (got {})",
                json_type_name(other)
            )),
        }
    }

    /// The optional `cwd` argument: an absolute, existing directory.
    fn cwd_arg(args: &Value) -> std::result::Result<Option<PathBuf>, String> {
        match args.get("cwd") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
            Some(Value::String(s)) => {
                let p = PathBuf::from(s);
                if !p.is_absolute() {
                    return Err("Argument 'cwd' must be an absolute path".into());
                }
                if !p.is_dir() {
                    return Err("Argument 'cwd' is not an existing directory".into());
                }
                // `/a/repo/../repo` and symlinked directories: one spelling,
                // so a policy file is reported once.
                Ok(Some(std::fs::canonicalize(&p).unwrap_or(p)))
            }
            Some(other) => Err(format!(
                "Argument 'cwd' must be a string (got {})",
                json_type_name(other)
            )),
        }
    }

    fn assess(
        &self,
        command: &str,
        cwd: Option<PathBuf>,
    ) -> std::result::Result<agent::RiskAssessment, String> {
        // One time budget per tool call (from the server's settings).
        let _scope = self.settings.command_scope();
        // `cwd`: assess as if run there (its project policy applies).
        let at_cwd = cwd.map(|c| agent::CwdEnvironment::new(self.env, c));
        let env: &dyn Environment = match &at_cwd {
            Some(e) => e,
            None => self.env,
        };
        let Ok(cwd) = env.current_dir() else {
            return agent::assess_command(
                command,
                self.settings,
                self.checks,
                env,
                &self.settings.agent,
            )
            .map_err(|e| format!("analysis failed: {e}"));
        };
        // The policies of `cwd` and of every directory the command targets
        // (`cd repo && …`, `rm -rf repo/src`) apply, and a check they enforce
        // is active even when the user ignored it or disabled its group.
        let dirs = agent::command_target_dirs(command, &cwd, env.home_dir().as_deref());
        let discovery = policy::with_extra_target_dirs(&dirs, || {
            policy::discover_for(env, &cwd, &crate::context::command_target_dirs(command))
        });
        let checks = agent::enforce_policy_checks(self.checks, discovery.policy.as_ref());
        let mut settings = self.settings.clone();
        if let Some(p) = &discovery.policy {
            let _ = policy::apply_to_settings(&mut settings, p);
        }
        let mut assessment = policy::with_extra_target_dirs(&dirs, || {
            agent::assess_command(command, &settings, &checks, env, &settings.agent)
        })
        .map_err(|e| format!("analysis failed: {e}"))?;
        // A broken project policy means team rules are not enforced: fail
        // closed (at least `ask`) instead of silently dropping them.
        agent::apply_policy_errors(&mut assessment, &discovery.errors);
        Ok(assessment)
    }

    fn tool_check_command(&self, args: &Value) -> std::result::Result<Value, String> {
        let command = Self::command_arg(args)?;
        let assessment = self.assess(command, Self::cwd_arg(args)?)?;
        if let Some(ref path) = self.audit_path {
            let info = AgentAuditInfo {
                agent_name: "mcp",
                session_id: Some(&self.session_id),
                ..AgentAuditInfo::default()
            };
            if let Err(e) = agent::audit_decision(self.settings, path, command, &assessment, &info)
            {
                tracing::warn!("could not write audit log: {e}");
            }
        }
        let mut value = serde_json::to_value(&assessment).map_err(|e| e.to_string())?;
        // The same document as `check --format json`, version included.
        if let Some(obj) = value.as_object_mut() {
            obj.insert("version".into(), json!(env!("CARGO_PKG_VERSION")));
        }
        Ok(value)
    }

    fn tool_suggest_alternative(&self, args: &Value) -> std::result::Result<Value, String> {
        let command = Self::command_arg(args)?;
        let goal = args.get("goal").and_then(Value::as_str);
        let assessment = self.assess(command, Self::cwd_arg(args)?)?;
        let mut out = json!({
            "schema_version": agent::ASSESSMENT_SCHEMA_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
            "command": command,
            "decision": assessment.decision,
            "alternatives": assessment.alternatives,
        });
        if let Some(goal) = goal {
            out["goal"] = json!(goal);
        }
        if assessment.alternatives.is_empty() {
            out["message"] = json!(if assessment.matched_rules.is_empty() {
                "No risky patterns matched; no alternative needed"
            } else {
                "No built-in alternative for the matched rule(s)"
            });
        }
        Ok(out)
    }

    fn tool_get_policy(&self, args: &Value) -> std::result::Result<Value, String> {
        let resolved = self.settings.resolved_for(Mode::Ai);
        let agent_cfg = &self.settings.agent;
        let cwd = Self::cwd_arg(args)?.or_else(|| self.env.current_dir().ok());
        let discovery = cwd
            .map(|cwd| policy::discover_all(self.env, &cwd))
            .unwrap_or_default();
        let project = discovery.policy.as_ref();
        let policy_errors: Vec<Value> = discovery
            .errors
            .iter()
            .map(|e| {
                json!({
                    "path": e.path.display().to_string(),
                    "error": agent::sanitize_untrusted(&e.message, 300),
                })
            })
            .collect();
        let negotiated = self.protocol_version.lock().ok().and_then(|v| *v);
        Ok(json!({
            "schema_version": agent::ASSESSMENT_SCHEMA_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
            "decision_model": "no match -> allow; match below auto_deny_severity -> ask; \
                at/above auto_deny_severity or deny-listed -> deny (ask when \
                require_human_approval); self-protection rules -> at least ask",
            "challenge": format!("{}", resolved.challenge),
            "challenge_note": "Agents are never challenged interactively; the challenge applies to humans only.",
            "active_groups": self.settings.enabled_groups,
            "active_checks_count": self.checks.len(),
            "min_severity": resolved.min_severity,
            "deny_patterns_ids": self.settings.deny_patterns_ids,
            "audit_enabled": self.settings.audit_enabled,
            "agent_config": {
                "auto_deny_severity": agent_cfg.auto_deny_severity,
                "require_human_approval": agent_cfg.require_human_approval,
                "context_escalation": agent_cfg.context_escalation,
                "self_protection": agent_cfg.self_protection,
                "allow_safe": agent_cfg.allow_safe,
                "llm_review": agent_cfg.llm_review && self.settings.llm.is_some(),
            },
            "project_policy": project.map(|p| json!({
                "sources": p.sources.iter().map(|s| s.display().to_string()).collect::<Vec<_>>(),
                "deny": p.deny,
                "extra_checks": p.checks.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
            })),
            "project_policy_errors": policy_errors,
            "project_policy_note": (!policy_errors.is_empty()).then_some(
                "A project policy file is invalid: its rules are not enforced and every \
                 command is answered with at least `ask` until it is fixed."
            ),
            "protocol_version": negotiated,
            "session_id": self.session_id,
        }))
    }

    fn tool_explain_risk(&self, args: &Value) -> std::result::Result<Value, String> {
        let command = Self::command_arg(args)?;
        let assessment = self.assess(command, Self::cwd_arg(args)?)?;

        if assessment.matched_rules.is_empty() {
            return Ok(json!({
                "schema_version": agent::ASSESSMENT_SCHEMA_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
                "command": command,
                "risky": false,
                "decision": assessment.decision,
                "explanation": assessment.explanation
                    .unwrap_or_else(|| "No risky patterns detected for this command.".into()),
            }));
        }

        Ok(json!({
            "schema_version": agent::ASSESSMENT_SCHEMA_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
            "command": command,
            "risky": true,
            "decision": assessment.decision,
            "allowed": assessment.allowed,
            "severity": assessment.severity,
            "effective_severity": assessment.effective_severity,
            "risk_level": assessment.risk_level,
            "context": assessment.context,
            "matched_rules": assessment.matched_rules,
            "alternatives": assessment.alternatives,
            "explanation": agent::format_reason(&assessment),
            "decision_reason": assessment.decision_reason,
            "blast_radius_scope": assessment.blast_radius_scope,
            "blast_radius_detail": assessment.blast_radius_detail,
        }))
    }
}

const fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MockEnvironment;

    fn test_settings() -> Settings {
        Settings {
            enabled_groups: vec!["base".into(), "fs".into(), "git".into()],
            audit_enabled: false,
            ..Settings::default()
        }
    }

    fn test_env() -> MockEnvironment {
        MockEnvironment {
            cwd: "/tmp/test".into(),
            ..Default::default()
        }
    }

    /// Run `input` through a fresh server and return the parsed output lines.
    fn run(input: &[u8]) -> Vec<Value> {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());
        let mut out = Vec::new();
        server.serve(input, &mut out).unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn call(id: i64, method: &str, params: &Value) -> String {
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
    }

    fn tool(id: i64, name: &str, args: &Value) -> String {
        call(id, "tools/call", &json!({"name": name, "arguments": args}))
    }

    #[test]
    fn cwd_argument_and_schema_version_on_every_tool() {
        let input = [
            tool(1, "explain_risk", &json!({"command": "ls"})),
            tool(2, "suggest_alternative", &json!({"command": "git push -f"})),
            tool(
                3,
                "check_command",
                &json!({"command": "ls", "cwd": "relative/dir"}),
            ),
            tool(4, "check_command", &json!({"command": "ls", "cwd": 5})),
            tool(5, "check_command", &json!({"command": "ls", "cwd": "/"})),
        ]
        .join("\n");
        let out = run(input.as_bytes());
        assert_eq!(out[0]["result"]["structuredContent"]["schema_version"], 2);
        assert_eq!(out[1]["result"]["structuredContent"]["schema_version"], 2);
        // `version` on every tool, not only check_command.
        for o in &out[..2] {
            assert_eq!(
                o["result"]["structuredContent"]["version"],
                env!("CARGO_PKG_VERSION"),
                "{o}"
            );
        }
        assert_eq!(out[2]["result"]["isError"], true, "{}", out[2]);
        assert_eq!(out[3]["result"]["isError"], true, "{}", out[3]);
        assert_eq!(out[4]["result"]["isError"], false, "{}", out[4]);
    }

    fn one(line: &str) -> Value {
        let mut r = run(format!("{line}\n").as_bytes());
        assert_eq!(r.len(), 1, "expected exactly one response to {line}");
        r.remove(0)
    }

    #[test]
    fn initialize_echoes_supported_version() {
        for v in SUPPORTED_PROTOCOL_VERSIONS {
            let r = one(&call(1, "initialize", &json!({"protocolVersion": v})));
            assert_eq!(r["id"], 1);
            assert_eq!(r["result"]["protocolVersion"], *v);
            assert_eq!(r["result"]["serverInfo"]["name"], "shellfirm");
            assert!(r["result"]["capabilities"]["tools"].is_object());
        }
    }

    #[test]
    fn initialize_unknown_version_gets_latest() {
        let r = one(&call(
            1,
            "initialize",
            &json!({"protocolVersion": "1999-01-01"}),
        ));
        assert_eq!(
            r["result"]["protocolVersion"],
            SUPPORTED_PROTOCOL_VERSIONS[0]
        );
        let r = one(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#);
        assert_eq!(
            r["result"]["protocolVersion"],
            SUPPORTED_PROTOCOL_VERSIONS[0]
        );
    }

    #[test]
    fn ping_returns_empty_result() {
        let r = one(r#"{"jsonrpc":"2.0","id":"p1","method":"ping"}"#);
        assert_eq!(r["id"], "p1");
        assert_eq!(r["result"], json!({}));
    }

    #[test]
    fn notifications_never_get_responses() {
        let input = concat!(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"some/unknown"}"#,
            "\n",
            r#"{"method":"no-jsonrpc-notification"}"#,
            "\n",
        );
        assert!(run(input.as_bytes()).is_empty());
    }

    #[test]
    fn tools_list_has_four_tools() {
        let r = one(&call(2, "tools/list", &json!({})));
        let tools = r["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "check_command",
                "suggest_alternative",
                "get_policy",
                "explain_risk"
            ]
        );
        for t in tools {
            assert_eq!(t["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn error_codes() {
        // parse error
        let r = one("not valid json");
        assert_eq!(r["error"]["code"], PARSE_ERROR);
        assert_eq!(r["id"], Value::Null);
        // invalid request: missing jsonrpc, id echoed
        let r = one(r#"{"id":21,"method":"ping"}"#);
        assert_eq!(r["error"]["code"], INVALID_REQUEST);
        assert_eq!(r["id"], 21);
        // wrong jsonrpc version
        let r = one(r#"{"jsonrpc":"1.0","id":"x","method":"ping"}"#);
        assert_eq!(r["error"]["code"], INVALID_REQUEST);
        assert_eq!(r["id"], "x");
        // batch / non-object
        assert_eq!(one("[]")["error"]["code"], INVALID_REQUEST);
        assert_eq!(one("42")["error"]["code"], INVALID_REQUEST);
        // bad id type
        let r = one(r#"{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}"#);
        assert_eq!(r["error"]["code"], INVALID_REQUEST);
        // method not found
        let r = one(&call(7, "resources/list", &json!({})));
        assert_eq!(r["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(r["id"], 7);
        // invalid params
        let r = one(r#"{"jsonrpc":"2.0","id":8,"method":"tools/call"}"#);
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
        let r = one(&call(9, "tools/call", &json!({"name": "nope"})));
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
        let r = one(r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":[1]}"#);
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn deep_substitution_nesting_does_not_kill_server() {
        // A 50k-deep `$(` line is answered (nesting too deep, not allowed)
        // and the next request in the session still gets its answer.
        let settings = Settings {
            enabled_groups: vec!["base".into(), "fs".into(), "git".into(), "shell".into()],
            audit_enabled: false,
            ..Settings::default()
        };
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());
        let mut input = String::new();
        for (i, depth) in [5_000usize, 15_000, 50_000].iter().enumerate() {
            let cmd = format!("echo {}x{}", "$(".repeat(*depth), ")".repeat(*depth));
            input.push_str(&tool(
                i64::try_from(i).unwrap() + 1,
                "check_command",
                &json!({ "command": cmd }),
            ));
            input.push('\n');
        }
        input.push_str(&tool(9, "check_command", &json!({"command": "ls"})));
        input.push('\n');
        let mut out = Vec::new();
        server.serve(input.as_bytes(), &mut out).unwrap();
        let lines: Vec<Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 4);
        for r in &lines[..3] {
            let text = r.to_string();
            assert!(text.contains("shell:nesting_too_deep"), "{text}");
            assert!(
                !text.replace('\\', "").contains("\"allowed\":true"),
                "{text}"
            );
        }
        assert_eq!(lines[3]["id"], 9);
        assert!(lines[3]["result"].is_object(), "{}", lines[3]);
    }

    /// An environment whose first call panics (an unexpected bug while
    /// handling one request), then behaves like [`test_env`].
    struct PanicOnceEnv {
        armed: std::sync::atomic::AtomicBool,
        inner: MockEnvironment,
    }

    impl PanicOnceEnv {
        fn trip(&self) {
            if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                panic!("simulated bug while handling a request");
            }
        }
    }

    impl Environment for PanicOnceEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.trip();
            self.inner.var(key)
        }
        fn current_dir(&self) -> Result<PathBuf> {
            self.trip();
            self.inner.current_dir()
        }
        fn path_exists(&self, path: &std::path::Path) -> bool {
            self.trip();
            self.inner.path_exists(path)
        }
        fn home_dir(&self) -> Option<PathBuf> {
            self.trip();
            self.inner.home_dir()
        }
        fn run_command(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> Option<String> {
            self.trip();
            self.inner.run_command(cmd, args, timeout_ms)
        }
        fn read_file(&self, path: &std::path::Path) -> Result<String> {
            self.trip();
            self.inner.read_file(path)
        }
        fn find_file_upward(&self, start: &std::path::Path, filename: &str) -> Option<PathBuf> {
            self.trip();
            self.inner.find_file_upward(start, filename)
        }
    }

    #[test]
    fn a_request_that_panics_gets_an_error_and_the_server_continues() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = PanicOnceEnv {
            armed: std::sync::atomic::AtomicBool::new(true),
            inner: test_env(),
        };
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());
        let input = [
            tool(1, "check_command", &json!({"command": "git push -f"})),
            tool(2, "check_command", &json!({"command": "git push -f"})),
        ]
        .join("\n");
        let mut out = Vec::new();
        server.serve(input.as_bytes(), &mut out).unwrap();
        let lines: Vec<Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[0]["id"], 1);
        assert_eq!(lines[0]["error"]["code"], -32603);
        assert_eq!(lines[1]["id"], 2);
        assert!(lines[1]["result"].is_object(), "{}", lines[1]);
    }

    #[test]
    fn invalid_utf8_line_does_not_kill_server() {
        let mut input = Vec::new();
        input.extend_from_slice(br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#);
        input.push(b'\n');
        input.extend_from_slice(
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_command","arguments":{"command":"ls "#,
        );
        input.push(0xff);
        input.extend_from_slice(b"\"}}}\n");
        input.extend_from_slice(br#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#);
        input.push(b'\n');
        let out = run(&input);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0]["id"], 1);
        assert_eq!(out[1]["error"]["code"], PARSE_ERROR);
        assert_eq!(out[2]["id"], 3);
    }

    #[test]
    fn oversized_line_is_rejected_and_server_continues() {
        let mut input = vec![b'a'; MAX_LINE_BYTES + 10];
        input.push(b'\n');
        input.extend_from_slice(br#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#);
        // no trailing newline: partial last line must still be processed
        let out = run(&input);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["error"]["code"], INVALID_REQUEST);
        assert_eq!(out[1]["id"], 5);
    }

    #[test]
    fn crlf_and_blank_lines_are_tolerated() {
        let out = run(b"\r\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["result"], json!({}));
    }

    #[test]
    fn check_command_safe_and_risky() {
        let r = one(&tool(3, "check_command", &json!({"command": "echo hello"})));
        let result = &r["result"];
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        let a: agent::RiskAssessment = serde_json::from_str(text).unwrap();
        assert!(a.allowed);
        assert_eq!(result["structuredContent"]["decision"], "allow");

        let r = one(&tool(
            4,
            "check_command",
            &json!({"command": "git push --force"}),
        ));
        let sc = &r["result"]["structuredContent"];
        assert_eq!(sc["decision"], "deny");
        assert_eq!(sc["allowed"], false);
        assert_eq!(sc["schema_version"], agent::ASSESSMENT_SCHEMA_VERSION);
        assert!(!sc["matched_rules"].as_array().unwrap().is_empty());
    }

    #[test]
    fn tool_argument_errors_are_tool_errors() {
        let r = one(&tool(5, "check_command", &json!({"command": 123})));
        assert_eq!(r["result"]["isError"], true);
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("must be a string"), "{text}");
        let r = one(&tool(6, "check_command", &json!({})));
        assert!(r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Missing"));
    }

    #[test]
    fn get_policy_reports_agent_settings() {
        let r = one(&tool(5, "get_policy", &json!({})));
        let p = &r["result"]["structuredContent"];
        assert_eq!(p["challenge"], "Math");
        assert_eq!(p["session_id"], "test-session");
        assert_eq!(p["agent_config"]["auto_deny_severity"], "High");
        assert_eq!(p["agent_config"]["self_protection"], true);
        assert!(p["deny_patterns_ids"].is_array());
    }

    #[test]
    fn explain_risk_and_suggest_alternative() {
        let r = one(&tool(6, "explain_risk", &json!({"command": "ls -la"})));
        assert_eq!(r["result"]["structuredContent"]["risky"], false);
        let r = one(&tool(
            7,
            "explain_risk",
            &json!({"command": "git push --force"}),
        ));
        let sc = &r["result"]["structuredContent"];
        assert_eq!(sc["risky"], true);
        assert!(sc["explanation"]
            .as_str()
            .unwrap()
            .contains("git:force_push"));

        let r = one(&tool(
            8,
            "suggest_alternative",
            &json!({"command": "git push --force", "goal": "update my branch"}),
        ));
        let sc = &r["result"]["structuredContent"];
        assert_eq!(sc["goal"], "update my branch");
        assert!(!sc["alternatives"].as_array().unwrap().is_empty());
    }

    #[test]
    fn check_command_is_audited() {
        let dir = tree_fs::TreeBuilder::default().create().unwrap();
        let path = dir.root.join("audit.log");
        let settings = Settings {
            audit_enabled: true,
            ..test_settings()
        };
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server =
            McpServer::new(&settings, &checks, &env, "sess".into()).with_audit_path(path.clone());
        let input = format!(
            "{}\n{}\n",
            tool(1, "check_command", &json!({"command": "git push --force"})),
            tool(2, "check_command", &json!({"command": "ls"}))
        );
        let mut out = Vec::new();
        server.serve(input.as_bytes(), &mut out).unwrap();
        let log = std::fs::read_to_string(&path).unwrap();
        assert_eq!(log.lines().count(), 1);
        let ev: Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
        assert_eq!(ev["agent_name"], "mcp");
        assert_eq!(ev["agent_session_id"], "sess");
        assert_eq!(ev["outcome"], "Denied");
    }
}
