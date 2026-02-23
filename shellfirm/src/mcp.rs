//! MCP (Model Context Protocol) server — exposes shellfirm as an MCP tool server.
//!
//! AI agents connect via stdio and can check commands before executing them.
//! Implements JSON-RPC 2.0 with the MCP tool protocol surface:
//! `initialize`, `tools/list`, `tools/call`, `notifications/initialized`.

use std::io::{self, BufRead, Write};

use crate::error::Result;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use crate::{agent, checks::Check, config::Settings, env::Environment};

// ---------------------------------------------------------------------------
// JSON-RPC types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

// ---------------------------------------------------------------------------
// MCP protocol types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
    capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    server_info: ServerInfo,
}

#[derive(Debug, Serialize)]
struct ServerCapabilities {
    tools: ToolsCapability,
}

#[derive(Debug, Serialize)]
struct ToolsCapability {}

#[derive(Debug, Serialize)]
struct ServerInfo {
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct ToolDefinition {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
}

#[derive(Debug, Serialize)]
struct ToolsListResult {
    tools: Vec<ToolDefinition>,
}

#[derive(Debug, Serialize)]
struct ToolCallResult {
    content: Vec<ToolContent>,
    #[serde(rename = "isError", skip_serializing_if = "std::ops::Not::not")]
    is_error: bool,
}

#[derive(Debug, Serialize)]
struct ToolContent {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
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
        }
    }

    /// Run the stdio JSON-RPC loop. Reads requests from stdin, writes responses to stdout.
    ///
    /// # Errors
    /// Returns an error if stdin/stdout operations fail.
    pub fn run_stdio(&self) -> Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        for line in stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            if let Some(response) = self.handle_line(&line) {
                let json = serde_json::to_string(&response)?;
                writeln!(stdout, "{json}")?;
                stdout.flush()?;
            }
        }

        Ok(())
    }

    /// Handle a single JSON-RPC line, returning a response (or None for notifications).
    fn handle_line(&self, line: &str) -> Option<JsonRpcResponse> {
        let request: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                return Some(JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id: None,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {e}"),
                    }),
                });
            }
        };

        self.handle_request(&request)
    }

    /// Handle a parsed JSON-RPC request.
    fn handle_request(&self, request: &JsonRpcRequest) -> Option<JsonRpcResponse> {
        match request.method.as_str() {
            "initialize" => Some(self.handle_initialize(request)),
            "notifications/initialized" => None, // notification, no response
            "tools/list" => Some(self.handle_tools_list(request)),
            "tools/call" => Some(self.handle_tools_call(request)),
            _ => Some(JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {}", request.method),
                }),
            }),
        }
    }

    #[allow(clippy::unused_self)]
    fn handle_initialize(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let result = InitializeResult {
            protocol_version: "2024-11-05".into(),
            capabilities: ServerCapabilities {
                tools: ToolsCapability {},
            },
            server_info: ServerInfo {
                name: "shellfirm".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
        };

        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: request.id.clone(),
            result: Some(serde_json::to_value(result).unwrap()),
            error: None,
        }
    }

    #[allow(clippy::unused_self)]
    fn handle_tools_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let tools = vec![
            ToolDefinition {
                name: "check_command".into(),
                description: "Check if a shell command is risky. Returns a risk assessment \
                    with severity, matched rules, and safer alternatives."
                    .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The shell command to check"
                        }
                    },
                    "required": ["command"]
                }),
            },
            ToolDefinition {
                name: "suggest_alternative".into(),
                description: "Get safer alternative commands for a risky shell command.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The risky shell command"
                        },
                        "goal": {
                            "type": "string",
                            "description": "What you're trying to accomplish (optional)"
                        }
                    },
                    "required": ["command"]
                }),
            },
            ToolDefinition {
                name: "get_policy".into(),
                description: "Get the current shellfirm configuration and active policy.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "explain_risk".into(),
                description: "Get a detailed explanation of why a command is risky, \
                    including context and matched patterns."
                    .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The shell command to explain risks for"
                        }
                    },
                    "required": ["command"]
                }),
            },
        ];

        let result = ToolsListResult { tools };

        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: request.id.clone(),
            result: Some(serde_json::to_value(result).unwrap()),
            error: None,
        }
    }

    fn handle_tools_call(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let params = request.params.as_ref().and_then(|p| p.as_object());
        let tool_name = params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let arguments = params
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));

        let result = match tool_name {
            "check_command" => self.tool_check_command(&arguments),
            "suggest_alternative" => self.tool_suggest_alternative(&arguments),
            "get_policy" => self.tool_get_policy(),
            "explain_risk" => self.tool_explain_risk(&arguments),
            _ => Err(crate::error::Error::Mcp(format!(
                "Unknown tool: {tool_name}"
            ))),
        };

        match result {
            Ok(text) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                result: Some(
                    serde_json::to_value(ToolCallResult {
                        content: vec![ToolContent {
                            content_type: "text".into(),
                            text,
                        }],
                        is_error: false,
                    })
                    .unwrap(),
                ),
                error: None,
            },
            Err(e) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                result: Some(
                    serde_json::to_value(ToolCallResult {
                        content: vec![ToolContent {
                            content_type: "text".into(),
                            text: format!("Error: {e}"),
                        }],
                        is_error: true,
                    })
                    .unwrap(),
                ),
                error: None,
            },
        }
    }

    // -----------------------------------------------------------------------
    // Tool implementations
    // -----------------------------------------------------------------------

    fn tool_check_command(&self, args: &Value) -> Result<String> {
        let command = args
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::error::Error::Mcp("Missing 'command' parameter".into()))?;

        let assessment = agent::assess_command(
            command,
            self.settings,
            self.checks,
            self.env,
            &self.settings.agent,
        )?;

        Ok(serde_json::to_string_pretty(&assessment)?)
    }

    fn tool_suggest_alternative(&self, args: &Value) -> Result<String> {
        let command = args
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::error::Error::Mcp("Missing 'command' parameter".into()))?;

        let assessment = agent::assess_command(
            command,
            self.settings,
            self.checks,
            self.env,
            &self.settings.agent,
        )?;

        if assessment.alternatives.is_empty() {
            Ok(serde_json::to_string_pretty(&serde_json::json!({
                "command": command,
                "alternatives": [],
                "message": "No alternatives found for this command"
            }))?)
        } else {
            Ok(serde_json::to_string_pretty(&serde_json::json!({
                "command": command,
                "alternatives": assessment.alternatives,
            }))?)
        }
    }

    fn tool_get_policy(&self) -> Result<String> {
        let policy_info = serde_json::json!({
            "challenge": format!("{}", self.settings.challenge),
            "active_groups": self.settings.enabled_groups,
            "active_checks_count": self.checks.len(),
            "min_severity": self.settings.min_severity,
            "audit_enabled": self.settings.audit_enabled,
            "agent_config": {
                "auto_deny_severity": self.settings.agent.auto_deny_severity,
                "require_human_approval": self.settings.agent.require_human_approval,
            },
            "session_id": self.session_id,
        });

        Ok(serde_json::to_string_pretty(&policy_info)?)
    }

    fn tool_explain_risk(&self, args: &Value) -> Result<String> {
        let command = args
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::error::Error::Mcp("Missing 'command' parameter".into()))?;

        let assessment = agent::assess_command(
            command,
            self.settings,
            self.checks,
            self.env,
            &self.settings.agent,
        )?;

        if assessment.matched_rules.is_empty() {
            return Ok(serde_json::to_string_pretty(&serde_json::json!({
                "command": command,
                "risky": false,
                "explanation": "No risks detected for this command."
            }))?);
        }

        let mut explanation_parts = Vec::new();
        for rule in &assessment.matched_rules {
            explanation_parts.push(format!(
                "- [{}] {}: {}",
                rule.severity, rule.id, rule.description
            ));
        }

        let explanation = serde_json::json!({
            "command": command,
            "risky": true,
            "allowed": assessment.allowed,
            "severity": assessment.severity,
            "risk_level": assessment.risk_level,
            "context": assessment.context,
            "matched_rules": assessment.matched_rules,
            "alternatives": assessment.alternatives,
            "explanation": explanation_parts.join("\n"),
            "denial_reason": assessment.denial_reason,
            "blast_radius_scope": assessment.blast_radius_scope,
            "blast_radius_detail": assessment.blast_radius_detail,
        });

        Ok(serde_json::to_string_pretty(&explanation)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use crate::env::MockEnvironment;

    fn test_settings() -> Settings {
        Settings {
            challenge: crate::config::Challenge::Math,
            enabled_groups: vec!["base".into(), "fs".into(), "git".into()],
            disabled_groups: vec![],
            ignores_patterns_ids: vec![],
            deny_patterns_ids: vec![],
            context: crate::context::ContextConfig::default(),
            audit_enabled: false,
            blast_radius: true,
            min_severity: None,
            agent: AgentConfig::default(),
            llm: crate::config::LlmConfig::default(),
            wrappers: crate::config::WrappersConfig::default(),
        }
    }

    fn test_env() -> MockEnvironment {
        MockEnvironment {
            cwd: "/tmp/test".into(),
            ..Default::default()
        }
    }

    fn make_request(id: i64, method: &str, params: Option<Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(Value::Number(id.into())),
            method: method.into(),
            params,
        }
    }

    #[test]
    fn test_initialize() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let request = make_request(1, "initialize", None);
        let response = server.handle_request(&request).unwrap();
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "shellfirm");
    }

    #[test]
    fn test_tools_list() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let request = make_request(2, "tools/list", None);
        let response = server.handle_request(&request).unwrap();
        assert!(response.error.is_none());
        let tools = response.result.unwrap()["tools"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(tools.len(), 4);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"check_command"));
        assert!(names.contains(&"suggest_alternative"));
        assert!(names.contains(&"get_policy"));
        assert!(names.contains(&"explain_risk"));
    }

    #[test]
    fn test_check_command_safe() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let request = make_request(
            3,
            "tools/call",
            Some(serde_json::json!({
                "name": "check_command",
                "arguments": {"command": "echo hello"}
            })),
        );
        let response = server.handle_request(&request).unwrap();
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let assessment: agent::RiskAssessment = serde_json::from_str(text).unwrap();
        assert!(assessment.allowed);
        assert!(assessment.matched_rules.is_empty());
    }

    #[test]
    fn test_check_command_risky() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let request = make_request(
            4,
            "tools/call",
            Some(serde_json::json!({
                "name": "check_command",
                "arguments": {"command": "git push --force"}
            })),
        );
        let response = server.handle_request(&request).unwrap();
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let assessment: agent::RiskAssessment = serde_json::from_str(text).unwrap();
        // Force push should be detected
        assert!(!assessment.matched_rules.is_empty());
    }

    #[test]
    fn test_get_policy() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let request = make_request(
            5,
            "tools/call",
            Some(serde_json::json!({
                "name": "get_policy",
                "arguments": {}
            })),
        );
        let response = server.handle_request(&request).unwrap();
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let policy: Value = serde_json::from_str(text).unwrap();
        assert_eq!(policy["challenge"], "Math");
        assert_eq!(policy["session_id"], "test-session");
    }

    #[test]
    fn test_explain_risk_safe_command() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let request = make_request(
            6,
            "tools/call",
            Some(serde_json::json!({
                "name": "explain_risk",
                "arguments": {"command": "ls -la"}
            })),
        );
        let response = server.handle_request(&request).unwrap();
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let explanation: Value = serde_json::from_str(text).unwrap();
        assert_eq!(explanation["risky"], false);
    }

    #[test]
    fn test_unknown_method() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let request = make_request(7, "unknown/method", None);
        let response = server.handle_request(&request).unwrap();
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32601);
    }

    #[test]
    fn test_notification_returns_none() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let request = make_request(0, "notifications/initialized", None);
        assert!(server.handle_request(&request).is_none());
    }

    #[test]
    fn test_unknown_tool() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let request = make_request(
            8,
            "tools/call",
            Some(serde_json::json!({
                "name": "nonexistent_tool",
                "arguments": {}
            })),
        );
        let response = server.handle_request(&request).unwrap();
        assert!(response.error.is_none()); // Tool errors are returned as content
        let result = response.result.unwrap();
        assert!(result["isError"].as_bool().unwrap());
    }

    #[test]
    fn test_suggest_alternative_for_risky_command() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let request = make_request(
            9,
            "tools/call",
            Some(serde_json::json!({
                "name": "suggest_alternative",
                "arguments": {"command": "git push --force"}
            })),
        );
        let response = server.handle_request(&request).unwrap();
        assert!(response.error.is_none());
    }

    #[test]
    fn test_handle_malformed_json() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let server = McpServer::new(&settings, &checks, &env, "test-session".into());

        let response = server.handle_line("not valid json").unwrap();
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32700);
    }
}
