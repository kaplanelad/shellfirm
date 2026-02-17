//! LLM-powered semantic command analysis (feature-gated behind `llm`).
//!
//! Provides optional deep analysis of commands using large language models.
//! This can catch risks that regex patterns miss (e.g. subtle data exfiltration,
//! semantic intent behind complex pipelines).
//!
//! **Safety rule:** LLM analysis can only *increase* risk (flip allowed → denied),
//! never *decrease* it. LLM failure silently falls back to regex-only results.

use anyhow::Result;
use serde_derive::{Deserialize, Serialize};

use crate::config::LlmConfig;
use crate::env::Environment;

/// Result of LLM command analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmAnalysis {
    /// Whether the LLM considers the command risky (true = risky).
    pub is_risky: bool,
    /// Risk score from 0.0 (safe) to 1.0 (extremely dangerous).
    pub risk_score: f64,
    /// Human-readable explanation of risks found.
    pub explanation: String,
    /// Additional risks not caught by regex patterns.
    pub additional_risks: Vec<String>,
}

/// A safer alternative suggested by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmAlternative {
    /// The suggested safer command.
    pub command: String,
    /// Why this alternative is safer.
    pub explanation: String,
}

/// Trait for LLM providers — enables testing with mocks.
pub trait LlmProvider: Send + Sync {
    /// Analyze a command for risks beyond what regex patterns detect.
    ///
    /// # Errors
    /// Returns an error if the LLM API call fails.
    fn analyze_command(
        &self,
        command: &str,
        context_hints: &[String],
        matched_descriptions: &[String],
    ) -> Result<LlmAnalysis>;

    /// Suggest safer alternatives to a risky command.
    ///
    /// # Errors
    /// Returns an error if the LLM API call fails.
    fn suggest_alternatives(&self, command: &str, risk: &str) -> Result<Vec<LlmAlternative>>;

    /// Generate a detailed risk explanation.
    ///
    /// # Errors
    /// Returns an error if the LLM API call fails.
    fn explain_risk(
        &self,
        command: &str,
        matched_checks: &[String],
        context_hints: &[String],
    ) -> Result<String>;

    /// Check if the provider is configured and available.
    fn is_available(&self) -> bool;
}

// ---------------------------------------------------------------------------
// NoOpProvider — fallback when LLM is unconfigured
// ---------------------------------------------------------------------------

/// A no-op provider that returns neutral results. Used when LLM is not configured.
pub struct NoOpProvider;

impl LlmProvider for NoOpProvider {
    fn analyze_command(
        &self,
        _command: &str,
        _context_hints: &[String],
        _matched_descriptions: &[String],
    ) -> Result<LlmAnalysis> {
        Ok(LlmAnalysis {
            is_risky: false,
            risk_score: 0.0,
            explanation: String::new(),
            additional_risks: vec![],
        })
    }

    fn suggest_alternatives(&self, _command: &str, _risk: &str) -> Result<Vec<LlmAlternative>> {
        Ok(vec![])
    }

    fn explain_risk(
        &self,
        _command: &str,
        _matched_checks: &[String],
        _context_hints: &[String],
    ) -> Result<String> {
        Ok(String::new())
    }

    fn is_available(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// AnthropicProvider — calls Claude Messages API
// ---------------------------------------------------------------------------

/// Provider that calls the Anthropic (Claude) Messages API.
pub struct AnthropicProvider {
    api_key: String,
    model: String,
    max_tokens: u32,
    client: reqwest::blocking::Client,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(api_key: String, config: &LlmConfig) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()?;
        Ok(Self {
            api_key,
            model: config.model.clone(),
            max_tokens: config.max_tokens,
            client,
        })
    }

    fn call_api(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt}
            ]
        });

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()?;

        let status = resp.status();
        let text = resp.text()?;

        if !status.is_success() {
            anyhow::bail!("Anthropic API error ({status}): {text}");
        }

        // Extract text content from the response
        let json: serde_json::Value = serde_json::from_str(&text)?;
        let content = json["content"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|block| block["text"].as_str())
            .unwrap_or("")
            .to_string();

        Ok(content)
    }
}

impl LlmProvider for AnthropicProvider {
    fn analyze_command(
        &self,
        command: &str,
        context_hints: &[String],
        matched_descriptions: &[String],
    ) -> Result<LlmAnalysis> {
        let system = "You are a shell command security analyzer. Respond ONLY with valid JSON. \
            Analyze the given command for security risks. Return: \
            {\"is_risky\": bool, \"risk_score\": float 0-1, \"explanation\": string, \
            \"additional_risks\": [string]}";

        let user = format!(
            "Command: {}\nContext: {}\nAlready matched risks: {}",
            command,
            context_hints.join(", "),
            matched_descriptions.join("; "),
        );

        let response = self.call_api(system, &user)?;
        Ok(parse_analysis_response(&response))
    }

    fn suggest_alternatives(&self, command: &str, risk: &str) -> Result<Vec<LlmAlternative>> {
        let system = "You are a shell command security advisor. Respond ONLY with valid JSON. \
            Suggest safer alternatives. Return: \
            [{\"command\": string, \"explanation\": string}]";

        let user = format!("Risky command: {command}\nRisk: {risk}");
        let response = self.call_api(system, &user)?;
        Ok(parse_alternatives_response(&response))
    }

    fn explain_risk(
        &self,
        command: &str,
        matched_checks: &[String],
        context_hints: &[String],
    ) -> Result<String> {
        let system = "You are a shell command security advisor. Explain the risks of the given \
            command in 2-3 concise sentences. Consider the environment context.";

        let user = format!(
            "Command: {}\nMatched patterns: {}\nContext: {}",
            command,
            matched_checks.join(", "),
            context_hints.join(", "),
        );

        self.call_api(system, &user)
    }

    fn is_available(&self) -> bool {
        !self.api_key.is_empty()
    }
}

// ---------------------------------------------------------------------------
// OpenAiCompatibleProvider — calls /v1/chat/completions
// ---------------------------------------------------------------------------

/// Provider that calls any `OpenAI`-compatible API (`OpenAI`, local models, etc.).
pub struct OpenAiCompatibleProvider {
    api_key: String,
    model: String,
    base_url: String,
    max_tokens: u32,
    client: reqwest::blocking::Client,
}

impl OpenAiCompatibleProvider {
    /// Create a new OpenAI-compatible provider.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(api_key: String, config: &LlmConfig) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()?;
        let base_url = config
            .base_url
            .clone()
            .unwrap_or_else(|| "https://api.openai.com".into());
        Ok(Self {
            api_key,
            model: config.model.clone(),
            base_url,
            max_tokens: config.max_tokens,
            client,
        })
    }

    fn call_api(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        });

        let url = format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        );
        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()?;

        let status = resp.status();
        let text = resp.text()?;

        if !status.is_success() {
            anyhow::bail!("OpenAI API error ({status}): {text}");
        }

        let json: serde_json::Value = serde_json::from_str(&text)?;
        let content = json["choices"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|choice| choice["message"]["content"].as_str())
            .unwrap_or("")
            .to_string();

        Ok(content)
    }
}

impl LlmProvider for OpenAiCompatibleProvider {
    fn analyze_command(
        &self,
        command: &str,
        context_hints: &[String],
        matched_descriptions: &[String],
    ) -> Result<LlmAnalysis> {
        let system = "You are a shell command security analyzer. Respond ONLY with valid JSON. \
            Analyze the given command for security risks. Return: \
            {\"is_risky\": bool, \"risk_score\": float 0-1, \"explanation\": string, \
            \"additional_risks\": [string]}";

        let user = format!(
            "Command: {}\nContext: {}\nAlready matched risks: {}",
            command,
            context_hints.join(", "),
            matched_descriptions.join("; "),
        );

        let response = self.call_api(system, &user)?;
        Ok(parse_analysis_response(&response))
    }

    fn suggest_alternatives(&self, command: &str, risk: &str) -> Result<Vec<LlmAlternative>> {
        let system = "You are a shell command security advisor. Respond ONLY with valid JSON. \
            Suggest safer alternatives. Return: \
            [{\"command\": string, \"explanation\": string}]";

        let user = format!("Risky command: {command}\nRisk: {risk}");
        let response = self.call_api(system, &user)?;
        Ok(parse_alternatives_response(&response))
    }

    fn explain_risk(
        &self,
        command: &str,
        matched_checks: &[String],
        context_hints: &[String],
    ) -> Result<String> {
        let system = "You are a shell command security advisor. Explain the risks of the given \
            command in 2-3 concise sentences. Consider the environment context.";

        let user = format!(
            "Command: {}\nMatched patterns: {}\nContext: {}",
            command,
            matched_checks.join(", "),
            context_hints.join(", "),
        );

        self.call_api(system, &user)
    }

    fn is_available(&self) -> bool {
        !self.api_key.is_empty()
    }
}

// ---------------------------------------------------------------------------
// MockLlmProvider — for tests
// ---------------------------------------------------------------------------

/// Test provider that returns preconfigured responses.
pub struct MockLlmProvider {
    pub analysis: LlmAnalysis,
    pub alternatives: Vec<LlmAlternative>,
    pub explanation: String,
    pub available: bool,
}

impl Default for MockLlmProvider {
    fn default() -> Self {
        Self {
            analysis: LlmAnalysis {
                is_risky: false,
                risk_score: 0.0,
                explanation: String::new(),
                additional_risks: vec![],
            },
            alternatives: vec![],
            explanation: String::new(),
            available: true,
        }
    }
}

impl LlmProvider for MockLlmProvider {
    fn analyze_command(
        &self,
        _command: &str,
        _context_hints: &[String],
        _matched_descriptions: &[String],
    ) -> Result<LlmAnalysis> {
        Ok(self.analysis.clone())
    }

    fn suggest_alternatives(&self, _command: &str, _risk: &str) -> Result<Vec<LlmAlternative>> {
        Ok(self.alternatives.clone())
    }

    fn explain_risk(
        &self,
        _command: &str,
        _matched_checks: &[String],
        _context_hints: &[String],
    ) -> Result<String> {
        Ok(self.explanation.clone())
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Create an LLM provider based on the configuration and environment.
///
/// Looks for an API key in `SHELLFIRM_LLM_API_KEY`, then falls back to
/// `ANTHROPIC_API_KEY` (for anthropic provider) or `OPENAI_API_KEY`
/// (for openai-compatible). Returns `NoOpProvider` if no key is found.
#[must_use]
pub fn create_provider(config: &LlmConfig, env: &dyn Environment) -> Box<dyn LlmProvider> {
    let api_key = env
        .var("SHELLFIRM_LLM_API_KEY")
        .or_else(|| match config.provider.as_str() {
            "anthropic" => env.var("ANTHROPIC_API_KEY"),
            "openai-compatible" => env.var("OPENAI_API_KEY"),
            _ => None,
        });

    let Some(key) = api_key else {
        log::debug!("No LLM API key found, using NoOpProvider");
        return Box::new(NoOpProvider);
    };

    if key.is_empty() {
        return Box::new(NoOpProvider);
    }

    match config.provider.as_str() {
        "anthropic" => match AnthropicProvider::new(key, config) {
            Ok(p) => Box::new(p),
            Err(e) => {
                log::warn!("Failed to create Anthropic provider: {e}");
                Box::new(NoOpProvider)
            }
        },
        "openai-compatible" => match OpenAiCompatibleProvider::new(key, config) {
            Ok(p) => Box::new(p),
            Err(e) => {
                log::warn!("Failed to create OpenAI-compatible provider: {e}");
                Box::new(NoOpProvider)
            }
        },
        other => {
            log::warn!("Unknown LLM provider: {other}, using NoOpProvider");
            Box::new(NoOpProvider)
        }
    }
}

// ---------------------------------------------------------------------------
// Response parsing helpers
// ---------------------------------------------------------------------------

fn parse_analysis_response(response: &str) -> LlmAnalysis {
    // Try to extract JSON from the response (LLMs sometimes wrap in markdown)
    let json_str = extract_json(response);
    match serde_json::from_str::<LlmAnalysis>(json_str) {
        Ok(analysis) => analysis,
        Err(e) => {
            log::warn!("Failed to parse LLM analysis response: {e}");
            LlmAnalysis {
                is_risky: false,
                risk_score: 0.0,
                explanation: String::new(),
                additional_risks: vec![],
            }
        }
    }
}

fn parse_alternatives_response(response: &str) -> Vec<LlmAlternative> {
    let json_str = extract_json(response);
    match serde_json::from_str::<Vec<LlmAlternative>>(json_str) {
        Ok(alts) => alts,
        Err(e) => {
            log::warn!("Failed to parse LLM alternatives response: {e}");
            vec![]
        }
    }
}

/// Extract JSON from a response that might contain markdown code fences.
fn extract_json(text: &str) -> &str {
    let trimmed = text.trim();
    // Handle ```json ... ``` blocks
    if let Some(start) = trimmed.find("```json") {
        let after_fence = &trimmed[start + 7..];
        if let Some(end) = after_fence.find("```") {
            return after_fence[..end].trim();
        }
    }
    // Handle ``` ... ``` blocks
    if let Some(start) = trimmed.find("```") {
        let after_fence = &trimmed[start + 3..];
        if let Some(end) = after_fence.find("```") {
            return after_fence[..end].trim();
        }
    }
    trimmed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_provider_returns_safe() {
        let provider = NoOpProvider;
        let result = provider.analyze_command("rm -rf /", &[], &[]).unwrap();
        assert!(!result.is_risky);
        assert_eq!(result.risk_score, 0.0);
        assert!(!provider.is_available());
    }

    #[test]
    fn test_mock_provider_returns_configured() {
        let provider = MockLlmProvider {
            analysis: LlmAnalysis {
                is_risky: true,
                risk_score: 0.9,
                explanation: "Very dangerous".into(),
                additional_risks: vec!["data loss".into()],
            },
            ..Default::default()
        };

        let result = provider.analyze_command("rm -rf /", &[], &[]).unwrap();
        assert!(result.is_risky);
        assert_eq!(result.risk_score, 0.9);
        assert_eq!(result.explanation, "Very dangerous");
    }

    #[test]
    fn test_mock_provider_availability() {
        let available = MockLlmProvider {
            available: true,
            ..Default::default()
        };
        assert!(available.is_available());

        let unavailable = MockLlmProvider {
            available: false,
            ..Default::default()
        };
        assert!(!unavailable.is_available());
    }

    #[test]
    fn test_extract_json_plain() {
        let json = r#"{"is_risky": true}"#;
        assert_eq!(extract_json(json), json);
    }

    #[test]
    fn test_extract_json_from_markdown() {
        let response = "Here is the analysis:\n```json\n{\"is_risky\": true}\n```\nDone.";
        assert_eq!(extract_json(response), r#"{"is_risky": true}"#);
    }

    #[test]
    fn test_extract_json_from_plain_fences() {
        let response = "```\n{\"is_risky\": false}\n```";
        assert_eq!(extract_json(response), r#"{"is_risky": false}"#);
    }

    #[test]
    fn test_parse_analysis_response_valid() {
        let json = r#"{"is_risky": true, "risk_score": 0.8, "explanation": "bad", "additional_risks": ["x"]}"#;
        let result = parse_analysis_response(json);
        assert!(result.is_risky);
        assert_eq!(result.risk_score, 0.8);
    }

    #[test]
    fn test_parse_analysis_response_invalid_falls_back() {
        let result = parse_analysis_response("not json at all");
        assert!(!result.is_risky);
        assert_eq!(result.risk_score, 0.0);
    }

    #[test]
    fn test_parse_alternatives_response_valid() {
        let json = r#"[{"command": "rm -i /path", "explanation": "interactive mode"}]"#;
        let result = parse_alternatives_response(json);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "rm -i /path");
    }

    #[test]
    fn test_create_provider_no_key() {
        let config = LlmConfig::default();
        let env = crate::env::MockEnvironment::default();
        let provider = create_provider(&config, &env);
        assert!(!provider.is_available());
    }

    #[test]
    fn test_create_provider_unknown_provider() {
        let mut config = LlmConfig::default();
        config.provider = "unknown".into();
        let mut env = crate::env::MockEnvironment::default();
        env.env_vars
            .insert("SHELLFIRM_LLM_API_KEY".into(), "test-key".into());
        let provider = create_provider(&config, &env);
        assert!(!provider.is_available());
    }

    #[test]
    fn test_llm_analysis_serialization() {
        let analysis = LlmAnalysis {
            is_risky: true,
            risk_score: 0.75,
            explanation: "Recursive delete".into(),
            additional_risks: vec!["no confirmation".into()],
        };
        let json = serde_json::to_string(&analysis).unwrap();
        assert!(json.contains("\"is_risky\":true"));
        let deserialized: LlmAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.risk_score, 0.75);
    }
}
