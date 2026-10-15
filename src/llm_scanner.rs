use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use log::{warn, info};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LlmProvider {
    OpenAiCompatible, // works with Grok, OpenAI, LM Studio, vLLM, etc.
    Ollama,
}

impl LlmProvider {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ollama" => LlmProvider::Ollama,
            _ => LlmProvider::OpenAiCompatible,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LlmConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub provider: LlmProvider,
    pub timeout_secs: u64,
    pub temperature: f32,
}

impl LlmConfig {
    /// Load from environment with sensible defaults.
    /// Prefers Grok / OpenAI-compatible if an API key is present.
    pub fn from_env() -> Self {
        let api_key = std::env::var("XAI_API_KEY")
        .or_else(|_| std::env::var("LLM_API_KEY"))
        .or_else(|_| std::env::var("OPENAI_API_KEY"))
        .ok();

        let provider = LlmProvider::from_str(
            &std::env::var("LLM_PROVIDER").unwrap_or_else(|_| {
                if api_key.is_some() { "openai".to_string() } else { "ollama".to_string() }
            })
        );

        let default_base = match provider {
            LlmProvider::OpenAiCompatible => "https://api.x.ai/v1".to_string(),
            LlmProvider::Ollama => "http://127.0.0.1:11434".to_string(),
        };

        Self {
            base_url: std::env::var("LLM_BASE_URL").unwrap_or(default_base),
            model: std::env::var("LLM_MODEL").unwrap_or_else(|_| {
                if provider == LlmProvider::OpenAiCompatible {
                    "grok-4".to_string() // or grok-4.7 / grok-3 / etc.
                } else {
                    "phi4-mini".to_string()
                }
            }),
            api_key,
            provider,
            timeout_secs: std::env::var("LLM_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
            temperature: std::env::var("LLM_TEMPERATURE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.1),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub enum DetectionType {
    #[serde(rename = "version")]
    Version,
    #[serde(rename = "secret")]
    Secret,
    #[serde(rename = "note")]
    Note,
    #[serde(rename = "other")]
    Other,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Detection {
    pub detection_type: DetectionType,
    pub software_or_key: String,
    pub value_or_version: String,
    pub evidence: String,
    pub confidence: f32,
}

#[derive(Deserialize, Debug)]
struct ScanOutput {
    #[serde(rename = "detections")]
    detections: Vec<Detection>,
}

pub struct LlmScanner {
    client: Client,
    config: LlmConfig,
}

impl LlmScanner {
    pub fn new() -> Self {
        Self::with_config(LlmConfig::from_env())
    }

    pub fn with_config(config: LlmConfig) -> Self {
        let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .unwrap_or_else(|_| Client::new());

        Self { client, config }
    }

    fn extract_json(raw: &str) -> String {
        let trimmed = raw
        .trim()
        .trim_start_matches("```json")
        .trim_end_matches("```")
        .trim();

        if let Some(start) = trimmed.find('{') {
            if let Some(end) = trimmed.rfind('}') {
                return trimmed[start..=end].trim().to_string();
            }
        }
        trimmed.to_string()
    }

    async fn call_llm(&self, prompt: &str) -> Result<String> {
        match self.config.provider {
            LlmProvider::OpenAiCompatible => self.call_openai_compatible(prompt).await,
            LlmProvider::Ollama => self.call_ollama(prompt).await,
        }
    }

    async fn call_openai_compatible(&self, prompt: &str) -> Result<String> {
        let url = format!("{}/chat/completions", self.config.base_url.trim_end_matches('/'));

        let body = json!({
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a precise security/reconnaissance scanner. Output only valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": self.config.temperature,
            "response_format": { "type": "json_object" } // ignored if model doesn't support it
        });

        let mut req = self.client.post(&url).json(&body);

        if let Some(key) = &self.config.api_key {
            req = req.bearer_auth(key);
        }

        let res = req.send().await.map_err(|e| anyhow!("LLM request failed: {}", e))?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("LLM HTTP error {}: {}", status, text));
        }

        let json: Value = res.json().await.map_err(|e| anyhow!("Failed to parse LLM response: {}", e))?;

        let content = json["choices"][0]["message"]["content"]
        .as_str()
        .ok_or_else(|| anyhow!("No content in OpenAI-compatible response: {:?}", json))?;

        Ok(content.to_string())
    }

    async fn call_ollama(&self, prompt: &str) -> Result<String> {
        let url = format!("{}/api/generate", self.config.base_url.trim_end_matches('/'));

        let body = json!({
            "model": self.config.model,
            "prompt": prompt,
            "stream": false,
            "format": "json",
            "options": {
                "temperature": self.config.temperature,
                "top_p": 0.9
            }
        });

        let res = self.client.post(&url).json(&body).send().await
        .map_err(|e| anyhow!("Ollama request failed: {}", e))?;

        if !res.status().is_success() {
            return Err(anyhow!("Ollama HTTP error: {}", res.status()));
        }

        #[derive(Deserialize)]
        struct OllamaResp { response: String }

        let ollama: OllamaResp = res.json().await
        .map_err(|e| anyhow!("Failed to parse Ollama response: {}", e))?;

        Ok(ollama.response)
    }

    pub async fn extract_interesting_artifacts(
        &self,
        hostname: &str,
        status: u16,
        headers_str: &str,
        body: &str,
    ) -> Result<Vec<Detection>> {
        if body.is_empty() {
            return Ok(vec![]);
        }

        let total_chars = body.chars().count();
        let replacement_count = body.chars().filter(|&c| c == '\u{FFFD}').count();
        if replacement_count as f64 / total_chars as f64 > 0.25 {
            return Ok(vec![]);
        }

        let body_snippet = if body.len() > 4000 {
            let mut end = 4000;
            while end > 0 && !body.is_char_boundary(end) {
                end -= 1;
            }
            if end < 2000 {
                return Ok(vec![]);
            }
            format!("{}... [truncated at {} bytes]", &body[..end], end)
        } else {
            body.to_string()
        };

        let json_example = r#"{
        "detections": [
        {"detection_type": "version", "software_or_key": "nginx", "value_or_version": "1.24.0", "evidence": "Server header", "confidence": 0.95},
        {"detection_type": "secret", "software_or_key": "api_key", "value_or_version": "sk-abc123...", "evidence": "JSON field", "confidence": 0.98},
        {"detection_type": "note", "software_or_key": "debug_comment", "value_or_version": "TODO: Secure endpoint", "evidence": "HTML comment", "confidence": 0.90},
        {"detection_type": "other", "software_or_key": "base64_blob", "value_or_version": "PHNvbWU+...", "evidence": "Body content", "confidence": 0.75}
        ]
    }"#;

    let prompt = format!(
        r#"You are a security/reconnaissance scanner. Exhaustively analyze the HTTP {} for software versions AND interesting artifacts like secrets, notes, or anomalies.

        TWO TASKS:
        1. SOFTWARE VERSIONS: Extract explicit software + exact versions (e.g., "nginx 1.24.0" from Server header or User-Agent).
    2. INTERESTING ARTIFACTS: Flag potential secrets (API keys, tokens, creds), notes/comments (TODOs, debug info), or anomalies (base64 blobs, unusual strings).

    CRITERIA:
    - Versions: Exact (1.24.0, v3.6.2); sources: headers, meta, filenames, footers. Normalize software to lowercase.
    - Secrets: High-confidence patterns like 'sk-...', 'Bearer ...', 'api_key=abc123', passwords in forms/JSON. Truncate value to first 20 chars + '...' for privacy.
    - Notes: Comments like '<!-- DEBUG: fix auth -->', TODOs, internal memos. Capture the full note if short (<100 chars).
    - Other: Anomalies like long base64, suspicious URLs, or embedded creds. Only if clearly interesting.

    RULES:
    - Comprehensive but precise: Skip low-confidence (e.g., vague "version X"). Use confidence 0.0-1.0 (1.0=explicit, 0.6=probable).
    - No speculation: If unclear, omit or low confidence.
    - Evidence: Quote exact location/string.
    - Output ONLY valid JSON — no explanations, no markdown.

    Format:
    {}

    {}: {}
    Status: {}
    Headers:
    {}

    Body (full scan):
    {}"#,
    if status > 0 { "response" } else { "request" },
        json_example,
        if status > 0 { "Response" } else { "Request" },
            hostname,
            status,
            headers_str,
            body_snippet
    );

    let raw_response = self.call_llm(&prompt).await?;
    let json_str = Self::extract_json(&raw_response);

    let parsed: ScanOutput = serde_json::from_str(&json_str).map_err(|e| {
        warn!("LLM JSON parse failed (raw: {:?})\nExtracted: {}", raw_response, json_str);
        anyhow!("Invalid JSON from LLM: {} (extracted: {})", e, json_str)
    })?;

    if parsed.detections.is_empty() {
        info!("LLM scan complete: No interesting artifacts for {}", hostname);
        Ok(vec![])
    } else {
        info!("LLM scan complete: {} artifacts detected for {}", parsed.detections.len(), hostname);
        Ok(parsed.detections)
    }
    }

    pub async fn scan_saved_entry(
        &self,
        hostname: &str,
        entry_type: &str,
        raw_data: &str,
    ) -> Result<Vec<Detection>> {
        if raw_data.is_empty() || raw_data.len() > 1_000_000 {
            return Ok(vec![]);
        }

        let (status_code, headers_str, body) = if entry_type == "response" {
            match crate::scanner::parse_http_response(raw_data) {
                Ok((status, headers, body)) => (status.as_u16(), format!("{:#?}", headers), body),
                Err(e) => {
                    warn!("Failed to parse saved response for {}: {}", hostname, e);
                    return Ok(vec![]);
                }
            }
        } else if entry_type == "request" {
            match crate::scanner::parse_http_request(raw_data) {
                Ok((_method, headers, body)) => (0, format!("{:#?}", headers), body),
                Err(e) => {
                    warn!("Failed to parse saved request for {}: {}", hostname, e);
                    return Ok(vec![]);
                }
            }
        } else {
            return Ok(vec![]);
        };

        self.extract_interesting_artifacts(hostname, status_code, &headers_str, &body).await
    }
}
