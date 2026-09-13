// LLM Provider - DeepSeek (OpenAI-compatible) R2-2

use crate::{SemanticReport, SoftwareIdentity};

pub struct LlmProvider {
    api_key: Option<String>,
    base_url: String,
    model: String,
}

#[derive(Debug)]
pub enum LlmError {
    NoApiKey,
    RequestFailed(String),
    InvalidResponse,
}

impl LlmProvider {
    pub fn new() -> Self {
        let api_key = std::env::var("DEEPSEEK_API_KEY").ok();
        let base_url = std::env::var("DEEPSEEK_BASE_URL")
            .unwrap_or_else(|_| "https://api.deepseek.com".to_string());
        let model = std::env::var("DEEPSEEK_MODEL")
            .unwrap_or_else(|_| "deepseek-chat".to_string());
        Self { api_key, base_url, model }
    }

    pub fn is_available(&self) -> bool {
        self.api_key.is_some()
    }

    pub async fn identify_software(&self, evidence: &str) -> Result<SemanticReport, LlmError> {
        let key = self.api_key.as_ref().ok_or(LlmError::NoApiKey)?;

        let system_prompt = "You are FOX Semantic Analyst. FOX Core provides deterministic evidence. \
            You must distinguish: FACT, HYPOTHESIS, CLAIM, UNKNOWN. \
            Never invent evidence. Never convert unsupported hypotheses into claims. \
            Every claim must reference FOX evidence IDs. If evidence is insufficient, return UNKNOWN.";

        let user_prompt = format!(
            "Based on this reverse engineering evidence, identify the software. \
            Respond ONLY with JSON: {{\"domain\":\"\",\"purpose\":\"\",\"major_components\":[],\"confidence\":\"\"}}\n\n\
            Evidence:\n{}",
            evidence
        );

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/chat/completions", self.base_url))
            .bearer_auth(key)
            .json(&serde_json::json!({
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.1
            }))
            .send()
            .await
            .map_err(|e| LlmError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(LlmError::RequestFailed(format!("{}: {}", status, body)));
        }

        let json: serde_json::Value = resp.json().await.map_err(|_| LlmError::InvalidResponse)?;
        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .ok_or(LlmError::InvalidResponse)?;

        let parsed: serde_json::Value = serde_json::from_str(content)
            .map_err(|_| LlmError::InvalidResponse)?;

        let identity = SoftwareIdentity {
            domain: parsed["domain"].as_str().unwrap_or("unknown").to_string(),
            purpose: parsed["purpose"].as_str().unwrap_or("unknown").to_string(),
            major_components: parsed["major_components"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
            confidence: parsed["confidence"].as_str().unwrap_or("low").to_string(),
        };

        let mut report = SemanticReport::new();
        report.software_identity = Some(identity);
        Ok(report)
    }
}
