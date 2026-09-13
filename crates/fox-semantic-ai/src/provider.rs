// LLM Provider - DeepSeek (OpenAI-compatible)

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
        let prompt = format!(
            "Based on the following reverse engineering evidence, identify what software this is.\n\
            Evidence:\n{}\n\n\
            Respond in JSON with: domain, purpose, major_components, confidence",
            evidence
        );
        // For R2-1 foundation: return a minimal report (actual HTTP call is TODO)
        let _ = (key, &self.base_url, &self.model, prompt);
        let mut report = SemanticReport::new();
        report.software_identity = Some(SoftwareIdentity {
            domain: "unknown".to_string(),
            purpose: "analysis pending".to_string(),
            major_components: vec![],
            confidence: "low".to_string(),
        });
        Ok(report)
    }
}
