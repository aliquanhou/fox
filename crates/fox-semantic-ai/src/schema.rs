// Semantic Schema - R2-1

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticFact {
    pub id: String,
    pub category: String,
    pub value: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticHypothesis {
    pub id: String,
    pub statement: String,
    pub confidence: f32,
    pub supporting: Vec<String>,
    pub contradicting: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticClaim {
    pub id: String,
    pub statement: String,
    pub confidence: f32,
    pub evidence_ids: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticUnknown {
    pub statement: String,
    pub reason: String,
    pub missing_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareIdentity {
    pub domain: String,
    pub purpose: String,
    pub major_components: Vec<String>,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticReport {
    pub software_identity: Option<SoftwareIdentity>,
    pub facts: Vec<SemanticFact>,
    pub hypotheses: Vec<SemanticHypothesis>,
    pub claims: Vec<SemanticClaim>,
    pub unknowns: Vec<SemanticUnknown>,
}

impl SemanticReport {
    pub fn new() -> Self {
        Self {
            software_identity: None,
            facts: vec![],
            hypotheses: vec![],
            claims: vec![],
            unknowns: vec![],
        }
    }
}
