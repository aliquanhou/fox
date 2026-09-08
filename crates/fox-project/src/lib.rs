//! FOX Project Management & Reconstruction
//!
//! P0: project save/load skeleton.
//! Full project reconstruction: P1+.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoxProject {
    pub name: String,
    pub version: String,
    pub binary_path: String,
    pub analysis_data: serde_json::Value,
}

impl FoxProject {
    pub fn new(name: &str, binary_path: &str) -> Self {
        FoxProject {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            binary_path: binary_path.to_string(),
            analysis_data: serde_json::Value::Null,
        }
    }
}
