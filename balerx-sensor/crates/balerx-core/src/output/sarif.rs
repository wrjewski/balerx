use crate::finding::{FindingSeverity, ScanResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[must_use]
pub fn to_sarif(result: &ScanResult) -> SarifReport {
    let results: Vec<SarifResult> = result
        .findings
        .iter()
        .map(|f| SarifResult {
            rule_id: f.rule_id.to_string(),
            level: severity_to_sarif_level(f.severity),
            message: SarifMessage {
                text: format!("{}: {}", f.title, f.description),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.affected_resource.clone(),
                    },
                },
            }],
        })
        .collect();

    SarifReport {
        version: "2.1.0".to_string(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Balerx Gate".to_string(),
                    version: result.device.balerx_version.clone(),
                    information_uri: "https://github.com/wrjewski/balerx".to_string(),
                },
            },
            results,
        }],
    }
}

fn severity_to_sarif_level(severity: FindingSeverity) -> String {
    match severity {
        FindingSeverity::Critical | FindingSeverity::High => "error".to_string(),
        FindingSeverity::Medium => "warning".to_string(),
        FindingSeverity::Low | FindingSeverity::Info => "note".to_string(),
    }
}
