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
    /// Coverage notes for agents Guard cannot hook. Not SARIF results, so they are not alerts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifProperties>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifProperties {
    #[serde(rename = "guardCoverage")]
    pub guard_coverage: Vec<String>,
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
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    pub help: SarifMessage,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[must_use]
pub fn to_sarif(result: &ScanResult) -> SarifReport {
    let mut rules = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for finding in &result.findings {
        let id = finding.rule_id.to_string();
        if seen.insert(id.clone()) {
            rules.push(SarifRule {
                id,
                short_description: SarifMessage {
                    text: finding.rule_id.summary().to_string(),
                },
                help: SarifMessage {
                    text: finding.rule_id.summary().to_string(),
                },
            });
        }
    }

    let results: Vec<SarifResult> = result
        .findings
        .iter()
        .map(|finding| SarifResult {
            rule_id: finding.rule_id.to_string(),
            level: severity_to_sarif_level(finding.severity),
            message: SarifMessage {
                text: sarif_message(finding),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: relative_uri(&finding.affected_resource),
                    },
                    region: finding.line.map(|start_line| SarifRegion { start_line }),
                },
            }],
        })
        .collect();

    let coverage: Vec<String> = result
        .agents
        .iter()
        .filter_map(|agent| agent.guard_coverage.clone())
        .collect();
    let properties = if coverage.is_empty() {
        None
    } else {
        Some(SarifProperties {
            guard_coverage: coverage,
        })
    };

    SarifReport {
        version: "2.1.0".to_string(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Balerx Gate".to_string(),
                    version: result.device.balerx_version.clone(),
                    information_uri: "https://github.com/wrjewski/balerx".to_string(),
                    rules,
                },
            },
            results,
            properties,
        }],
    }
}

fn sarif_message(finding: &crate::finding::Finding) -> String {
    match finding.suggested_fix.as_deref() {
        Some(fix) if !fix.is_empty() => {
            format!("{}: {}\n{fix}", finding.title, finding.description)
        }
        _ => format!("{}: {}", finding.title, finding.description),
    }
}

fn relative_uri(path: &str) -> String {
    let cwd = std::env::current_dir().ok();
    crate::lockfile::portable_uri(path, cwd.as_deref(), crate::agent::home_dir().as_deref())
}

fn severity_to_sarif_level(severity: FindingSeverity) -> String {
    match severity {
        FindingSeverity::Critical | FindingSeverity::High => "error".to_string(),
        FindingSeverity::Medium => "warning".to_string(),
        FindingSeverity::Low | FindingSeverity::Info => "note".to_string(),
    }
}
