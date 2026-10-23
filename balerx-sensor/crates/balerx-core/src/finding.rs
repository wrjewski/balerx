use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::agent::Agent;
use crate::rules::RuleId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub schema_version: String,
    pub scan_id: String,
    pub scanned_at: DateTime<Utc>,
    pub device: DeviceInfo,
    pub summary: ScanSummary,
    pub agents: Vec<Agent>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: Option<String>,
    pub hostname: String,
    pub platform: String,
    pub os_version: String,
    pub balerx_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub agents_found: usize,
    pub findings_count: usize,
    pub risk_score: u8,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

impl ScanSummary {
    #[must_use]
    pub fn risk_label(&self) -> &'static str {
        if self.critical_count > 0 || self.risk_score > 75 {
            "CRITICAL"
        } else if self.high_count >= 3 || self.risk_score > 50 {
            "HIGH"
        } else if self.high_count > 0 || self.medium_count > 0 || self.risk_score > 25 {
            "MEDIUM"
        } else {
            "LOW"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: RuleId,
    pub severity: FindingSeverity,
    pub confidence: Confidence,
    pub category: String,
    pub title: String,
    pub description: String,
    pub affected_agent: Option<String>,
    pub affected_resource: String,
    pub evidence: serde_json::Value,
    pub suggested_fix: Option<String>,
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl ScanResult {
    #[must_use]
    pub fn new() -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        Self {
            schema_version: "1.0.0".to_string(),
            scan_id: Uuid::now_v7().to_string(),
            scanned_at: Utc::now(),
            device: DeviceInfo {
                id: None,
                hostname,
                platform: std::env::consts::OS.to_string(),
                os_version: os_version(),
                balerx_version: env!("CARGO_PKG_VERSION").to_string(),
            },
            summary: ScanSummary {
                agents_found: 0,
                findings_count: 0,
                risk_score: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 0,
            },
            agents: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub fn add_agent(&mut self, agent: Agent) {
        self.agents.push(agent);
        self.summary.agents_found = self.agents.len();
    }

    pub fn add_finding(&mut self, finding: Finding) {
        match finding.severity {
            FindingSeverity::Critical => self.summary.critical_count += 1,
            FindingSeverity::High => self.summary.high_count += 1,
            FindingSeverity::Medium => self.summary.medium_count += 1,
            FindingSeverity::Low => self.summary.low_count += 1,
            FindingSeverity::Info => self.summary.info_count += 1,
        }
        let duplicate = self.findings.iter().any(|existing| {
            existing.rule_id == finding.rule_id
                && existing.affected_resource == finding.affected_resource
                && existing.title == finding.title
                && existing.evidence == finding.evidence
        });
        if duplicate {
            return;
        }
        self.findings.push(finding);
        self.summary.findings_count = self.findings.len();
        self.recalculate_risk_score();
    }

    // Risk score calculation: intentional casts from usize to u32
    #[allow(clippy::cast_possible_truncation)]
    fn recalculate_risk_score(&mut self) {
        let mut score = 0u32;

        score += self.summary.critical_count as u32 * 25;
        score += self.summary.high_count as u32 * 10;
        score += self.summary.medium_count as u32 * 4;
        score += self.summary.low_count as u32;

        self.summary.risk_score = score.min(100) as u8;
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self::new()
    }
}

impl Finding {
    pub fn new(
        rule_id: RuleId,
        severity: FindingSeverity,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::now_v7().to_string(),
            rule_id,
            severity,
            confidence: Confidence::High,
            category: rule_id.category().to_string(),
            title: title.into(),
            description: description.into(),
            affected_agent: None,
            affected_resource: String::new(),
            evidence: serde_json::json!({}),
            suggested_fix: None,
            references: vec![format!(
                "https://github.com/wrjewski/balerx#{}",
                rule_id.code()
            )],
            line: None,
        }
    }

    #[must_use]
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    #[must_use]
    pub fn with_agent(mut self, agent: impl Into<String>) -> Self {
        self.affected_agent = Some(agent.into());
        self
    }

    #[must_use]
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.affected_resource = resource.into();
        self
    }

    #[must_use]
    pub fn with_evidence(mut self, evidence: serde_json::Value) -> Self {
        self.evidence = evidence;
        self
    }

    #[must_use]
    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.suggested_fix = Some(fix.into());
        self
    }

    #[must_use]
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    #[must_use]
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.references.push(reference.into());
        self
    }
}

pub struct RiskScore;

impl RiskScore {
    #[must_use]
    pub fn calculate(findings: &[Finding]) -> u8 {
        let mut score = 0u32;

        for finding in findings {
            score += match finding.severity {
                FindingSeverity::Critical => 25,
                FindingSeverity::High => 10,
                FindingSeverity::Medium => 4,
                FindingSeverity::Low => 1,
                FindingSeverity::Info => 0,
            };
        }

        score.min(100) as u8
    }
}

fn os_version() -> String {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("cmd")
            .args(["/C", "ver"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map_or_else(
                || "Windows (unknown version)".to_string(),
                |s| s.trim().to_string(),
            )
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map_or_else(
                || "macOS (unknown version)".to_string(),
                |s| s.trim().to_string(),
            )
    }

    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|line| line.starts_with("PRETTY_NAME="))
                    .map(|line| {
                        line.trim_start_matches("PRETTY_NAME=")
                            .trim_matches('"')
                            .to_string()
                    })
            })
            .unwrap_or_else(|| "Linux (unknown version)".to_string())
    }
}
