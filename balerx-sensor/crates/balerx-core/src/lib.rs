pub mod agent;
pub mod canary;
pub mod config;
pub mod discovery;
pub mod finding;
pub mod guard;
pub mod lockfile;
pub mod log;
pub mod output;
pub mod poison;
pub mod policy;
pub mod process;
pub mod rules;
pub mod secret;

pub use agent::{Agent, AgentDefinition, AgentStatus};
pub use finding::{Finding, FindingSeverity, RiskScore, ScanResult};
pub use lockfile::Lockfile;
pub use rules::{Rule, RuleEngine, RuleId};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_score_calculation() {
        let findings = vec![
            Finding::new(
                RuleId::SecretInConfig,
                FindingSeverity::Critical,
                "Test critical",
                "desc",
            ),
            Finding::new(
                RuleId::McpSupplyUnpinned,
                FindingSeverity::Medium,
                "Test medium",
                "desc",
            ),
        ];

        let score = RiskScore::calculate(&findings);
        assert_eq!(score, 29); // 25 (critical) + 4 (medium)
    }

    #[test]
    fn test_scan_result_initialization() {
        let result = ScanResult::new();
        assert_eq!(result.schema_version, "1.0.0");
        assert_eq!(result.summary.agents_found, 0);
        assert_eq!(result.summary.findings_count, 0);
        assert_eq!(result.summary.risk_score, 0);
    }
}
