use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleId {
    McpSupplyUnpinned,
    McpSupplyLatest,
    McpSupplyGitNoCommit,
    McpSupplyLocalScript,
    McpPermBroadFilesystem,
    McpPermShellExec,
    McpPermDocker,
    McpPermDatabase,
    McpRemotePlainHttp,
    McpRemoteNoAuth,
    SecretInConfig,
    SecretInEnv,
    SecretInArgs,
    AgentAutonomyAutoApprove,
    AgentAutonomyDangerousPermissions,
    ToolPoisonHiddenInstructions,
    ToolPoisonExfiltration,
    HookGapNoGuard,
    HookGapNoTelemetry,
    ConfigInvalid,
}

impl RuleId {
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::McpSupplyUnpinned
            | Self::McpSupplyLatest
            | Self::McpSupplyGitNoCommit
            | Self::McpSupplyLocalScript => "mcp_supply_chain",
            Self::McpPermBroadFilesystem
            | Self::McpPermShellExec
            | Self::McpPermDocker
            | Self::McpPermDatabase => "mcp_permissions",
            Self::McpRemotePlainHttp | Self::McpRemoteNoAuth => "mcp_remote",
            Self::SecretInConfig | Self::SecretInEnv | Self::SecretInArgs => "secrets",
            Self::AgentAutonomyAutoApprove | Self::AgentAutonomyDangerousPermissions => {
                "agent_autonomy"
            }
            Self::ToolPoisonHiddenInstructions | Self::ToolPoisonExfiltration => "tool_poisoning",
            Self::HookGapNoGuard | Self::HookGapNoTelemetry => "hook_gap",
            Self::ConfigInvalid => "configuration",
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::McpSupplyUnpinned => "MCP-SUPPLY-001",
            Self::McpSupplyLatest => "MCP-SUPPLY-002",
            Self::McpSupplyGitNoCommit => "MCP-SUPPLY-003",
            Self::McpSupplyLocalScript => "MCP-SUPPLY-004",
            Self::McpPermBroadFilesystem => "MCP-PERM-001",
            Self::McpPermShellExec => "MCP-PERM-002",
            Self::McpPermDocker => "MCP-PERM-003",
            Self::McpPermDatabase => "MCP-PERM-004",
            Self::McpRemotePlainHttp => "MCP-REMOTE-001",
            Self::McpRemoteNoAuth => "MCP-REMOTE-002",
            Self::SecretInConfig => "SECRET-001",
            Self::SecretInEnv => "SECRET-002",
            Self::SecretInArgs => "SECRET-003",
            Self::AgentAutonomyAutoApprove => "AGENT-AUTONOMY-001",
            Self::AgentAutonomyDangerousPermissions => "AGENT-AUTONOMY-002",
            Self::ToolPoisonHiddenInstructions => "TOOL-POISON-001",
            Self::ToolPoisonExfiltration => "TOOL-POISON-002",
            Self::HookGapNoGuard => "HOOK-GAP-001",
            Self::HookGapNoTelemetry => "HOOK-GAP-002",
            Self::ConfigInvalid => "CONFIG-001",
        }
    }

    #[must_use]
    pub fn summary(self) -> &'static str {
        match self {
            Self::McpSupplyUnpinned => "MCP package is not pinned to a version.",
            Self::McpSupplyLatest => "MCP package uses a latest tag.",
            Self::McpSupplyGitNoCommit => "MCP server is a git URL without a commit.",
            Self::McpSupplyLocalScript => "MCP server runs a local script.",
            Self::McpPermBroadFilesystem => "MCP server can read a broad filesystem path.",
            Self::McpPermShellExec => "MCP server command is a shell.",
            Self::McpPermDocker => "MCP server runs Docker with a privileged or root mount.",
            Self::McpPermDatabase => "MCP server points at a database.",
            Self::McpRemotePlainHttp => "Remote MCP server uses plain HTTP.",
            Self::McpRemoteNoAuth => "Remote MCP server has no authentication configured.",
            Self::SecretInConfig => "Secret material found in an agent config.",
            Self::SecretInEnv => "Secret material found in an env block.",
            Self::SecretInArgs => "Secret material found in command arguments.",
            Self::AgentAutonomyAutoApprove => "Agent is set to approve actions without a prompt.",
            Self::AgentAutonomyDangerousPermissions => {
                "Agent permission mode allows a broad or bypass action."
            }
            Self::ToolPoisonHiddenInstructions => "Instruction text tries to hide a tool action.",
            Self::ToolPoisonExfiltration => "Instruction text tries to send data out.",
            Self::HookGapNoGuard => "Agent is configured and Guard hooks are not installed.",
            Self::HookGapNoTelemetry => "Agent has no telemetry upload configured.",
            Self::ConfigInvalid => "Agent config file is empty or is not valid JSON or TOML.",
        }
    }
}

/// Exact install command for HOOK-GAP-001. Other agents have no `guard install` value.
#[must_use]
pub fn hook_gap_install_fix(definition_id: &str) -> Option<String> {
    match definition_id {
        "claude-code" | "cursor" => Some(format!(
            "Run: balerx guard install {definition_id}\nMore: https://balerxgate.com/docs/guard"
        )),
        _ => None,
    }
}

/// Note for a discovered agent that Guard cannot hook. Not a finding and not HOOK-GAP-002.
#[must_use]
pub fn guard_coverage_note(definition_id: &str, name: &str) -> Option<String> {
    if hook_gap_install_fix(definition_id).is_some() {
        return None;
    }
    Some(format!(
        "Guard hooks are not available for {name} yet, so its tool calls aren't intercepted. The scan still checks its config."
    ))
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

pub trait Rule {
    fn id(&self) -> RuleId;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
}

pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleEngine {
    #[must_use]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    #[must_use]
    pub fn rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::guard_coverage_note;

    #[test]
    fn coverage_note_is_only_for_agents_without_guard() {
        assert!(guard_coverage_note("claude-code", "Claude Code").is_none());
        assert!(guard_coverage_note("cursor", "Cursor").is_none());
        let vscode = guard_coverage_note("vscode-copilot", "VS Code with GitHub Copilot")
            .expect("vscode note");
        let codex = guard_coverage_note("codex-cli", "Codex CLI").expect("codex note");
        assert_eq!(
            vscode,
            "Guard hooks are not available for VS Code with GitHub Copilot yet, so its tool calls aren't intercepted. The scan still checks its config."
        );
        assert_eq!(
            codex,
            "Guard hooks are not available for Codex CLI yet, so its tool calls aren't intercepted. The scan still checks its config."
        );
        assert!(!vscode.contains("HOOK-GAP"));
        assert!(!codex.contains("HOOK-GAP"));
    }
}
