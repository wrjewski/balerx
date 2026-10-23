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
            Self::ConfigInvalid => "Agent config file is not valid JSON or TOML.",
        }
    }
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
