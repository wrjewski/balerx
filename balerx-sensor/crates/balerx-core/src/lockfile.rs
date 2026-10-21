use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lockfile {
    #[serde(rename = "lockfile_version")]
    pub version: String,
    #[serde(rename = "generated_at")]
    pub timestamp: String,
    pub device: DeviceInfo,
    pub agents: Vec<LockedAgent>,
    pub mcp_servers: Vec<LockedMcpServer>,
    pub settings: AgentSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceInfo {
    pub hostname: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LockedAgent {
    pub name: String,
    pub definition_id: String,
    pub version: Option<String>,
    pub config_paths: Vec<String>,
    pub config_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LockedMcpServer {
    pub name: String,
    pub agent: String,
    pub command: String,
    pub args: Vec<String>,
    pub package: Option<PackageInfo>,
    pub config_hash: String,
    pub tool_descriptions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub registry: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentSettings {
    pub auto_approve: HashMap<String, bool>,
    pub hooks_enabled: HashMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DriftType {
    NewAgent(String),
    RemovedAgent(String),
    AgentVersionChanged {
        name: String,
        old: Option<String>,
        new: Option<String>,
    },
    NewMcpServer {
        agent: String,
        server: String,
    },
    RemovedMcpServer {
        agent: String,
        server: String,
    },
    McpVersionChanged {
        server: String,
        old: String,
        new: String,
    },
    McpCommandChanged {
        server: String,
        old: String,
        new: String,
    },
    McpArgsChanged {
        server: String,
    },
    ConfigHashChanged {
        agent: String,
    },
    AutoApproveChanged {
        agent: String,
        old: bool,
        new: bool,
    },
    HooksDisabled {
        agent: String,
    },
}

impl DriftType {
    #[must_use]
    pub fn severity(&self) -> DriftSeverity {
        match self {
            Self::McpVersionChanged { .. }
            | Self::McpCommandChanged { .. }
            | Self::McpArgsChanged { .. } => DriftSeverity::High,
            Self::NewMcpServer { .. }
            | Self::AutoApproveChanged { .. }
            | Self::HooksDisabled { .. } => DriftSeverity::Medium,
            Self::NewAgent(_)
            | Self::ConfigHashChanged { .. }
            | Self::AgentVersionChanged { .. } => DriftSeverity::Low,
            Self::RemovedAgent(_) | Self::RemovedMcpServer { .. } => DriftSeverity::Info,
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::NewAgent(name) => format!("New agent discovered: {name}"),
            Self::RemovedAgent(name) => format!("Agent removed: {name}"),
            Self::AgentVersionChanged { name, old, new } => {
                format!(
                    "Agent {} version changed: {} → {}",
                    name,
                    old.as_deref().unwrap_or("unknown"),
                    new.as_deref().unwrap_or("unknown")
                )
            }
            Self::NewMcpServer { agent, server } => {
                format!("New MCP server in {agent}: {server}")
            }
            Self::RemovedMcpServer { agent, server } => {
                format!("MCP server removed from {agent}: {server}")
            }
            Self::McpVersionChanged { server, old, new } => {
                format!("MCP server {server} version changed: {old} → {new}")
            }
            Self::McpCommandChanged { server, old, new } => {
                format!("MCP server {server} command changed: {old} → {new}")
            }
            Self::McpArgsChanged { server } => {
                format!("MCP server {server} arguments changed")
            }
            Self::ConfigHashChanged { agent } => {
                format!("Configuration changed for {agent}")
            }
            Self::AutoApproveChanged { agent, old, new } => {
                format!("Auto-approve for {agent} changed: {old} → {new}")
            }
            Self::HooksDisabled { agent } => {
                format!("Hooks disabled for {agent}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriftSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl Lockfile {
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: "1.0.0".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            device: DeviceInfo {
                hostname: hostname::get()
                    .ok()
                    .and_then(|h| h.into_string().ok())
                    .unwrap_or_else(|| "unknown".to_string()),
                platform: std::env::consts::OS.to_string(),
            },
            agents: Vec::new(),
            mcp_servers: Vec::new(),
            settings: AgentSettings {
                auto_approve: HashMap::new(),
                hooks_enabled: HashMap::new(),
            },
        }
    }

    /// Loads a lockfile from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed as TOML.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read lockfile: {}", path.as_ref().display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse lockfile: {}", path.as_ref().display()))
    }

    /// Saves the lockfile to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the lockfile cannot be serialized or written to disk.
    pub fn to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize lockfile")?;

        fs::write(path.as_ref(), content)
            .with_context(|| format!("Failed to write lockfile: {}", path.as_ref().display()))
    }

    pub fn add_agent(&mut self, agent: LockedAgent) {
        self.agents.push(agent);
    }

    pub fn add_mcp_server(&mut self, server: LockedMcpServer) {
        self.mcp_servers.push(server);
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn diff(&self, other: &Self) -> Vec<DriftType> {
        let mut drifts = Vec::new();

        for agent in &other.agents {
            if !self
                .agents
                .iter()
                .any(|a| a.definition_id == agent.definition_id)
            {
                drifts.push(DriftType::NewAgent(agent.name.clone()));
            }
        }

        for agent in &self.agents {
            if let Some(other_agent) = other
                .agents
                .iter()
                .find(|a| a.definition_id == agent.definition_id)
            {
                if agent.version != other_agent.version {
                    drifts.push(DriftType::AgentVersionChanged {
                        name: agent.name.clone(),
                        old: agent.version.clone(),
                        new: other_agent.version.clone(),
                    });
                }
                if agent.config_hash != other_agent.config_hash {
                    drifts.push(DriftType::ConfigHashChanged {
                        agent: agent.name.clone(),
                    });
                }
            } else {
                drifts.push(DriftType::RemovedAgent(agent.name.clone()));
            }
        }

        for server in &other.mcp_servers {
            if !self
                .mcp_servers
                .iter()
                .any(|s| s.name == server.name && s.agent == server.agent)
            {
                drifts.push(DriftType::NewMcpServer {
                    agent: server.agent.clone(),
                    server: server.name.clone(),
                });
            }
        }

        for server in &self.mcp_servers {
            if let Some(other_server) = other
                .mcp_servers
                .iter()
                .find(|s| s.name == server.name && s.agent == server.agent)
            {
                if server.command != other_server.command {
                    drifts.push(DriftType::McpCommandChanged {
                        server: server.name.clone(),
                        old: server.command.clone(),
                        new: other_server.command.clone(),
                    });
                }
                if server.args != other_server.args {
                    drifts.push(DriftType::McpArgsChanged {
                        server: server.name.clone(),
                    });
                }
                if server.package != other_server.package {
                    if let (Some(old_pkg), Some(new_pkg)) = (&server.package, &other_server.package)
                    {
                        if old_pkg.version != new_pkg.version {
                            drifts.push(DriftType::McpVersionChanged {
                                server: server.name.clone(),
                                old: old_pkg.version.clone(),
                                new: new_pkg.version.clone(),
                            });
                        }
                    }
                }
            } else {
                drifts.push(DriftType::RemovedMcpServer {
                    agent: server.agent.clone(),
                    server: server.name.clone(),
                });
            }
        }

        for (agent, enabled) in &self.settings.auto_approve {
            if let Some(other_enabled) = other.settings.auto_approve.get(agent) {
                if enabled != other_enabled {
                    drifts.push(DriftType::AutoApproveChanged {
                        agent: agent.clone(),
                        old: *enabled,
                        new: *other_enabled,
                    });
                }
            }
        }

        for (agent, enabled) in &self.settings.hooks_enabled {
            if let Some(other_enabled) = other.settings.hooks_enabled.get(agent) {
                if *enabled && !other_enabled {
                    drifts.push(DriftType::HooksDisabled {
                        agent: agent.clone(),
                    });
                }
            }
        }

        drifts.sort_by_key(|d| std::cmp::Reverse(d.severity()));
        drifts
    }
}

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockfile_serialization() {
        let lockfile = Lockfile::new();
        let toml = toml::to_string(&lockfile).unwrap();
        let parsed: Lockfile = toml::from_str(&toml).unwrap();
        assert_eq!(lockfile.version, parsed.version);
    }

    #[test]
    fn test_drift_detection_new_agent() {
        let old = Lockfile::new();
        let mut new = Lockfile::new();
        new.add_agent(LockedAgent {
            name: "Cursor".to_string(),
            definition_id: "cursor".to_string(),
            version: Some("1.0.0".to_string()),
            config_paths: vec![],
            config_hash: None,
        });

        let drifts = old.diff(&new);
        assert_eq!(drifts.len(), 1);
        assert!(matches!(drifts[0], DriftType::NewAgent(_)));
    }

    #[test]
    fn test_drift_detection_version_change() {
        let mut old = Lockfile::new();
        old.add_agent(LockedAgent {
            name: "Cursor".to_string(),
            definition_id: "cursor".to_string(),
            version: Some("1.0.0".to_string()),
            config_paths: vec![],
            config_hash: None,
        });

        let mut new = Lockfile::new();
        new.add_agent(LockedAgent {
            name: "Cursor".to_string(),
            definition_id: "cursor".to_string(),
            version: Some("1.1.0".to_string()),
            config_paths: vec![],
            config_hash: None,
        });

        let drifts = old.diff(&new);
        assert!(drifts
            .iter()
            .any(|d| matches!(d, DriftType::AgentVersionChanged { .. })));
    }

    #[test]
    fn test_drift_severity_ordering() {
        assert!(DriftSeverity::High > DriftSeverity::Medium);
        assert!(DriftSeverity::Medium > DriftSeverity::Low);
        assert!(DriftSeverity::Low > DriftSeverity::Info);
    }
}
