use crate::agent::Agent;
use crate::config::McpConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
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
                hostname: String::new(),
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

    /// Builds a lockfile from discovered agents.
    ///
    /// Paths are home-relative. Each config file and MCP server gets a content hash.
    /// The machine hostname is left empty so the file can be committed.
    #[must_use]
    pub fn capture(agents: &[Agent]) -> Self {
        let mut lockfile = Self::new();
        for agent in agents {
            let mut paths = Vec::new();
            let mut file_hashes = Vec::new();
            for path in &agent.config_paths {
                paths.push(home_relative(path));
                let bytes = fs::read(path).unwrap_or_default();
                file_hashes.push(sha256_hex(&bytes));
                if let Ok(config) = McpConfig::parse_file(path) {
                    for (name, server) in config.mcp_servers {
                        let args = server.args.clone().unwrap_or_default();
                        let command = server.command.clone().unwrap_or_default();
                        let canonical = serde_json::json!({
                            "name": name,
                            "command": command,
                            "args": args,
                            "url": server.url,
                        });
                        let package = package_from_command(&command, &args);
                        lockfile.add_mcp_server(LockedMcpServer {
                            name,
                            agent: agent.name.clone(),
                            command,
                            args,
                            package,
                            config_hash: sha256_hex(canonical.to_string().as_bytes()),
                            tool_descriptions: Vec::new(),
                        });
                    }
                }
            }
            paths.sort();
            let config_hash = if file_hashes.is_empty() {
                None
            } else {
                Some(sha256_hex(file_hashes.join("\n").as_bytes()))
            };
            lockfile.add_agent(LockedAgent {
                name: agent.name.clone(),
                definition_id: agent.definition_id.clone(),
                version: agent.version.clone(),
                config_paths: paths,
                config_hash,
            });
        }
        lockfile
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

#[must_use]
pub fn home_relative(path: &Path) -> String {
    home_relative_from(path, dirs::home_dir().as_deref())
}

/// SARIF `uri` for a finding path: cwd-relative when it is inside `cwd`,
/// otherwise `~/...` when it is inside `home`. Separators are `/`.
///
/// Windows drive paths compare without regard to ASCII case, and a `\\?\`
/// prefix is removed so `C:\` and `c:\` name the same directory.
#[must_use]
pub(crate) fn portable_uri(path: &str, cwd: Option<&Path>, home: Option<&Path>) -> String {
    let normalized = normalize_separators(path);
    if let Some(cwd) = cwd {
        let cwd_norm = normalize_separators(&cwd.to_string_lossy());
        let cwd_dir = directory_prefix(&cwd_norm);
        if paths_equal(directory_prefix(&normalized), cwd_dir) {
            return ".".to_string();
        }
        let prefix = format!("{cwd_dir}/");
        if let Some(rest) = child_suffix(&normalized, &prefix) {
            return rest.to_string();
        }
    }
    home_relative_from(Path::new(&normalized), home)
}

fn home_relative_from(path: &Path, home: Option<&Path>) -> String {
    let display = normalize_separators(&path.to_string_lossy());
    if let Some(home) = home {
        let home_norm = normalize_separators(&home.to_string_lossy());
        let home_dir = directory_prefix(&home_norm);
        if paths_equal(directory_prefix(&display), home_dir) {
            return "~".to_string();
        }
        let prefix = format!("{home_dir}/");
        if let Some(rest) = child_suffix(&display, &prefix) {
            return format!("~/{rest}");
        }
    }
    display
}

fn normalize_separators(value: &str) -> String {
    let slashed = value.replace('\\', "/");
    if let Some(rest) = slashed.strip_prefix("//?/") {
        if has_drive_prefix(rest) {
            return rest.to_string();
        }
    }
    slashed
}

fn directory_prefix(value: &str) -> &str {
    if value.len() > 1 && value.ends_with('/') {
        value.trim_end_matches('/')
    } else {
        value
    }
}

fn paths_equal(left: &str, right: &str) -> bool {
    if has_drive_prefix(left) || has_drive_prefix(right) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

fn child_suffix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if has_drive_prefix(path) || has_drive_prefix(prefix) {
        let mut rest = path.chars();
        for expected in prefix.chars() {
            let actual = rest.next()?;
            if !actual.eq_ignore_ascii_case(&expected) {
                return None;
            }
        }
        return Some(rest.as_str());
    }
    path.strip_prefix(prefix)
}

fn has_drive_prefix(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic()
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn package_from_command(command: &str, args: &[String]) -> Option<PackageInfo> {
    let identity = crate::config::package_identity(command, args)?;
    Some(PackageInfo {
        name: identity.name,
        version: identity.version,
        registry: identity.registry.to_string(),
    })
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
        assert!(!toml.contains("hostname"));
    }

    #[test]
    fn test_mcp_server_add_remove_and_change() {
        let mut saved = Lockfile::new();
        saved.add_mcp_server(LockedMcpServer {
            name: "filesystem".to_string(),
            agent: "Cursor".to_string(),
            command: "npx".to_string(),
            args: vec!["-y".to_string(), "server".to_string(), "/tmp".to_string()],
            package: None,
            config_hash: "abc".to_string(),
            tool_descriptions: vec![],
        });
        let mut current = saved.clone();
        current.mcp_servers[0].args = vec!["-y".to_string(), "server".to_string(), "/".to_string()];
        current.add_mcp_server(LockedMcpServer {
            name: "evil".to_string(),
            agent: "Cursor".to_string(),
            command: "npx".to_string(),
            args: vec!["-y".to_string(), "evil".to_string()],
            package: None,
            config_hash: "def".to_string(),
            tool_descriptions: vec![],
        });
        let drifts = saved.diff(&current);
        assert!(drifts.iter().any(
            |drift| matches!(drift, DriftType::NewMcpServer { server, .. } if server == "evil")
        ));
        assert!(drifts.iter().any(
            |drift| matches!(drift, DriftType::McpArgsChanged { server } if server == "filesystem")
        ));

        let removed = current.diff(&saved);
        assert!(removed.iter().any(
            |drift| matches!(drift, DriftType::RemovedMcpServer { server, .. } if server == "evil")
        ));
    }

    #[test]
    fn home_relative_windows_drive_is_a_forward_slash_uri() {
        let home = Path::new(r"C:\Users\ada");
        let cwd = Path::new(r"D:\work\repo");
        assert_eq!(
            portable_uri(r"C:\Users\ada\.cursor\mcp.json", Some(cwd), Some(home)),
            "~/.cursor/mcp.json"
        );
        assert_eq!(
            portable_uri(r"c:\users\ada\.cursor\mcp.json", Some(cwd), Some(home)),
            "~/.cursor/mcp.json"
        );
        assert_eq!(
            portable_uri(r"\\?\C:\Users\ada\.cursor\mcp.json", Some(cwd), Some(home)),
            "~/.cursor/mcp.json"
        );
        assert_eq!(portable_uri(r"C:\Users\ada", Some(cwd), Some(home)), "~");
        assert_eq!(
            portable_uri(r"D:\work\repo\src\main.rs", Some(cwd), Some(home)),
            "src/main.rs"
        );
        assert_eq!(
            portable_uri(r"E:\other\file.txt", Some(cwd), Some(home)),
            "E:/other/file.txt"
        );
        assert_eq!(
            portable_uri(
                "/home/ada/.cursor/mcp.json",
                Some(Path::new("/workspace")),
                Some(Path::new("/home/ada"))
            ),
            "~/.cursor/mcp.json"
        );
        assert_eq!(
            portable_uri(
                "/Home/ada/.cursor/mcp.json",
                Some(Path::new("/workspace")),
                Some(Path::new("/home/ada"))
            ),
            "/Home/ada/.cursor/mcp.json"
        );
    }

    #[test]
    fn test_home_relative_paths_drop_the_machine_name() {
        let home = dirs::home_dir().expect("home");
        let path = home.join("proj").join("mcp.json");
        let shown = home_relative(&path);
        assert!(shown.starts_with("~/"));
        if let Some(name) = hostname::get()
            .ok()
            .and_then(|value| value.into_string().ok())
        {
            if !name.is_empty() {
                assert!(!shown.contains(&name), "path should not include hostname");
            }
        }
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
