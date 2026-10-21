use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    #[serde(default, rename = "mcpServers")]
    pub mcp_servers: HashMap<String, McpServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
    pub url: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl McpConfig {
    /// Parse MCP configuration from a file
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed
    pub fn parse_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    #[must_use]
    pub fn find_issues(&self) -> Vec<ConfigIssue> {
        let mut issues = Vec::new();

        for (name, server) in &self.mcp_servers {
            if let Some(cmd) = &server.command {
                if cmd.starts_with("npx") || cmd.starts_with("uvx") {
                    if let Some(args) = &server.args {
                        let pkg_index =
                            args.iter().position(|arg| arg == "-y").map_or(0, |i| i + 1);
                        let pkg = args.get(pkg_index).map_or("", std::string::String::as_str);

                        if !pkg.is_empty() && !has_version_pin(pkg) {
                            issues.push(ConfigIssue {
                                server_name: name.clone(),
                                issue_type: IssueType::UnpinnedPackage,
                                description: format!(
                                    "MCP server '{name}' uses unpinned package: {pkg}"
                                ),
                                resource: pkg.to_string(),
                            });
                        }

                        if pkg.contains("@latest") {
                            issues.push(ConfigIssue {
                                server_name: name.clone(),
                                issue_type: IssueType::LatestTag,
                                description: format!("MCP server '{name}' uses @latest tag: {pkg}"),
                                resource: pkg.to_string(),
                            });
                        }
                    }
                }

                if cmd.contains("http://")
                    && !cmd.contains("localhost")
                    && !cmd.contains("127.0.0.1")
                {
                    issues.push(ConfigIssue {
                        server_name: name.clone(),
                        issue_type: IssueType::PlainHttp,
                        description: format!("MCP server '{name}' uses plain HTTP: {cmd}"),
                        resource: cmd.clone(),
                    });
                }
            }

            if let Some(url) = &server.url {
                if url.starts_with("http://")
                    && !url.contains("localhost")
                    && !url.contains("127.0.0.1")
                {
                    issues.push(ConfigIssue {
                        server_name: name.clone(),
                        issue_type: IssueType::PlainHttp,
                        description: format!("MCP server '{name}' uses plain HTTP URL: {url}"),
                        resource: url.clone(),
                    });
                }
            }

            if let Some(args) = &server.args {
                for arg in args {
                    if arg == "/" || arg == "C:\\" || arg == "~" {
                        issues.push(ConfigIssue {
                            server_name: name.clone(),
                            issue_type: IssueType::BroadFilesystem,
                            description: format!(
                                "MCP server '{name}' has broad filesystem access: {arg}"
                            ),
                            resource: arg.clone(),
                        });
                    }
                }
            }
        }

        issues
    }
}

fn has_version_pin(pkg: &str) -> bool {
    pkg.contains('@') && !pkg.ends_with('@') && !pkg.contains("@latest")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigIssue {
    pub server_name: String,
    pub issue_type: IssueType,
    pub description: String,
    pub resource: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueType {
    UnpinnedPackage,
    LatestTag,
    PlainHttp,
    BroadFilesystem,
    NoAuth,
}
