use crate::redaction::redact_url;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

const SCAN_DOCS: &str = "https://balerxgate.com/docs/scan";

#[derive(Debug, Clone, Serialize)]
pub struct McpConfig {
    #[serde(rename = "mcpServers")]
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

impl<'de> Deserialize<'de> for McpConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Ok(Self::from_json(&value))
    }
}

impl McpConfig {
    /// Parse MCP configuration from a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or is not JSON or TOML the parser understands.
    pub fn parse_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let content = strip_utf8_bom(&content);
        let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("toml") {
            return Ok(Self::from_toml(content).unwrap_or_else(Self::empty));
        }
        let value: Value = serde_json::from_str(content)?;
        Ok(Self::from_json(&value))
    }

    #[must_use]
    pub fn from_json(value: &Value) -> Self {
        let Some(map) = value.as_object() else {
            return Self::empty();
        };
        let mut servers = HashMap::new();
        for key in ["mcpServers", "servers", "mcp_servers"] {
            if let Some(table) = map.get(key).and_then(Value::as_object) {
                insert_server_map(&mut servers, table);
            }
        }
        Self {
            mcp_servers: servers,
        }
    }

    #[must_use]
    pub fn from_toml(content: &str) -> Option<Self> {
        let value: toml::Value = toml::from_str(content).ok()?;
        let table = value.as_table()?;
        let mut servers = HashMap::new();
        if let Some(mcp) = table.get("mcp_servers").and_then(toml::Value::as_table) {
            for (name, entry) in mcp {
                if let Ok(server) = server_from_toml(entry) {
                    servers.insert(name.clone(), server);
                }
            }
        }
        Some(Self {
            mcp_servers: servers,
        })
    }

    fn empty() -> Self {
        Self {
            mcp_servers: HashMap::new(),
        }
    }

    #[must_use]
    pub fn find_issues(&self) -> Vec<ConfigIssue> {
        let mut issues = Vec::new();
        for (name, server) in &self.mcp_servers {
            issues.extend(server_issues(name, server));
        }
        issues
    }
}

/// Reads a config file and returns MCP servers plus findings, including broken JSON.
///
/// # Errors
///
/// Returns an error when the file cannot be read.
pub fn inspect_file(path: &Path) -> anyhow::Result<InspectedConfig> {
    let content = std::fs::read_to_string(path)?;
    Ok(inspect_contents(path, &content))
}

/// Drops one leading UTF-8 BOM so a VS Code or editor save can still be parsed.
#[must_use]
pub fn strip_utf8_bom(content: &str) -> &str {
    content.strip_prefix('\u{feff}').unwrap_or(content)
}

#[must_use]
pub fn inspect_contents(path: &Path, content: &str) -> InspectedConfig {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let content = strip_utf8_bom(content);
    let config_text = matches!(ext.as_str(), "" | "json" | "toml" | "yaml" | "yml");
    if !config_text {
        return InspectedConfig {
            mcp: None,
            issues: Vec::new(),
        };
    }
    if content.trim().is_empty() {
        return InspectedConfig {
            mcp: None,
            issues: vec![empty_config_issue(path)],
        };
    }
    if ext == "yaml" || ext == "yml" {
        return InspectedConfig {
            mcp: None,
            issues: Vec::new(),
        };
    }
    if ext == "toml" {
        return inspect_toml(path, content);
    }
    match serde_json::from_str::<Value>(content) {
        Ok(value) => inspect_json(content, &value),
        Err(error) => InspectedConfig {
            mcp: None,
            issues: vec![broken_json_issue(path, &error)],
        },
    }
}

#[derive(Debug)]
pub struct InspectedConfig {
    pub mcp: Option<McpConfig>,
    pub issues: Vec<ConfigIssue>,
}

fn inspect_json(content: &str, value: &Value) -> InspectedConfig {
    let mcp = McpConfig::from_json(value);
    let mut issues = mcp.find_issues();
    issues.extend(claude_permission_issues(value));
    stamp_lines(content, &mut issues);
    InspectedConfig {
        mcp: Some(mcp),
        issues,
    }
}

fn empty_config_issue(path: &Path) -> ConfigIssue {
    ConfigIssue {
        server_name: String::new(),
        issue_type: IssueType::EmptyConfig,
        description: "Configuration file is empty".to_string(),
        resource: path.display().to_string(),
        line: None,
    }
}

fn broken_json_issue(path: &Path, error: &serde_json::Error) -> ConfigIssue {
    ConfigIssue {
        server_name: String::new(),
        issue_type: IssueType::BrokenConfig,
        description: format!("Configuration file is not valid JSON: {error}. More: {SCAN_DOCS}"),
        resource: path.display().to_string(),
        line: u32::try_from(error.line()).ok(),
    }
}

fn broken_toml_issue(path: &Path, content: &str, error: &toml::de::Error) -> ConfigIssue {
    let (line, column) = line_column_at(content, error.span());
    let description = match (line, column) {
        (Some(line), Some(column)) => format!(
            "Configuration file is not valid TOML: {} at line {line} column {column}. More: {SCAN_DOCS}",
            error.message()
        ),
        _ => format!(
            "Configuration file is not valid TOML: {}. More: {SCAN_DOCS}",
            error.message()
        ),
    };
    ConfigIssue {
        server_name: String::new(),
        issue_type: IssueType::BrokenConfig,
        description,
        resource: path.display().to_string(),
        line,
    }
}

fn line_column_at(
    content: &str,
    span: Option<std::ops::Range<usize>>,
) -> (Option<u32>, Option<usize>) {
    let Some(span) = span else {
        return (None, None);
    };
    let mut line = 1u32;
    let mut column = 1usize;
    for (index, ch) in content.char_indices() {
        if index >= span.start {
            break;
        }
        if ch == '\n' {
            line = line.saturating_add(1);
            column = 1;
        } else {
            column += 1;
        }
    }
    (Some(line), Some(column))
}

fn inspect_toml(path: &Path, content: &str) -> InspectedConfig {
    let value = match toml::from_str::<toml::Value>(content) {
        Ok(value) => value,
        Err(error) => {
            return InspectedConfig {
                mcp: None,
                issues: vec![broken_toml_issue(path, content, &error)],
            };
        }
    };
    let mcp = McpConfig::from_toml(content).unwrap_or_else(McpConfig::empty);
    let mut issues = mcp.find_issues();
    if let Some(table) = value.as_table() {
        if table.get("approval_policy").and_then(toml::Value::as_str) == Some("never") {
            issues.push(setting_issue(
                IssueType::AutoApprove,
                "Codex approval_policy is never",
                "approval_policy",
            ));
        }
        if table.get("sandbox_mode").and_then(toml::Value::as_str) == Some("danger-full-access") {
            issues.push(setting_issue(
                IssueType::DangerousPermissions,
                "Codex sandbox_mode is danger-full-access",
                "sandbox_mode",
            ));
        }
    }
    stamp_lines(content, &mut issues);
    InspectedConfig {
        mcp: Some(mcp),
        issues,
    }
}

fn claude_permission_issues(value: &Value) -> Vec<ConfigIssue> {
    let mut issues = Vec::new();
    let mode = value
        .get("defaultMode")
        .or_else(|| value.pointer("/permissions/defaultMode"))
        .and_then(Value::as_str);
    if mode == Some("bypassPermissions") {
        issues.push(setting_issue(
            IssueType::DangerousPermissions,
            "Claude Code defaultMode is bypassPermissions",
            "bypassPermissions",
        ));
    }
    if let Some(allow) = value
        .pointer("/permissions/allow")
        .and_then(Value::as_array)
    {
        for entry in allow {
            if let Some(text) = entry.as_str() {
                if text == "Bash(*)" || text.ends_with("(*)") && text.contains("Bash") {
                    issues.push(setting_issue(
                        IssueType::DangerousPermissions,
                        "Claude Code allow list contains Bash(*)",
                        text,
                    ));
                }
            }
        }
    }
    issues
}

fn setting_issue(issue_type: IssueType, description: &str, resource: &str) -> ConfigIssue {
    ConfigIssue {
        server_name: String::new(),
        issue_type,
        description: description.to_string(),
        resource: resource.to_string(),
        line: None,
    }
}

fn server_issues(name: &str, server: &McpServer) -> Vec<ConfigIssue> {
    let mut issues = Vec::new();
    let args = server.args.clone().unwrap_or_default();
    if let Some(command) = &server.command {
        if let Some(package) = package_spec(command, &args) {
            match package.pin {
                PinState::Unpinned => {
                    let shown = redact_url(&package.name);
                    issues.push(ConfigIssue {
                        server_name: name.to_string(),
                        issue_type: IssueType::UnpinnedPackage,
                        description: format!("MCP server '{name}' uses unpinned package: {shown}"),
                        resource: shown,
                        line: None,
                    });
                }
                PinState::Latest => {
                    let shown = redact_url(&package.name);
                    issues.push(ConfigIssue {
                        server_name: name.to_string(),
                        issue_type: IssueType::LatestTag,
                        description: format!("MCP server '{name}' uses a latest tag: {shown}"),
                        resource: shown,
                        line: None,
                    });
                }
                PinState::Pinned => {}
            }
        }
        if let Some(url) = plain_http_target(command) {
            issues.push(remote_http_issue(name, &url));
        }
        if is_shell_command(command) {
            issues.push(ConfigIssue {
                server_name: name.to_string(),
                issue_type: IssueType::ShellExec,
                description: format!("MCP server '{name}' command is a shell: {command}"),
                resource: command.clone(),
                line: None,
            });
        }
        if is_database_command(command) {
            issues.push(database_issue(name, command));
        }
        issues.extend(docker_issues(name, command, &args));
    }
    if let Some(url) = &server.url {
        if let Some(target) = plain_http_target(url) {
            issues.push(remote_http_issue(name, &target));
        }
        if is_remote_url(url) && !server_has_auth(server) {
            let redacted = redact_url(url);
            issues.push(ConfigIssue {
                server_name: name.to_string(),
                issue_type: IssueType::NoAuth,
                description: format!(
                    "MCP server '{name}' is a remote endpoint with no auth configured"
                ),
                resource: redacted,
                line: None,
            });
        }
        if is_database_url(url) {
            issues.push(database_issue(name, url));
        }
    }
    for arg in &args {
        if is_broad_filesystem(arg) {
            issues.push(ConfigIssue {
                server_name: name.to_string(),
                issue_type: IssueType::BroadFilesystem,
                description: format!("MCP server '{name}' has broad filesystem access: {arg}"),
                resource: arg.clone(),
                line: None,
            });
        }
    }
    issues
}

fn remote_http_issue(name: &str, url: &str) -> ConfigIssue {
    let redacted = redact_url(url);
    ConfigIssue {
        server_name: name.to_string(),
        issue_type: IssueType::PlainHttp,
        description: format!("MCP server '{name}' uses plain HTTP: {redacted}"),
        resource: redacted,
        line: None,
    }
}

fn database_issue(name: &str, resource: &str) -> ConfigIssue {
    let redacted = redact_url(resource);
    ConfigIssue {
        server_name: name.to_string(),
        issue_type: IssueType::DatabaseAccess,
        description: format!("MCP server '{name}' can reach a database: {redacted}"),
        resource: redacted,
        line: None,
    }
}

fn docker_issues(name: &str, command: &str, args: &[String]) -> Vec<ConfigIssue> {
    let base = command_base(command);
    if base != "docker" && base != "podman" {
        return Vec::new();
    }
    let mut issues = Vec::new();
    let joined = args.join(" ");
    if args.iter().any(|arg| arg == "--privileged") || joined.contains("--privileged") {
        issues.push(ConfigIssue {
            server_name: name.to_string(),
            issue_type: IssueType::DockerPrivileged,
            description: format!("MCP server '{name}' runs a container with --privileged"),
            resource: "--privileged".to_string(),
            line: None,
        });
    }
    if has_root_mount(args) {
        issues.push(ConfigIssue {
            server_name: name.to_string(),
            issue_type: IssueType::RootMount,
            description: format!("MCP server '{name}' mounts the host root into a container"),
            resource: "/".to_string(),
            line: None,
        });
    }
    issues
}

struct PackageSpec {
    name: String,
    pin: PinState,
}

enum PinState {
    Pinned,
    Unpinned,
    Latest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageIdentity {
    pub name: String,
    pub version: String,
    pub registry: &'static str,
}

/// Package name, version, and registry parsed from an MCP server command.
///
/// `npx -y docs@1.2.3` is name `docs`, version `1.2.3`, registry `npm`.
/// Flags are not part of the name. An empty version means the spec has no pin.
#[must_use]
pub fn package_identity(command: &str, args: &[String]) -> Option<PackageIdentity> {
    let base = command_base(command);
    let registry = match base {
        "npx" | "npm" => "npm",
        "uvx" | "uv" | "pip" | "pip3" => "pypi",
        "docker" | "podman" => "docker",
        _ => return None,
    };
    let spec = package_spec(command, args)?;
    let (name, version) = split_name_version(base, &spec.name);
    if name.is_empty() {
        return None;
    }
    Some(PackageIdentity {
        name,
        version,
        registry,
    })
}

fn package_spec(command: &str, args: &[String]) -> Option<PackageSpec> {
    let base = command_base(command);
    let spec = match base {
        "npx" | "npm" => npm_package(args)?,
        "uvx" | "uv" => uv_package(args)?,
        "pip" | "pip3" => pip_package(args)?,
        "docker" | "podman" => docker_image(args)?,
        _ => return None,
    };
    let pin = classify_pin(base, &spec);
    Some(PackageSpec { name: spec, pin })
}

fn classify_pin(tool: &str, spec: &str) -> PinState {
    match package_version(tool, spec)
        .map(str::trim)
        .filter(|version| !version.is_empty())
    {
        Some("latest" | "*") => PinState::Latest,
        Some(_) => PinState::Pinned,
        None => PinState::Unpinned,
    }
}

fn split_name_version(tool: &str, spec: &str) -> (String, String) {
    let version = package_version(tool, spec)
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .unwrap_or("")
        .to_string();
    if version.is_empty() {
        return (spec.to_string(), String::new());
    }
    let suffix = match tool {
        "uvx" | "uv" | "pip" | "pip3" if spec.contains("==") => format!("=={version}"),
        "docker" | "podman" => format!(":{version}"),
        _ => format!("@{version}"),
    };
    let name = spec.strip_suffix(&suffix).unwrap_or(spec).to_string();
    (name, version)
}

fn package_version<'a>(tool: &str, spec: &'a str) -> Option<&'a str> {
    if spec.contains("://") {
        return None;
    }
    match tool {
        "uvx" | "uv" | "pip" | "pip3" => spec
            .split_once("==")
            .map(|(_, version)| version)
            .or_else(|| spec.split_once('@').map(|(_, version)| version)),
        "docker" | "podman" => spec.rsplit_once(':').and_then(|(image, tag)| {
            if image.is_empty() || tag.contains('/') {
                None
            } else {
                Some(tag)
            }
        }),
        _ => npm_version(spec),
    }
}

fn npm_version(spec: &str) -> Option<&str> {
    if let Some(rest) = spec.strip_prefix('@') {
        rest.split_once('@').map(|(_, version)| version)
    } else {
        spec.split_once('@').map(|(_, version)| version)
    }
}

fn npm_package(args: &[String]) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if matches!(
            arg,
            "-y" | "--yes"
                | "-q"
                | "--quiet"
                | "--no-install"
                | "--ignore-existing"
                | "--prefer-offline"
        ) {
            index += 1;
            continue;
        }
        if matches!(
            arg,
            "--package" | "-p" | "--call" | "-c" | "--cache" | "--userconfig"
        ) {
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(arg.to_string());
    }
    None
}

fn uv_package(args: &[String]) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if matches!(
            arg,
            "--from" | "--with" | "--python" | "-p" | "--index-url" | "--extra-index-url"
        ) {
            if arg == "--from" {
                return args.get(index + 1).cloned();
            }
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(arg.to_string());
    }
    None
}

fn pip_package(args: &[String]) -> Option<String> {
    let mut index = 0;
    if args.first().is_some_and(|arg| arg == "install") {
        index = 1;
    }
    while index < args.len() {
        let arg = args[index].as_str();
        if arg.starts_with('-') {
            index += if arg.contains('=') { 1 } else { 2 };
            continue;
        }
        return Some(arg.to_string());
    }
    None
}

fn docker_image(args: &[String]) -> Option<String> {
    let mut index = 0;
    if args
        .first()
        .is_some_and(|arg| arg == "run" || arg == "pull" || arg == "create")
    {
        index = 1;
    }
    while index < args.len() {
        let arg = args[index].as_str();
        if matches!(
            arg,
            "-v" | "--volume"
                | "-e"
                | "--env"
                | "-p"
                | "--publish"
                | "--name"
                | "-w"
                | "--workdir"
                | "-u"
                | "--user"
                | "--network"
                | "--entrypoint"
                | "--label"
                | "-l"
                | "--mount"
                | "--cpus"
                | "--memory"
        ) {
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(arg.to_string());
    }
    None
}

fn has_root_mount(args: &[String]) -> bool {
    args.iter().any(|arg| {
        let value = arg.as_str();
        value.starts_with("-v/")
            || value.starts_with("--volume=/")
            || value.starts_with("--mount")
            || value == "-v"
            || value == "--volume"
            || mount_source_is_root(value)
    }) || args.windows(2).any(|pair| {
        matches!(pair[0].as_str(), "-v" | "--volume" | "--mount") && mount_source_is_root(&pair[1])
    })
}

fn mount_source_is_root(value: &str) -> bool {
    let spec = value
        .trim_start_matches("--volume=")
        .trim_start_matches("-v")
        .trim_start_matches("--mount=")
        .trim_start_matches("type=bind,source=")
        .trim_start_matches("src=");
    spec == "/" || spec.starts_with("/:") || spec.starts_with("/,") || spec.starts_with("source=/")
}

fn is_broad_filesystem(arg: &str) -> bool {
    let quoted = arg.trim_matches('"');
    let stripped = quoted.trim_end_matches(['/', '\\']);
    let trimmed = if stripped.is_empty() {
        quoted
    } else {
        stripped
    };
    if matches!(
        trimmed,
        "/" | "~"
            | "$HOME"
            | "${HOME}"
            | "%USERPROFILE%"
            | "C:"
            | "C:\\"
            | "/home"
            | "/Users"
            | "/root"
            | "/home/*"
            | "/Users/*"
            | "$HOME/*"
            | "~/*"
    ) {
        return true;
    }
    let normalized = trimmed.replace('\\', "/");
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    (normalized.starts_with("/home/") || normalized.starts_with("/Users/")) && parts.len() == 2
}

fn plain_http_target(value: &str) -> Option<String> {
    let rest = value.strip_prefix("http://")?;
    let host = http_host(rest);
    if is_loopback_host(&host) {
        None
    } else {
        Some(value.to_string())
    }
}

fn is_remote_url(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    !is_loopback_host(&http_host(rest))
}

fn http_host(rest: &str) -> String {
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let hostport = &rest[..end];
    if let Some(inner) = hostport.strip_prefix('[') {
        inner.split(']').next().unwrap_or(inner).to_string()
    } else {
        hostport.split(':').next().unwrap_or(hostport).to_string()
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1" | "0.0.0.0")
}

fn server_has_auth(server: &McpServer) -> bool {
    if let Some(env) = &server.env {
        if env.keys().any(|key| {
            let key = key.to_ascii_lowercase();
            key.contains("token")
                || key.contains("key")
                || key.contains("secret")
                || key.contains("auth")
                || key.contains("password")
        }) {
            return true;
        }
    }
    server.extra.keys().any(|key| {
        let key = key.to_ascii_lowercase();
        key.contains("header") || key.contains("auth")
    })
}

fn is_shell_command(command: &str) -> bool {
    matches!(
        command_base(command),
        "bash" | "sh" | "zsh" | "powershell" | "pwsh" | "cmd" | "cmd.exe"
    )
}

fn is_database_command(command: &str) -> bool {
    matches!(
        command_base(command),
        "psql" | "mysql" | "mariadb" | "mongosh" | "mongo" | "redis-cli"
    )
}

fn is_database_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("postgres://")
        || lower.starts_with("postgresql://")
        || lower.starts_with("mysql://")
        || lower.starts_with("mongodb://")
        || lower.starts_with("mongodb+srv://")
        || lower.starts_with("redis://")
}

fn command_base(command: &str) -> &str {
    command.rsplit(['/', '\\']).next().unwrap_or(command).trim()
}

fn insert_server_map(
    into: &mut HashMap<String, McpServer>,
    table: &serde_json::Map<String, Value>,
) {
    for (name, value) in table {
        if let Ok(server) = serde_json::from_value::<McpServer>(value.clone()) {
            into.entry(name.clone()).or_insert(server);
        }
    }
}

fn server_from_toml(value: &toml::Value) -> Result<McpServer, ()> {
    let json = toml_to_json(value);
    serde_json::from_value(json).map_err(|_| ())
}

fn toml_to_json(value: &toml::Value) -> Value {
    match value {
        toml::Value::String(text) => Value::String(text.clone()),
        toml::Value::Integer(number) => Value::from(*number),
        toml::Value::Float(number) => Value::from(*number),
        toml::Value::Boolean(flag) => Value::Bool(*flag),
        toml::Value::Datetime(value) => Value::String(value.to_string()),
        toml::Value::Array(items) => Value::Array(items.iter().map(toml_to_json).collect()),
        toml::Value::Table(table) => {
            let mut map = serde_json::Map::new();
            for (key, child) in table {
                map.insert(key.clone(), toml_to_json(child));
            }
            Value::Object(map)
        }
    }
}

fn stamp_lines(content: &str, issues: &mut [ConfigIssue]) {
    for issue in issues {
        if issue.line.is_none() {
            issue.line = line_of(content, &issue.resource);
        }
    }
}

fn line_of(content: &str, needle: &str) -> Option<u32> {
    if needle.is_empty() {
        return None;
    }
    let index = content.find(needle)?;
    let line = content[..index]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    u32::try_from(line).ok()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigIssue {
    pub server_name: String,
    pub issue_type: IssueType,
    pub description: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueType {
    UnpinnedPackage,
    LatestTag,
    PlainHttp,
    BroadFilesystem,
    NoAuth,
    BrokenConfig,
    EmptyConfig,
    DockerPrivileged,
    RootMount,
    AutoApprove,
    DangerousPermissions,
    ShellExec,
    DatabaseAccess,
}

#[cfg(test)]
mod tests {
    use super::package_identity;

    #[test]
    fn npm_package_keeps_the_name_and_version() {
        let identity = package_identity("npx", &["-y".to_string(), "docs@1.2.3".to_string()])
            .expect("package");
        assert_eq!(identity.name, "docs");
        assert_eq!(identity.version, "1.2.3");
        assert_eq!(identity.registry, "npm");
    }

    #[test]
    fn scoped_npm_package_splits_on_the_version() {
        let identity = package_identity("npx", &["-y".to_string(), "@scope/pkg@1.2.3".to_string()])
            .expect("package");
        assert_eq!(identity.name, "@scope/pkg");
        assert_eq!(identity.version, "1.2.3");
    }

    #[test]
    fn url_package_spec_is_not_split_at_colon_or_at() {
        let user = "tuser";
        let pw = "Tp1";
        let at_host = String::from("@") + "host.example.com/pkg.tgz?token=Tk1";
        let spec = format!("https://{user}:{pw}{at_host}");
        let identity = package_identity("npx", &["-y".to_string(), spec.clone()]).expect("package");
        assert_eq!(identity.name, spec);
        assert_eq!(identity.version, "");
    }

    #[test]
    fn unpinned_url_package_finding_redacts_userinfo() {
        let user = "guser";
        let pw = "Gp1";
        let at_host = String::from("@") + "github.com/o/r.git";
        let spec = format!("git+https://{user}:{pw}{at_host}");
        let config = crate::config::McpConfig::from_json(&serde_json::json!({
            "mcpServers": {
                "git-pkg": {
                    "command": "npx",
                    "args": [spec]
                }
            }
        }));
        let issues = config.find_issues();
        let unpinned = issues
            .iter()
            .find(|issue| issue.issue_type == crate::config::IssueType::UnpinnedPackage)
            .expect("unpinned");
        assert!(!unpinned.description.contains(pw));
        assert!(!unpinned.resource.contains(pw));
        assert!(unpinned.resource.contains("github.com/o/r.git"));
    }
}
